// Package aiassisted provides AI-powered investigation using AWS AgentCore
package aiassisted

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/bedrockagentcore"
	"github.com/openshift/configuration-anomaly-detection/pkg/aiconfig"
	"github.com/openshift/configuration-anomaly-detection/pkg/aws"
	"github.com/openshift/configuration-anomaly-detection/pkg/executor"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/investigation"
	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
	"github.com/openshift/configuration-anomaly-detection/pkg/notewriter"
	"github.com/openshift/configuration-anomaly-detection/pkg/pagerduty"
	"github.com/openshift/configuration-anomaly-detection/pkg/types"
)

type Investigation struct{}

// generateSessionID generates a unique session ID for this investigation
func generateSessionID(incidentID string) string {
	timestamp := time.Now().Unix()
	randomBytes := make([]byte, 8)
	rand.Read(randomBytes) //nolint:errcheck
	randomHex := hex.EncodeToString(randomBytes)
	return fmt.Sprintf("cad-%s-%d-%s", incidentID, timestamp, randomHex)
}

func (c *Investigation) Run(rb investigation.ResourceBuilder) (investigation.InvestigationResult, error) {
	result := investigation.InvestigationResult{}

	// Build resources
	r, err := rb.Build()
	if err != nil {
		return result, err
	}

	notes := notewriter.New(r.Name, logging.RawLogger)

	config, err := aiconfig.ParseAIAgentConfig()
	if err != nil {
		notes.AppendWarning("Failed to parse AI agent configuration: %v", err)
		result.Actions = []types.Action{
			executor.NoteFrom(notes),
			executor.Escalate("AI config parse error"),
		}
		return result, nil
	}

	if !config.Enabled {
		notes.AppendWarning("AI investigation is disabled (CAD_AI_AGENT_CONFIG not configured or enabled=false)")
		result.Actions = []types.Action{
			executor.NoteFrom(notes),
			executor.Escalate("AI investigation disabled"),
		}
		return result, nil
	}

	clusterID := r.Cluster.ID()
	orgID, err := r.OcmClient.GetOrganizationID(clusterID)
	if err != nil {
		notes.AppendWarning("Failed to get organization ID: %v", err)
		result.Actions = []types.Action{
			executor.NoteFrom(notes),
			executor.Escalate("Failed to get organization ID"),
		}
		return result, nil
	}

	if !config.IsAllowedForAI(clusterID, orgID) {
		notes.AppendWarning("Cluster %s (org: %s) is not in the AI investigation allowlist", clusterID, orgID)
		result.Actions = []types.Action{
			executor.NoteFrom(notes),
			executor.Escalate("Cluster not in AI allowlist"),
		}
		return result, nil
	}

	notes.AppendSuccess("AI investigation allowlist check passed for cluster %s (org: %s)", clusterID, orgID)

	// Get PagerDuty incident details
	pdClient, ok := r.PdClient.(*pagerduty.SdkClient)
	if !ok {
		notes.AppendWarning("Failed to access PagerDuty client details")
		result.Actions = []types.Action{
			executor.NoteFrom(notes),
			executor.Escalate("Failed to access PagerDuty client"),
		}
		return result, nil
	}

	// Gather all available PagerDuty incident data
	incidentID := pdClient.GetIncidentID()
	incidentRef := pdClient.GetIncidentRef()
	alertTitle := pdClient.GetTitle()
	serviceID := pdClient.GetServiceID()
	serviceName := pdClient.GetServiceName()

	// Fetch alerts for this incident
	alerts, err := pdClient.GetAlertsForIncident(incidentID)
	if err != nil {
		logging.Warnf("Failed to fetch alerts for incident %s: %v", incidentID, err)
	}

	// Get detailed alert information
	var alertDetails string
	if alerts != nil && len(*alerts) > 0 {
		details, err := pdClient.GetAlertListDetails(alerts)
		if err != nil {
			logging.Warnf("Failed to get alert details: %v", err)
			alertDetails = "Alert details unavailable"
		} else {
			detailsJSON, _ := json.MarshalIndent(details, "", "  ")
			alertDetails = string(detailsJSON)
		}
	} else {
		alertDetails = "No alerts found for incident"
	}

	// Build investigation prompt with all PagerDuty data
	prompt := fmt.Sprintf(`Investigate PagerDuty incident for OpenShift cluster %s (org: %s).

Incident Information:
- Incident ID: %s
- Incident URL: %s
- Alert Title: %s
- Service ID: %s
- Service Name: %s
- Cluster ID: %s
- Organization: %s

Alert Details:
%s

Please investigate this alert, determine the root cause, and provide remediation steps.`,
		clusterID,
		orgID,
		incidentID,
		incidentRef,
		alertTitle,
		serviceID,
		serviceName,
		clusterID,
		orgID,
		alertDetails,
	)

	// Load AWS config for AgentCore (uses CAD's AWS account credentials, not customer's)
	// Credentials are explicitly loaded from the mounted secret at:
	// /var/secrets/cad-ai-agent-credentials/credentials (INI format)
	// This ensures we use dedicated AI agent credentials, separate from any customer AWS access
	ctx, cancel := context.WithTimeout(context.Background(), config.GetTimeout())
	defer cancel()

	const aiAgentCredsFile = "/var/secrets/cad-ai-agent-credentials/credentials"
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx,
		awsconfig.WithSharedCredentialsFiles([]string{aiAgentCredsFile}),
	)
	if err != nil {
		notes.AppendWarning("Failed to load AWS configuration from %s: %v", aiAgentCredsFile, err)
		result.Actions = []types.Action{
			executor.NoteFrom(notes),
			executor.Escalate("Failed to load AI agent AWS credentials"),
		}
		return result, nil
	}

	// Create AgentCore client
	agentClient := aws.NewAgentCoreClient(awsCfg)

	// Generate unique session ID for this investigation
	sessionID := generateSessionID(incidentID)

	// Build payload
	payloadData := map[string]string{
		"prompt": prompt,
	}
	payloadJSON, err := json.Marshal(payloadData)
	if err != nil {
		notes.AppendWarning("Failed to marshal investigation payload: %v", err)
		result.Actions = []types.Action{
			executor.NoteFrom(notes),
			executor.Escalate("Failed to marshal payload"),
		}
		return result, nil
	}

	// Invoke AgentCore runtime
	logging.Infof("Invoking AgentCore runtime %s for incident %s (session: %s)", config.RuntimeARN, incidentID, sessionID)

	// Request streaming response format
	acceptHeader := "text/event-stream"
	input := &bedrockagentcore.InvokeAgentRuntimeInput{
		AgentRuntimeArn:  &config.RuntimeARN,
		RuntimeSessionId: &sessionID,
		Payload:          payloadJSON,
		RuntimeUserId:    &config.UserID,
		Accept:           &acceptHeader, // Force streaming response
	}

	output, err := agentClient.InvokeAgentRuntime(ctx, input)
	if err != nil {
		notes.AppendWarning("Failed to invoke AgentCore runtime: %v", err)
		result.Actions = []types.Action{
			executor.NoteFrom(notes),
			executor.Escalate("Failed to invoke AgentCore"),
		}
		return result, nil
	}
	defer output.Response.Close()

	// Verify we got the expected streaming response
	contentType := ""
	if output.ContentType != nil {
		contentType = *output.ContentType
	}
	if !strings.Contains(contentType, "text/event-stream") {
		logging.Warnf("Expected text/event-stream but got: %s", contentType)
		notes.AppendWarning("Unexpected response format from AgentCore: %s", contentType)
	}

	// Read and collect streaming response
	logging.Info("Processing streaming AI response")
	var aiResponse strings.Builder
	aiResponse.WriteString("🤖 AI Investigation Results 🤖\n")
	aiResponse.WriteString(fmt.Sprintf("Session ID: %s\n", sessionID))
	aiResponse.WriteString(fmt.Sprintf("Runtime: %s\n", config.RuntimeARN))
	if config.Version != "" {
		aiResponse.WriteString(fmt.Sprintf("Agent Version: %s\n", config.Version))
	}
	if config.OpsSopVersion != "" {
		aiResponse.WriteString(fmt.Sprintf("ops-sop Version: %s\n", config.OpsSopVersion))
	}
	if config.RosaPluginsVersion != "" {
		aiResponse.WriteString(fmt.Sprintf("rosa-plugins Version: %s\n", config.RosaPluginsVersion))
	}
	aiResponse.WriteString("\n")

	scanner := bufio.NewScanner(output.Response)
	for scanner.Scan() {
		line := scanner.Text()
		// Streaming responses have lines prefixed with "data: "
		if strings.HasPrefix(line, "data: ") {
			data := strings.TrimPrefix(line, "data: ")
			aiResponse.WriteString(data + "\n")
		}
	}
	if err := scanner.Err(); err != nil {
		notes.AppendWarning("Error reading AI response stream: %v", err)
	}

	aiResponse.WriteString("\n🤖 AI investigation completed - escalating to SRE for review 🤖")

	// Append the complete AI investigation output as automation
	notes.AppendAutomation(aiResponse.String())

	// Return actions for executor to handle
	result.Actions = []types.Action{
		executor.NoteFrom(notes),
		executor.Escalate("AI investigation completed - manual review required"),
	}
	return result, nil
}

func (c *Investigation) Name() string {
	return "aiassisted"
}

func (c *Investigation) AlertTitle() string {
	// Return empty string - this investigation is used as a fallback, not for matching specific alert titles
	return ""
}

func (c *Investigation) Description() string {
	return "AI-powered investigation using AgentCore for unknown alerts"
}

func (c *Investigation) IsExperimental() bool {
	// TODO: Update to false when graduating to production
	return true
}

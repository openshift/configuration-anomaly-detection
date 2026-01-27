// Package aiassisted provides AI-powered investigation using AWS AgentCore
package aiassisted

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
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

// InvestigationPayload represents the payload sent to the AgentCore agent
type InvestigationPayload struct {
	InvestigationID      string `json:"investigation_id"`
	InvestigationPayload string `json:"investigation_payload"` // TODO: Implement - should contain alert details/context
	AlertName            string `json:"alert_name"`
	ClusterID            string `json:"cluster_id"`
}

// ToAgentCorePayload wraps the investigation data in the "prompt" field
func (p InvestigationPayload) ToAgentCorePayload() ([]byte, error) {
	// Marshal the investigation payload to JSON string
	innerJSON, err := json.Marshal(p)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal investigation payload: %w", err)
	}

	// Wrap in "prompt" field for AgentCore as a string
	wrapper := map[string]string{
		"prompt": string(innerJSON),
	}

	return json.Marshal(wrapper)
}

// generateSessionID generates a unique session ID for this investigation
func generateSessionID(incidentID string) string {
	timestamp := time.Now().Unix()
	randomBytes := make([]byte, 8)
	rand.Read(randomBytes) //nolint:errcheck,gosec
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

	awsAccessKeyID := os.Getenv("AGENTCORE_AWS_ACCESS_KEY_ID")
	if awsAccessKeyID == "" {
		notes.AppendWarning("Failed to get AGENTCORE_AWS_ACCESS_KEY_ID")
		result.Actions = []types.Action{
			executor.NoteFrom(notes),
			executor.Escalate("Failed to get AGENTCORE_AWS_ACCESS_KEY_ID"),
		}
		return result, nil
	}
	awsSecretAccessKey := os.Getenv("AGENTCORE_AWS_SECRET_ACCESS_KEY")
	if awsSecretAccessKey == "" {
		notes.AppendWarning("Failed to get AGENTCORE_AWS_SECRET_ACCESS_KEY")
		result.Actions = []types.Action{
			executor.NoteFrom(notes),
			executor.Escalate("Failed to get AGENTCORE_AWS_SECRET_ACCESS_KEY"),
		}
		return result, nil
	}

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), config.GetTimeout())
	defer cancel()

	// Create AWS config directly without LoadDefaultConfig
	// This bypasses all default credential chain logic
	awsCfg := awsconfig.Config{
		Region:      config.Region,
		Credentials: credentials.NewStaticCredentialsProvider(awsAccessKeyID, awsSecretAccessKey, ""),
	}

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

	incidentID := pdClient.GetIncidentID()
	alertName := pdClient.GetTitle()

	// Build investigation payload using typed structure
	investigationData := &InvestigationPayload{
		InvestigationID:      incidentID,
		InvestigationPayload: "", // TODO: Populate with alert details when implemented
		AlertName:            alertName,
		ClusterID:            clusterID,
	}

	// Convert to AgentCore payload format
	payloadJSON, err := investigationData.ToAgentCorePayload()
	if err != nil {
		notes.AppendWarning("Failed to build investigation payload: %v", err)
		result.Actions = []types.Action{
			executor.NoteFrom(notes),
			executor.Escalate("Failed to create investigation prompt"),
		}
		return result, nil
	}

	// Create AgentCore client
	agentClient := aws.NewAgentCoreClient(awsCfg)

	// Generate unique session ID for this investigation
	sessionID := generateSessionID(incidentID)

	// Log AI invocation
	logging.Infof("🤖 Invoking AI agent for incident %s", incidentID)
	logging.Infof("Payload: %s", string(payloadJSON))

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
	defer func() {
		if closeErr := output.Response.Close(); closeErr != nil {
			logging.Warnf("Failed to close AgentCore response stream: %v", closeErr)
		}
	}()

	// Read and collect streaming response
	logging.Info("🤖 Receiving AI response...")
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
		line = strings.TrimPrefix(line, "data: ")
		aiResponse.WriteString(line + "\n")
	}

	if err := scanner.Err(); err != nil {
		logging.Errorf("Error reading AI response stream: %v", err)
		notes.AppendWarning("Error reading AI response stream: %v", err)
	}

	logging.Info("🤖 AI investigation complete")
	logging.Infof("AI Output:\n%s", aiResponse.String())

	// Add simple note about AI automation completion
	notes.AppendAutomation("🤖 AI automation completed. Check cluster report for investigation details.")

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

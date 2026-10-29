// Package aiassisted provides AI-powered investigation using AWS AgentCore
package aiassisted

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/bedrockagentcore"
	"github.com/openshift/configuration-anomaly-detection/pkg/aws"
	"github.com/openshift/configuration-anomaly-detection/pkg/config"
	"github.com/openshift/configuration-anomaly-detection/pkg/executor"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/investigation"
	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
)

// Name is the investigation's registered name, used to reference it from
// investigation-entry configs (e.g. the AI-fallback chain in pagerduty.go).
const Name = "aiassisted"

type Investigation struct {
	AIConfig *config.AIAgentConfig

	// Optional factory for offline tests; production uses aws.GetAIClient.
	getAIClient func(context.Context, string, string, string) (aws.AgentCoreAPI, error)
}

// InvestigationPayload represents the payload sent to the AgentCore agent.
type InvestigationPayload struct {
	InvestigationID      string               `json:"investigation_id"`
	InvestigationPayload string               `json:"investigation_payload"` // TODO: Implement - should contain alert details/context
	AlertName            string               `json:"alert_name"`
	ClusterID            string               `json:"cluster_id"`
	CloudTrail           *CloudTrailReference `json:"cloudtrail,omitempty"`
}

// generateSessionID generates a unique session ID for this investigation
func generateSessionID(incidentID string) string {
	timestamp := time.Now().Unix()
	randomBytes := make([]byte, 8)
	if _, err := rand.Read(randomBytes); err != nil {
		return fmt.Sprintf("cad-%s-%d-fallback", incidentID, timestamp)
	}
	randomHex := hex.EncodeToString(randomBytes)
	return fmt.Sprintf("cad-%s-%d-%s", incidentID, timestamp, randomHex)
}

func (c *Investigation) Run(rb investigation.ResourceBuilder) (investigation.InvestigationResult, error) {
	result := investigation.InvestigationResult{}

	// Build resources
	r, err := rb.WithNotes().WithCluster().Build()
	if err != nil {
		return result, err
	}

	notes := r.Notes

	clusterID := r.Cluster.ID()

	if r.IsHCP {
		notes.AppendWarning("HCP cluster - skipping AI investigation")
		result.Actions = []executor.Action{
			executor.NoteFrom(notes),
			executor.Escalate("Cluster is HCP - AI investigation not supported"),
		}
		return result, nil
	}

	if r.IsInfrastructureCluster {
		notes.AppendWarning("Management/Service cluster - skipping AI investigation")
		result.Actions = []executor.Action{
			executor.NoteFrom(notes),
			executor.Escalate("Cluster is a management/service cluster - AI investigation not supported"),
		}
		return result, nil
	}

	if c.AIConfig == nil {
		notes.AppendWarning("AI agent runtime configuration not set (ai_agent section missing from config)")
		result.Actions = append(
			executor.NoteAndReportFrom(notes, clusterID, c.Name()),
			executor.Escalate("AI runtime config not set"),
		)
		return result, nil
	}

	aiConfig := c.AIConfig

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.TODO(), aiConfig.GetTimeout())
	defer cancel()

	// Get PagerDuty incident details
	if r.PdClient == nil {
		notes.AppendWarning("Failed to access PagerDuty client details")
		result.Actions = append(
			executor.NoteAndReportFrom(notes, clusterID, c.Name()),
			executor.Escalate("Failed to access PagerDuty client"),
		)
		return result, nil
	}

	// Return reporting actions before escalation, including on AI failures.
	// Cora's recommendation is informational and never suppresses escalation.
	failureActions := func() []executor.Action {
		return append(executor.NoteAndReportFrom(notes, clusterID, c.Name()),
			executor.Escalate("AI investigation failed - manual review required"))
	}

	incidentID := r.PdClient.GetIncidentID()
	alertName := r.PdClient.GetTitle()
	sessionID := generateSessionID(incidentID)
	var cloudtrailRef *CloudTrailReference
	if aiConfig.CloudTrail != nil && aiConfig.CloudTrail.Enabled && !isDryRun(r) {
		cloudtrailRef = c.collectAndPublishCloudTrail(ctx, rb, r, incidentID, sessionID)
	} else if aiConfig.CloudTrail != nil && aiConfig.CloudTrail.Enabled {
		logging.Info("Skipping CloudTrail evidence collection during dry-run")
	}

	// Build investigation payload using typed structure
	investigationData := &InvestigationPayload{
		InvestigationID:      incidentID,
		InvestigationPayload: "{}", // TODO: Populate with alert details when implemented
		AlertName:            alertName,
		ClusterID:            clusterID,
		CloudTrail:           cloudtrailRef,
	}

	// Marshal to JSON for AgentCore
	payloadJSON, err := json.Marshal(investigationData)
	if err != nil {
		notes.AppendWarning("Failed to marshal investigation payload: %v", err)
		result.Actions = failureActions()
		return result, nil
	}

	// Get AI client (handles role assumption and client creation)
	// Use incident ID as session identifier for audit trail
	getAIClient := c.getAIClient
	if getAIClient == nil {
		getAIClient = aws.GetAIClient
	}
	agentClient, err := getAIClient(ctx, aiConfig.InvokerRoleArn, aiConfig.Region, incidentID)
	if err != nil {
		notes.AppendWarning("Failed to create AI client: %v", err)
		result.Actions = failureActions()
		return result, nil
	}

	// Log AI invocation
	logging.Infof("🤖 Invoking AI agent for incident %s", incidentID)

	// Request streaming response format
	acceptHeader := "text/event-stream"
	input := &bedrockagentcore.InvokeAgentRuntimeInput{
		AgentRuntimeArn:  &aiConfig.RuntimeARN,
		RuntimeSessionId: &sessionID,
		Payload:          payloadJSON,
		RuntimeUserId:    &aiConfig.UserID,
		Accept:           &acceptHeader, // Force streaming response
	}

	output, err := agentClient.InvokeAgentRuntime(ctx, input)
	if err != nil {
		notes.AppendWarning("Failed to invoke AgentCore runtime: %v", err)
		result.Actions = failureActions()
		return result, nil
	}
	defer func() {
		if closeErr := output.Response.Close(); closeErr != nil {
			logging.Warnf("Failed to close AgentCore response stream: %v", closeErr)
		}
	}()

	// Read and collect streaming response
	logging.Info("🤖 Receiving AI response...")
	logging.Infof("🤖 AI Investigation Results")
	logging.Infof("Session ID: %s", sessionID)
	logging.Infof("Runtime: %s", aiConfig.RuntimeARN)
	if aiConfig.Version != "" {
		logging.Infof("Agent Version: %s", aiConfig.Version)
	}
	if aiConfig.OpsSopVersion != "" {
		logging.Infof("ops-sop Version: %s", aiConfig.OpsSopVersion)
	}
	if aiConfig.RosaPluginsVersion != "" {
		logging.Infof("rosa-plugins Version: %s", aiConfig.RosaPluginsVersion)
	}

	aiResponse, streamErr := readAIResponse(output.Response)

	// A cancelled HTTP stream can end at EOF without a scanner error. Do not
	// treat a partial (or even valid-looking) response after timeout as success.
	if err := ctx.Err(); err != nil {
		notes.AppendWarning("AI investigation timed out or was cancelled: %v", err)
		result.Actions = failureActions()
		return result, nil
	}

	if streamErr != nil {
		logging.Errorf("Error reading AI response stream: %v", streamErr)
		notes.AppendWarning("Error reading AI response stream: %v\n\nRaw output:\n%s", streamErr, aiResponse)
		result.Actions = failureActions()
		return result, nil
	}

	logging.Info("🤖 AI investigation complete")

	// Unwrap double-encoded JSON from BedrockAgentCore SDK.
	// The SDK wraps Cora's JSON in another JSON string, so we receive:
	//   "{\"investigation_id\": ...}" instead of {"investigation_id": ...}
	// Unmarshal into a string to strip outer quotes and unescape.
	responseStr := strings.TrimSpace(aiResponse)
	var unquoted string
	if err := json.Unmarshal([]byte(responseStr), &unquoted); err == nil {
		responseStr = unquoted
	}

	// Log raw response for recoverability
	logging.Infof("Raw AI response length: %d chars", len(responseStr))

	// Parse JSON response from Cora
	var investigationResult CoraInvestigationResult
	if err := json.Unmarshal([]byte(responseStr), &investigationResult); err != nil {
		rawOutput := responseStr
		if len(rawOutput) > 60000 {
			rawOutput = rawOutput[:60000] + "\n... [truncated]"
		}
		notes.AppendWarning("Failed to parse Cora JSON response: %v\n\nRaw output:\n%s", err, rawOutput)
		result.Actions = failureActions()
		return result, nil
	}

	// Format to human-readable markdown for backplane report
	formattedReport := FormatInvestigationReport(&investigationResult)

	// Add the structured result to the shared note writer. The Backplane report
	// action appends its returned report ID before the PagerDuty note is sent.
	pdNote := FormatPagerDutyNote(&investigationResult)
	notes.AppendText(pdNote)

	// Create backplane report action with formatted output
	backplaneReportAction := &executor.BackplaneReportAction{
		ClusterID: r.Cluster.ExternalID(),
		Summary:   fmt.Sprintf("CAD Investigation: AI-Assisted Analysis for %s", alertName),
		Data:      formattedReport,
	}

	// Return actions for executor to handle
	result.Actions = []executor.Action{
		backplaneReportAction,    // Create cluster report first
		executor.NoteFrom(notes), // Include the report ID appended by the report action
		executor.Escalate("AI investigation completed - manual review required"),
	}
	return result, nil
}

// readAIResponse collects the data lines while preserving partial output on failure.
func readAIResponse(response io.Reader) (string, error) {
	var result strings.Builder
	scanner := bufio.NewScanner(response)
	for scanner.Scan() {
		result.WriteString(strings.TrimPrefix(scanner.Text(), "data: ") + "\n")
	}
	return result.String(), scanner.Err()
}

func isDryRun(resources *investigation.Resources) bool {
	return resources != nil && resources.Params != nil && strings.EqualFold(resources.Params["CAD_DRY_RUN"], "true")
}

func (c *Investigation) Name() string {
	return Name
}

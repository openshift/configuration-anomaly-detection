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

	"github.com/aws/aws-sdk-go-v2/service/bedrockagentcore"
	"github.com/openshift/configuration-anomaly-detection/pkg/aws"
	"github.com/openshift/configuration-anomaly-detection/pkg/config"
	"github.com/openshift/configuration-anomaly-detection/pkg/executor"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/investigation"
	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
	"github.com/openshift/configuration-anomaly-detection/pkg/pagerduty"
)

type Investigation struct {
	AIConfig *config.AIAgentConfig
}

// InvestigationPayload represents the payload sent to the AgentCore agent
type InvestigationPayload struct {
	InvestigationID      string `json:"investigation_id"`
	InvestigationPayload string `json:"investigation_payload"` // TODO: Implement - should contain alert details/context
	AlertName            string `json:"alert_name"`
	ClusterID            string `json:"cluster_id"`
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
		result.Actions = append(
			executor.NoteAndReportFrom(notes, clusterID, c.Name()),
			executor.Escalate("Cluster is HCP - AI investigation not supported"),
		)
		return result, nil
	}

	if r.IsInfrastructureCluster {
		notes.AppendWarning("Management/Service cluster - skipping AI investigation")
		result.Actions = append(
			executor.NoteAndReportFrom(notes, clusterID, c.Name()),
			executor.Escalate("Cluster is a management/service cluster - AI investigation not supported"),
		)
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
	pdClient, ok := r.PdClient.(*pagerduty.SdkClient)
	if !ok {
		notes.AppendWarning("Failed to access PagerDuty client details")
		result.Actions = append(
			executor.NoteAndReportFrom(notes, clusterID, c.Name()),
			executor.Escalate("Failed to access PagerDuty client"),
		)
		return result, nil
	}

	// Escalate immediately - AI investigations always go to SRE.
	// Results will be posted async to PD notes for review.
	if err := r.PdClient.EscalateIncident(); err != nil {
		// Fail pipeline - if there's no incident or issue reaching PD, there's nothing to post results back to
		logging.Errorf("Failed to escalate incident for AI investigation: %v", err)
		return result, investigation.WrapInfrastructure(err, "PagerDuty incident escalation failed")
	}
	logging.Info("Incident escalated immediately for AI investigation - SRE can review results async")

	incidentID := pdClient.GetIncidentID()
	alertName := pdClient.GetTitle()

	// Build investigation payload using typed structure
	investigationData := &InvestigationPayload{
		InvestigationID:      incidentID,
		InvestigationPayload: "{}", // TODO: Populate with alert details when implemented
		AlertName:            alertName,
		ClusterID:            clusterID,
	}

	// Marshal to JSON for AgentCore
	payloadJSON, err := json.Marshal(investigationData)
	if err != nil {
		notes.AppendWarning("Failed to marshal investigation payload: %v", err)
		result.Actions = executor.NoteAndReportFrom(notes, clusterID, c.Name())
		return result, nil
	}

	// Get AI client (handles role assumption and client creation)
	// Use incident ID as session identifier for audit trail
	agentClient, err := aws.GetAIClient(ctx, aiConfig.InvokerRoleArn, aiConfig.Region, incidentID)
	if err != nil {
		notes.AppendWarning("Failed to create AI client: %v", err)
		result.Actions = executor.NoteAndReportFrom(notes, clusterID, c.Name())
		return result, nil
	}

	// TODO: Move session ID generation outside of AI investigation so all investigations have unique IDs
	// This will require adapting this code to use the externally-generated ID instead
	// Generate unique session ID for this investigation
	sessionID := generateSessionID(incidentID)

	// Log AI invocation
	logging.Infof("🤖 Invoking AI agent for incident %s", incidentID)
	logging.Infof("Payload: %s", string(payloadJSON))

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
		result.Actions = executor.NoteAndReportFrom(notes, clusterID, c.Name())
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
	fmt.Fprintf(&aiResponse, "Session ID: %s\n", sessionID)
	fmt.Fprintf(&aiResponse, "Runtime: %s\n", aiConfig.RuntimeARN)
	if aiConfig.Version != "" {
		fmt.Fprintf(&aiResponse, "Agent Version: %s\n", aiConfig.Version)
	}
	if aiConfig.OpsSopVersion != "" {
		fmt.Fprintf(&aiResponse, "ops-sop Version: %s\n", aiConfig.OpsSopVersion)
	}
	if aiConfig.RosaPluginsVersion != "" {
		fmt.Fprintf(&aiResponse, "rosa-plugins Version: %s\n", aiConfig.RosaPluginsVersion)
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
	notes.AppendAutomation("AI automation completed. Check recent cluster reports for AI investigation details: 'osdctl cluster reports list --cluster-id %s'", clusterID)

	// Create backplane report action with the AI investigation results
	backplaneReportAction := &executor.BackplaneReportAction{
		ClusterID: r.Cluster.ExternalID(),
		Summary:   fmt.Sprintf("CAD Investigation: AI-Assisted Analysis for %s", alertName),
		Data:      aiResponse.String(),
	}

	// Return actions for executor to handle
	result.Actions = []executor.Action{
		executor.NoteFrom(notes), // Send automation message to PagerDuty
		backplaneReportAction,    // Create cluster report with AI investigation results
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

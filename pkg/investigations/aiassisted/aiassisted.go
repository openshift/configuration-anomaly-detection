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

	awsconfig "github.com/aws/aws-sdk-go-v2/aws"
	awssdk "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/bedrockagentcore"
	"github.com/aws/aws-sdk-go-v2/service/sts"
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
	r, err := rb.WithNotes().Build()
	if err != nil {
		return result, err
	}

	notes := r.Notes

	clusterID := r.Cluster.ID()

	if c.AIConfig == nil {
		notes.AppendWarning("AI agent runtime configuration not set (ai_agent section missing from config)")
		result.Actions = append(
			executor.NoteAndReportFrom(notes, clusterID, c.Name()),
			executor.Escalate("AI runtime config not set"),
		)
		return result, nil
	}

	config := c.AIConfig

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), config.GetTimeout())
	defer cancel()

	// Load default AWS config (uses default credential chain)
	awsCfg, err := awssdk.LoadDefaultConfig(ctx, awssdk.WithRegion(config.Region))
	if err != nil {
		notes.AppendWarning("Failed to load AWS config: %v", err)
		result.Actions = append(
			executor.NoteAndReportFrom(notes, clusterID, c.Name()),
			executor.Escalate("Failed to load AWS config"),
		)
		return result, nil
	}

	// Assume the CORA invoker IAM role with permissions to call AgentCore
	roleArnToAssume := config.InvokerRoleArn

	// Create STS client to assume the role
	stsClient := sts.NewFromConfig(awsCfg)

	// Get and log the identity of the original caller
	callerIdentity, err := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		logging.Warnf("Failed to get original caller identity: %v", err)
	} else {
		logging.Infof("Original Caller: %s", *callerIdentity.Arn)
	}

	// Assume the role
	assumeRoleOutput, err := stsClient.AssumeRole(ctx, &sts.AssumeRoleInput{
		RoleArn:         &roleArnToAssume,
		RoleSessionName: awsconfig.String("CAD-AI-Investigation"),
		DurationSeconds: awsconfig.Int32(3600), // 1 hour
	})
	if err != nil {
		notes.AppendWarning("Failed to assume IAM role: %v", err)
		result.Actions = append(
			executor.NoteAndReportFrom(notes, clusterID, c.Name()),
			executor.Escalate("Failed to assume IAM role"),
		)
		return result, nil
	}

	// Create new AWS config with the assumed role credentials
	awsCfg.Credentials = credentials.NewStaticCredentialsProvider(
		*assumeRoleOutput.Credentials.AccessKeyId,
		*assumeRoleOutput.Credentials.SecretAccessKey,
		*assumeRoleOutput.Credentials.SessionToken,
	)

	// Verify the assumed role identity
	stsClient2 := sts.NewFromConfig(awsCfg)
	callerIdentity2, err := stsClient2.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		logging.Warnf("Failed to get assumed role caller identity: %v", err)
	} else {
		logging.Infof("AssumedRole Caller: %s", *callerIdentity2.Arn)
	}

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
		result.Actions = append(
			executor.NoteAndReportFrom(notes, clusterID, c.Name()),
			executor.Escalate("Failed to create investigation payload"),
		)
		return result, nil
	}

	// Create AgentCore client
	agentClient := aws.NewAgentCoreClient(awsCfg)

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
		AgentRuntimeArn:  &config.RuntimeARN,
		RuntimeSessionId: &sessionID,
		Payload:          payloadJSON,
		RuntimeUserId:    &config.UserID,
		Accept:           &acceptHeader, // Force streaming response
	}

	output, err := agentClient.InvokeAgentRuntime(ctx, input)
	if err != nil {
		notes.AppendWarning("Failed to invoke AgentCore runtime: %v", err)
		result.Actions = append(
			executor.NoteAndReportFrom(notes, clusterID, c.Name()),
			executor.Escalate("Failed to invoke AgentCore"),
		)
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
	fmt.Fprintf(&aiResponse, "Runtime: %s\n", config.RuntimeARN)
	if config.Version != "" {
		fmt.Fprintf(&aiResponse, "Agent Version: %s\n", config.Version)
	}
	if config.OpsSopVersion != "" {
		fmt.Fprintf(&aiResponse, "ops-sop Version: %s\n", config.OpsSopVersion)
	}
	if config.RosaPluginsVersion != "" {
		fmt.Fprintf(&aiResponse, "rosa-plugins Version: %s\n", config.RosaPluginsVersion)
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
	notes.AppendAutomation("AI automation completed. Check recent cluster reports for report Summary %s: 'osdctl cluster reports list --cluster-id %s'", incidentID, clusterID)

	// Return actions for executor to handle
	result.Actions = append(
		executor.NoteAndReportFrom(notes, clusterID, c.Name()),
		executor.Escalate("AI investigation completed - manual review required"),
	)
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

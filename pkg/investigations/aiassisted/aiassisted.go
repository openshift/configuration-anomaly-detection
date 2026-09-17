// Package aiassisted provides AI-powered investigation using AWS AgentCore
package aiassisted

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
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

const (
	cloudTrailLookback = 2 * time.Hour
	cloudTrailTimeout  = 60 * time.Second
	cloudTrailMaxBytes = 5 * 1024 * 1024
)

// InvestigationPayload represents the payload sent to the AgentCore agent
type InvestigationPayload struct {
	InvestigationID      string               `json:"investigation_id"`
	InvestigationPayload string               `json:"investigation_payload"` // TODO: Implement - should contain alert details/context
	AlertName            string               `json:"alert_name"`
	ClusterID            string               `json:"cluster_id"`
	CloudTrail           *CloudTrailReference `json:"cloudtrail,omitempty"`
}

type CloudTrailReference struct {
	SchemaVersion   int       `json:"schema_version"`
	Status          string    `json:"status"`
	StorageStatus   string    `json:"storage_status"`
	InvocationID    string    `json:"invocation_id"`
	ReportID        string    `json:"report_id,omitempty"`
	ReportClusterID string    `json:"report_cluster_id"`
	SHA256          string    `json:"sha256,omitempty"`
	EventCount      int       `json:"event_count"`
	StartTime       time.Time `json:"start_time"`
	EndTime         time.Time `json:"end_time"`
	StopReason      string    `json:"stop_reason"`
	ErrorCategory   string    `json:"error_category,omitempty"`
}

type cloudTrailEvidenceReport struct {
	Kind            string                   `json:"kind"`
	SchemaVersion   int                      `json:"schema_version"`
	InvestigationID string                   `json:"investigation_id"`
	InvocationID    string                   `json:"invocation_id"`
	Collection      aws.CloudTrailCollection `json:"collection"`
	Events          []json.RawMessage        `json:"events"`
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

	var aiResponse strings.Builder

	scanner := bufio.NewScanner(output.Response)
	for scanner.Scan() {
		line := scanner.Text()
		// Streaming responses have lines prefixed with "data: "
		line = strings.TrimPrefix(line, "data: ")
		aiResponse.WriteString(line + "\n")
	}

	if err := scanner.Err(); err != nil {
		logging.Errorf("Error reading AI response stream: %v", err)
		notes.AppendWarning("Error reading AI response stream: %v\n\nRaw output:\n%s", err, aiResponse.String())
		result.Actions = executor.NoteAndReportFrom(notes, clusterID, c.Name())
		return result, nil
	}

	logging.Info("🤖 AI investigation complete")

	// Unwrap double-encoded JSON from BedrockAgentCore SDK.
	// The SDK wraps Cora's JSON in another JSON string, so we receive:
	//   "{\"investigation_id\": ...}" instead of {"investigation_id": ...}
	// Unmarshal into a string to strip outer quotes and unescape.
	responseStr := strings.TrimSpace(aiResponse.String())
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
		result.Actions = executor.NoteAndReportFrom(notes, clusterID, c.Name())
		return result, nil
	}

	// Format to human-readable markdown for backplane report
	formattedReport := FormatInvestigationReport(&investigationResult)

	// Format a structured PD note with the investigation summary.
	// Use the authoritative cluster external ID (not Cora's response) for the
	// osdctl footer so the command always matches the backplane report.
	reportClusterID := r.Cluster.ExternalID()
	pdNote := FormatPagerDutyNote(&investigationResult, reportClusterID)

	// Create backplane report action with formatted output
	backplaneReportAction := &executor.BackplaneReportAction{
		ClusterID: reportClusterID,
		Summary:   fmt.Sprintf("CAD Investigation: AI-Assisted Analysis for %s", alertName),
		Data:      formattedReport,
	}

	// Return actions for executor to handle
	result.Actions = []executor.Action{
		backplaneReportAction, // Create cluster report first
		executor.Note(pdNote), // Post structured investigation summary to PagerDuty
	}
	return result, nil
}

func (c *Investigation) collectAndPublishCloudTrail(ctx context.Context, rb investigation.ResourceBuilder, resources *investigation.Resources, incidentID, invocationID string) *CloudTrailReference {
	ref := &CloudTrailReference{SchemaVersion: 1, Status: "unavailable", StorageStatus: "unavailable", InvocationID: invocationID, ReportClusterID: resources.Cluster.ExternalID()}
	awsResources, buildErr := rb.WithAwsClient().Build()
	if buildErr != nil || awsResources == nil || awsResources.AwsClient == nil {
		ref.ErrorCategory = "aws_client_unavailable"
		return ref
	}
	collector, ok := awsResources.AwsClient.(interface {
		CollectCloudTrailEvents(context.Context, aws.CloudTrailCollectionOptions) (aws.CloudTrailCollection, error)
	})
	if !ok {
		ref.ErrorCategory = "cloudtrail_collector_unavailable"
		return ref
	}
	collectionCtx, cancel := context.WithTimeout(ctx, cloudTrailTimeout)
	defer cancel()
	end := time.Now().UTC()
	region := ""
	if baseConfig := awsResources.AwsClient.GetBaseConfig(); baseConfig != nil {
		region = baseConfig.Region
	}
	collection, collectErr := collector.CollectCloudTrailEvents(collectionCtx, aws.CloudTrailCollectionOptions{
		StartTime: end.Add(-cloudTrailLookback), EndTime: end,
		MaxEvents: aws.CloudTrailMaxEvents, MaxBytes: cloudTrailMaxBytes,
		Region: region,
	})
	ref.Status, ref.EventCount, ref.StartTime, ref.EndTime, ref.StopReason, ref.ErrorCategory = collection.Status, collection.EventCount, collection.StartTime, collection.EndTime, collection.StopReason, collection.ErrorCategory
	if collectErr != nil && ref.ErrorCategory == "" {
		ref.ErrorCategory = "collection_failed"
	}

	events := make([]json.RawMessage, 0, len(collection.Events))
	for _, event := range collection.Events {
		events = append(events, event.Data)
	}
	report := cloudTrailEvidenceReport{Kind: "cad.cloudtrail", SchemaVersion: 1, InvestigationID: incidentID, InvocationID: invocationID, Collection: collection, Events: events}
	report.Collection.Events = nil
	reportBytes, err := json.Marshal(report)
	if err != nil {
		ref.ErrorCategory = "report_marshal_failed"
		return ref
	}
	// The collector's event budget does not include the report envelope. Trim
	// whole events if necessary so the decoded report remains within budget.
	for cloudTrailMaxBytes > 0 && len(reportBytes) > cloudTrailMaxBytes && len(report.Events) > 0 {
		report.Events = report.Events[:len(report.Events)-1]
		report.Collection.Status, report.Collection.StopReason = "partial", "byte_limit"
		report.Collection.EventCount = len(report.Events)
		report.Collection.ByteCount = 0
		for _, event := range report.Events {
			report.Collection.ByteCount += len(event) + 1
		}
		ref.Status, ref.StopReason, ref.EventCount = "partial", "byte_limit", len(report.Events)
		reportBytes, err = json.Marshal(report)
		if err != nil {
			ref.ErrorCategory = "report_marshal_failed"
			return ref
		}
	}
	if cloudTrailMaxBytes > 0 && len(reportBytes) > cloudTrailMaxBytes {
		ref.Status, ref.StorageStatus, ref.ErrorCategory = "unavailable", "unavailable", "report_envelope_exceeds_limit"
		return ref
	}
	digest := sha256.Sum256(reportBytes)
	ref.SHA256 = hex.EncodeToString(digest[:])
	ref.StorageStatus = "unavailable"
	if resources.BpClient == nil {
		ref.ErrorCategory = "backplane_client_unavailable"
		return ref
	}
	uploadCtx, uploadCancel := context.WithTimeout(ctx, 15*time.Second)
	defer uploadCancel()
	backplaneReport, err := resources.BpClient.CreateReport(uploadCtx, resources.Cluster.ExternalID(), fmt.Sprintf("CAD CloudTrail evidence: %s / %s", incidentID, invocationID), string(reportBytes))
	if err != nil || backplaneReport == nil || backplaneReport.ReportId == "" {
		if err != nil {
			ref.ErrorCategory = "report_upload_failed"
		} else {
			ref.ErrorCategory = "report_upload_missing_id"
		}
		return ref
	}
	ref.ReportID, ref.StorageStatus = backplaneReport.ReportId, "available"
	logging.Infof("CloudTrail evidence collected: status=%s events=%d bytes=%d report_id=%s", collection.Status, len(collection.Events), len(reportBytes), ref.ReportID)
	return ref
}

func isDryRun(resources *investigation.Resources) bool {
	return resources != nil && resources.Params != nil && strings.EqualFold(resources.Params["CAD_DRY_RUN"], "true")
}

func (c *Investigation) Name() string {
	return "aiassisted"
}

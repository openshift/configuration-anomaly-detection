package aiassisted

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/openshift/configuration-anomaly-detection/pkg/aws"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/investigation"
	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
)

const (
	cloudTrailLookback          = 2 * time.Hour
	cloudTrailTimeout           = 60 * time.Second
	cloudTrailMaxBytes          = 5 * 1024 * 1024
	cloudTrailStatusUnavailable = "unavailable"
)

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

func (c *Investigation) collectAndPublishCloudTrail(ctx context.Context, rb investigation.ResourceBuilder, resources *investigation.Resources, incidentID, invocationID string) *CloudTrailReference {
	ref := &CloudTrailReference{SchemaVersion: 1, Status: cloudTrailStatusUnavailable, StorageStatus: cloudTrailStatusUnavailable, InvocationID: invocationID, ReportClusterID: resources.Cluster.ExternalID()}
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
		ref.Status, ref.StorageStatus, ref.ErrorCategory = cloudTrailStatusUnavailable, cloudTrailStatusUnavailable, "report_envelope_exceeds_limit"
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

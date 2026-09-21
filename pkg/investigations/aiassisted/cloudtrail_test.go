package aiassisted

import (
	"encoding/json"
	"testing"

	"github.com/openshift/configuration-anomaly-detection/pkg/aws"
)

func TestCloudTrailEvidenceReportKeepsEventsAtTopLevel(t *testing.T) {
	event := json.RawMessage(`{"eventID":"event-1","eventName":"DescribeInstances"}`)
	report := cloudTrailEvidenceReport{
		Kind:            "cad.cloudtrail",
		SchemaVersion:   1,
		InvestigationID: "incident-1",
		InvocationID:    "invocation-1",
		Collection: aws.CloudTrailCollection{
			Status: "complete",
			Events: []aws.CloudTrailEvent{{Data: event}},
		},
		Events: []json.RawMessage{event},
	}

	report.Collection.Events = nil
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("failed to marshal CloudTrail evidence report: %v", err)
	}

	var decoded map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("failed to decode CloudTrail evidence report: %v", err)
	}
	if _, ok := decoded["events"]; !ok {
		t.Fatal("CloudTrail evidence report is missing top-level events")
	}
	if collection := string(decoded["collection"]); collection == "" || collection == "null" {
		t.Fatal("CloudTrail evidence report is missing collection metadata")
	}
}

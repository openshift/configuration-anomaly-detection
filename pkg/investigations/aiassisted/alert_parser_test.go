package aiassisted

import (
	"encoding/json"
	"testing"
)

func TestParseFiringJSON(t *testing.T) {
	tests := []struct {
		name          string
		input         string
		expectedCount int
		expectErr     bool
	}{
		{
			name: "single alert",
			input: mustMarshal([]FiringAlert{{
				Labels: map[string]string{
					"alertname": "KubePersistentVolumeFillingUp",
					"namespace": "openshift-monitoring",
					"severity":  "critical",
				},
			}}),
			expectedCount: 1,
		},
		{
			name:          "empty string",
			input:         "",
			expectedCount: 0,
		},
		{
			name:      "invalid JSON",
			input:     "not json",
			expectErr: true,
		},
		{
			name:          "empty array",
			input:         "[]",
			expectedCount: 0,
		},
		{
			name: "multiple firing alerts",
			input: mustMarshal([]FiringAlert{
				{Labels: map[string]string{"alertname": "Alert1", "namespace": "ns1"}},
				{Labels: map[string]string{"alertname": "Alert2", "namespace": "ns2"}},
			}),
			expectedCount: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseFiringJSON(tt.input)

			if tt.expectErr {
				if err == nil {
					t.Error("Expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
			if len(result) != tt.expectedCount {
				t.Errorf("Expected %d alerts, got %d", tt.expectedCount, len(result))
			}
		})
	}
}

func TestPayloadStructure(t *testing.T) {
	firingJSON := mustMarshal([]FiringAlert{
		{
			Labels: map[string]string{
				"alertname":             "KubePersistentVolumeFillingUp",
				"namespace":             "openshift-monitoring",
				"persistentvolumeclaim": "prometheus-data-prometheus-k8s-0",
				"severity":              "critical",
			},
			StartsAt: "2026-07-07T12:00:00Z",
		},
		{
			Labels: map[string]string{
				"alertname":             "KubePersistentVolumeFillingUp",
				"namespace":             "openshift-monitoring",
				"persistentvolumeclaim": "prometheus-data-prometheus-k8s-1",
				"severity":              "critical",
			},
			StartsAt: "2026-07-07T12:01:00Z",
		},
	})

	details := map[string]interface{}{
		"firing_json":          firingJSON,
		"link":                 "https://github.com/openshift/runbooks/blob/master/alerts/cluster-monitoring-operator/KubePersistentVolumeFillingUp.md",
		"num_firing":           "2",
		"region":               "us-west-2",
		"suggested_next_steps": "This should be filtered out",
	}

	payloadData := buildInvestigationPayload(details, "https://redhat.pagerduty.com/incidents/Q3OFA2AM9FYDAB")

	if payloadData["incident_url"] != "https://redhat.pagerduty.com/incidents/Q3OFA2AM9FYDAB" {
		t.Errorf("Expected incident_url, got %v", payloadData["incident_url"])
	}

	firingAlerts, ok := payloadData["firing_alerts"].([]FiringAlert)
	if !ok {
		t.Fatal("Expected firing_alerts in payload")
	}
	if len(firingAlerts) != 2 {
		t.Errorf("Expected 2 firing alerts, got %d", len(firingAlerts))
	}
	if firingAlerts[1].Labels["persistentvolumeclaim"] != "prometheus-data-prometheus-k8s-1" {
		t.Errorf("Expected second alert's PVC, got %s", firingAlerts[1].Labels["persistentvolumeclaim"])
	}

	alertDetails := payloadData["alert_details"].(map[string]interface{})
	if _, ok := alertDetails["link"]; !ok {
		t.Error("Expected link in alert_details")
	}
	if _, ok := alertDetails["num_firing"]; !ok {
		t.Error("Expected num_firing in alert_details")
	}
	if _, ok := alertDetails["region"]; !ok {
		t.Error("Expected region in alert_details")
	}
	if _, ok := alertDetails["suggested_next_steps"]; ok {
		t.Error("suggested_next_steps should not be in alert_details (not in allow-list)")
	}
}

func TestPayloadFallbackRawJSON(t *testing.T) {
	invalidJSON := "not valid json {{"

	details := map[string]interface{}{
		"firing_json": invalidJSON,
		"link":        "https://example.com/runbook",
		"num_firing":  "1",
	}

	payloadData := buildInvestigationPayload(details, "https://redhat.pagerduty.com/incidents/TEST123")

	if _, hasFiring := payloadData["firing_alerts"]; hasFiring {
		t.Error("firing_alerts should not be present when parsing fails")
	}

	raw, hasRaw := payloadData["firing_json_raw"].(string)
	if !hasRaw {
		t.Fatal("Expected firing_json_raw fallback when parsing fails")
	}
	if raw != invalidJSON {
		t.Errorf("Expected raw string %q, got %q", invalidJSON, raw)
	}
}

func TestPayloadWithRealisticPDJSON(t *testing.T) {
	details := map[string]interface{}{
		"cluster_id":   "1a2b3c4d-5e6f-7890-abcd-ef1234567890",
		"firing_json":  `[{"labels":{"alertname":"ClusterProvisioningDelay","managed_notification_template":"ClusterProvisioningDelay","namespace":"openshift-monitoring","severity":"warning"},"annotations":{"summary":"Cluster provisioning is delayed","description":"Cluster 1a2b3c4d has been provisioning for more than 1 hour"},"startsAt":"2026-07-14T10:30:00.000Z","endsAt":"0001-01-01T00:00:00Z"}]`,
		"link":         "https://github.com/openshift/runbooks/blob/master/alerts/ClusterProvisioningDelay.md",
		"num_firing":   "1",
		"num_resolved": "0",
		"ocm_link":     "https://cloud.redhat.com/openshift/details/1a2b3c4d",
		"region":       "us-east-1",
		"dashboard":    "https://grafana.example.com/d/abc123",
		"notes":        "cluster_id: 1a2b3c4d-5e6f-7890-abcd-ef1234567890",
	}

	payloadData := buildInvestigationPayload(details, "https://redhat.pagerduty.com/incidents/PABCDEF")

	firingAlerts, ok := payloadData["firing_alerts"].([]FiringAlert)
	if !ok {
		t.Fatal("Expected firing_alerts from realistic PD JSON")
	}
	if len(firingAlerts) != 1 {
		t.Fatalf("Expected 1 firing alert, got %d", len(firingAlerts))
	}
	if firingAlerts[0].Labels["alertname"] != "ClusterProvisioningDelay" {
		t.Errorf("Expected alertname ClusterProvisioningDelay, got %s", firingAlerts[0].Labels["alertname"])
	}
	if firingAlerts[0].Labels["severity"] != "warning" {
		t.Errorf("Expected severity warning, got %s", firingAlerts[0].Labels["severity"])
	}
	if firingAlerts[0].Annotations["summary"] != "Cluster provisioning is delayed" {
		t.Errorf("Expected summary annotation, got %s", firingAlerts[0].Annotations["summary"])
	}
	if firingAlerts[0].StartsAt != "2026-07-14T10:30:00.000Z" {
		t.Errorf("Expected startsAt, got %s", firingAlerts[0].StartsAt)
	}

	alertDetails := payloadData["alert_details"].(map[string]interface{})
	expectedFields := []string{"link", "num_firing", "num_resolved", "ocm_link", "region", "dashboard"}
	for _, field := range expectedFields {
		if _, ok := alertDetails[field]; !ok {
			t.Errorf("Expected %s in alert_details", field)
		}
	}
	if _, ok := alertDetails["notes"]; ok {
		t.Error("notes should not be in alert_details (not in allow-list)")
	}
	if _, ok := alertDetails["cluster_id"]; ok {
		t.Error("cluster_id should not be in alert_details (not in allow-list)")
	}
}

func TestPayloadNilDetails(t *testing.T) {
	payloadData := buildInvestigationPayload(nil, "https://redhat.pagerduty.com/incidents/PNIL123")

	if payloadData["incident_url"] != "https://redhat.pagerduty.com/incidents/PNIL123" {
		t.Errorf("Expected incident_url even with nil details, got %v", payloadData["incident_url"])
	}

	if _, ok := payloadData["firing_alerts"]; ok {
		t.Error("firing_alerts should not be present with nil details")
	}
	if _, ok := payloadData["alert_details"]; ok {
		t.Error("alert_details should not be present with nil details")
	}
}

func mustMarshal(v interface{}) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(b)
}

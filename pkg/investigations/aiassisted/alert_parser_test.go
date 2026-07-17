package aiassisted

import (
	"testing"

	"github.com/openshift/configuration-anomaly-detection/pkg/pagerduty"
)

func TestPayloadStructure(t *testing.T) {
	firingResult := &pagerduty.FiringAlertsResult{
		Alerts: []pagerduty.FiringAlert{
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
		},
	}

	details := &pagerduty.AlertCustomDetails{
		Link:      "https://github.com/openshift/runbooks/blob/master/alerts/cluster-monitoring-operator/KubePersistentVolumeFillingUp.md",
		NumFiring: "2",
		Region:    "us-west-2",
	}

	payloadData := buildInvestigationPayload(firingResult, details, "https://redhat.pagerduty.com/incidents/Q3OFA2AM9FYDAB")

	if payloadData["incident_url"] != "https://redhat.pagerduty.com/incidents/Q3OFA2AM9FYDAB" {
		t.Errorf("Expected incident_url, got %v", payloadData["incident_url"])
	}

	firingAlerts, ok := payloadData["firing_alerts"].([]pagerduty.FiringAlert)
	if !ok {
		t.Fatal("Expected firing_alerts in payload")
	}
	if len(firingAlerts) != 2 {
		t.Errorf("Expected 2 firing alerts, got %d", len(firingAlerts))
	}
	if firingAlerts[1].Labels["persistentvolumeclaim"] != "prometheus-data-prometheus-k8s-1" {
		t.Errorf("Expected second alert's PVC, got %s", firingAlerts[1].Labels["persistentvolumeclaim"])
	}

	alertDetails, ok := payloadData["alert_details"].(map[string]interface{})
	if !ok {
		t.Fatal("Expected alert_details in payload")
	}
	if alertDetails["link"] != details.Link {
		t.Errorf("Expected link %q, got %v", details.Link, alertDetails["link"])
	}
	if alertDetails["num_firing"] != details.NumFiring {
		t.Errorf("Expected num_firing %q, got %v", details.NumFiring, alertDetails["num_firing"])
	}
	if alertDetails["region"] != details.Region {
		t.Errorf("Expected region %q, got %v", details.Region, alertDetails["region"])
	}

	if _, ok := payloadData["firing_alerts_partial"]; ok {
		t.Error("firing_alerts_partial should not be present when all alerts parse")
	}
}

func TestPayloadMultiplePDAlerts(t *testing.T) {
	firingResult := &pagerduty.FiringAlertsResult{
		Alerts: []pagerduty.FiringAlert{
			{Labels: map[string]string{"alertname": "Alert1", "severity": "critical"}, StartsAt: "2026-07-14T10:00:00Z"},
			{Labels: map[string]string{"alertname": "Alert2", "severity": "warning"}, StartsAt: "2026-07-14T10:05:00Z"},
			{Labels: map[string]string{"alertname": "Alert3", "severity": "critical"}, StartsAt: "2026-07-14T10:10:00Z"},
		},
	}

	details := &pagerduty.AlertCustomDetails{
		Link:      "https://example.com/runbook1",
		NumFiring: "3",
		Region:    "us-east-1",
	}

	payloadData := buildInvestigationPayload(firingResult, details, "https://redhat.pagerduty.com/incidents/PMULTI")

	firingAlerts, ok := payloadData["firing_alerts"].([]pagerduty.FiringAlert)
	if !ok {
		t.Fatal("Expected firing_alerts in payload")
	}
	if len(firingAlerts) != 3 {
		t.Fatalf("Expected 3 merged firing alerts, got %d", len(firingAlerts))
	}
	if firingAlerts[0].Labels["alertname"] != "Alert1" {
		t.Errorf("Expected Alert1, got %s", firingAlerts[0].Labels["alertname"])
	}
	if firingAlerts[2].Labels["alertname"] != "Alert3" {
		t.Errorf("Expected Alert3, got %s", firingAlerts[2].Labels["alertname"])
	}

	if _, ok := payloadData["firing_alerts_partial"]; ok {
		t.Error("firing_alerts_partial should not be present when all alerts parse")
	}

	alertDetails := payloadData["alert_details"].(map[string]interface{})
	if alertDetails["link"] != "https://example.com/runbook1" {
		t.Errorf("Expected alert_details link, got %v", alertDetails["link"])
	}
}

func TestPayloadPartialFailure(t *testing.T) {
	firingResult := &pagerduty.FiringAlertsResult{
		Alerts: []pagerduty.FiringAlert{
			{Labels: map[string]string{"alertname": "Alert1", "severity": "critical"}, StartsAt: "2026-07-14T10:00:00Z"},
		},
		RawFallbacks: []string{"not valid json {{"},
		Partial:      true,
	}

	details := &pagerduty.AlertCustomDetails{
		Link:      "https://example.com/runbook",
		NumFiring: "2",
	}

	payloadData := buildInvestigationPayload(firingResult, details, "https://redhat.pagerduty.com/incidents/PPARTIAL")

	firingAlerts, ok := payloadData["firing_alerts"].([]pagerduty.FiringAlert)
	if !ok {
		t.Fatal("Expected firing_alerts for the alert that parsed")
	}
	if len(firingAlerts) != 1 {
		t.Errorf("Expected 1 firing alert from successful parse, got %d", len(firingAlerts))
	}

	rawFallbacks, ok := payloadData["firing_json_raw"].([]string)
	if !ok {
		t.Fatal("Expected firing_json_raw as []string for failed parse")
	}
	if len(rawFallbacks) != 1 {
		t.Errorf("Expected 1 raw fallback, got %d", len(rawFallbacks))
	}

	partial, ok := payloadData["firing_alerts_partial"].(bool)
	if !ok || !partial {
		t.Error("Expected firing_alerts_partial=true when some alerts fail to parse")
	}
}

func TestPayloadFallbackRawJSON(t *testing.T) {
	invalidJSON := "not valid json {{"

	firingResult := &pagerduty.FiringAlertsResult{
		RawFallbacks: []string{invalidJSON},
	}

	payloadData := buildInvestigationPayload(firingResult, nil, "https://redhat.pagerduty.com/incidents/TEST123")

	if _, hasFiring := payloadData["firing_alerts"]; hasFiring {
		t.Error("firing_alerts should not be present when all parsing fails")
	}

	rawFallbacks, ok := payloadData["firing_json_raw"].([]string)
	if !ok {
		t.Fatal("Expected firing_json_raw as []string when parsing fails")
	}
	if len(rawFallbacks) != 1 || rawFallbacks[0] != invalidJSON {
		t.Errorf("Expected raw fallback %q, got %v", invalidJSON, rawFallbacks)
	}

	if _, ok := payloadData["firing_alerts_partial"]; ok {
		t.Error("firing_alerts_partial should not be present when no alerts parsed")
	}
}

func TestPayloadWithRealisticPDJSON(t *testing.T) {
	firingResult := &pagerduty.FiringAlertsResult{
		Alerts: []pagerduty.FiringAlert{
			{
				Labels: map[string]string{
					"alertname":                     "ClusterProvisioningDelay",
					"managed_notification_template": "ClusterProvisioningDelay",
					"namespace":                     "openshift-monitoring",
					"severity":                      "warning",
				},
				Annotations: map[string]string{
					"summary":     "Cluster provisioning is delayed",
					"description": "Cluster 1a2b3c4d has been provisioning for more than 1 hour",
				},
				StartsAt: "2026-07-14T10:30:00.000Z",
				EndsAt:   "0001-01-01T00:00:00Z",
			},
		},
	}

	details := &pagerduty.AlertCustomDetails{
		Link:        "https://github.com/openshift/runbooks/blob/master/alerts/ClusterProvisioningDelay.md",
		NumFiring:   "1",
		NumResolved: "0",
		OCMLink:     "https://cloud.redhat.com/openshift/details/1a2b3c4d",
		Region:      "us-east-1",
		Dashboard:   "https://grafana.example.com/d/abc123",
	}

	payloadData := buildInvestigationPayload(firingResult, details, "https://redhat.pagerduty.com/incidents/PABCDEF")

	firingAlerts, ok := payloadData["firing_alerts"].([]pagerduty.FiringAlert)
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
}

func TestPayloadNilInputs(t *testing.T) {
	payloadData := buildInvestigationPayload(nil, nil, "https://redhat.pagerduty.com/incidents/PNIL123")

	if payloadData["incident_url"] != "https://redhat.pagerduty.com/incidents/PNIL123" {
		t.Errorf("Expected incident_url even with nil inputs, got %v", payloadData["incident_url"])
	}

	if _, ok := payloadData["firing_alerts"]; ok {
		t.Error("firing_alerts should not be present with nil inputs")
	}
	if _, ok := payloadData["alert_details"]; ok {
		t.Error("alert_details should not be present with nil inputs")
	}
}

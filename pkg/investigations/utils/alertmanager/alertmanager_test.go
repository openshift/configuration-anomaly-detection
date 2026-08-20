package alertmanager

import (
	"encoding/json"
	"testing"
)

func TestAlertmanagerAlertParsing(t *testing.T) {
	rawJSON := `[
		{
			"labels": {"alertname": "HighMemory", "severity": "critical"},
			"annotations": {"summary": "Memory usage is above 90%"},
			"status": {"state": "firing"}
		},
		{
			"labels": {"alertname": "Watchdog", "severity": "none"},
			"annotations": {},
			"status": {"state": "active"}
		},
		{
			"labels": {"alertname": "DiskPressure", "severity": "warning"},
			"annotations": {"summary": "Disk is filling up"},
			"status": {"state": "suppressed"}
		}
	]`

	var amAlerts []alertmanagerAlert
	if err := json.Unmarshal([]byte(rawJSON), &amAlerts); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if len(amAlerts) != 3 {
		t.Fatalf("expected 3 alerts, got %d", len(amAlerts))
	}

	// Only "firing" and "active" states should be returned by the filtering logic
	var firing []FiringAlert
	for _, a := range amAlerts {
		if a.Status.State == "active" || a.Status.State == "firing" {
			firing = append(firing, FiringAlert{
				Name:     a.Labels["alertname"],
				Severity: a.Labels["severity"],
				State:    a.Status.State,
				Summary:  a.Annotations["summary"],
			})
		}
	}

	if len(firing) != 2 {
		t.Fatalf("expected 2 firing alerts, got %d", len(firing))
	}
	if firing[0].Name != "HighMemory" {
		t.Errorf("expected first alert to be HighMemory, got %s", firing[0].Name)
	}
	if firing[1].Name != "Watchdog" {
		t.Errorf("expected second alert to be Watchdog, got %s", firing[1].Name)
	}
}

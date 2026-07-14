package aiassisted

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
	"github.com/openshift/configuration-anomaly-detection/pkg/pagerduty"
)

var (
	errNoAlertBody    = errors.New("alert body is nil")
	errNoAlertDetails = errors.New("alert body has no details field")
)

// FiringAlert represents a single firing alert from the firing_json PagerDuty detail field.
type FiringAlert struct {
	Labels      map[string]string `json:"labels"`
	Annotations map[string]string `json:"annotations"`
	StartsAt    string            `json:"startsAt"`
	EndsAt      string            `json:"endsAt"`
}

// parseFiringJSON parses the firing_json detail field into structured alerts.
func parseFiringJSON(firingJSON string) ([]FiringAlert, error) {
	if firingJSON == "" {
		return []FiringAlert{}, nil
	}

	var alerts []FiringAlert
	if err := json.Unmarshal([]byte(firingJSON), &alerts); err != nil {
		return nil, fmt.Errorf("failed to parse firing_json: %w", err)
	}

	return alerts, nil
}

// extractAlertDetails gets the custom details map from the first PD alert's Body["details"].
func extractAlertDetails(pdClient *pagerduty.SdkClient) (map[string]interface{}, error) {
	incidentID := pdClient.GetIncidentID()
	alerts, err := pdClient.GetAlertsForIncident(incidentID)
	if err != nil {
		return nil, fmt.Errorf("failed to get alerts for incident: %w", err)
	}

	if alerts == nil || len(*alerts) == 0 {
		return nil, fmt.Errorf("no alerts found for incident %s", incidentID)
	}

	alert := (*alerts)[0]
	if alert.Body == nil {
		return nil, errNoAlertBody
	}

	details, ok := alert.Body["details"].(map[string]interface{})
	if !ok {
		return nil, errNoAlertDetails
	}

	return details, nil
}

// buildInvestigationPayload constructs the investigation payload from alert details.
func buildInvestigationPayload(details map[string]interface{}, incidentURL string) map[string]interface{} {
	payloadData := make(map[string]interface{})

	payloadData["incident_url"] = incidentURL

	if details == nil {
		return payloadData
	}

	if firingJSON, ok := details["firing_json"].(string); ok && firingJSON != "" {
		firingAlerts, err := parseFiringJSON(firingJSON)
		if err != nil {
			logging.Warnf("firing_json could not be parsed — sending raw string as fallback: %v", err)
			payloadData["firing_json_raw"] = firingJSON
		} else if len(firingAlerts) > 0 {
			payloadData["firing_alerts"] = firingAlerts
			logging.Infof("Extracted %d firing alert(s) from firing_json for AI investigation", len(firingAlerts))
		}
	}

	filteredDetails := make(map[string]interface{})
	allowedFields := []string{
		"link",
		"num_firing",
		"num_resolved",
		"ocm_link",
		"region",
		"dashboard",
	}
	for _, field := range allowedFields {
		if value, ok := details[field]; ok {
			filteredDetails[field] = value
		}
	}
	if len(filteredDetails) > 0 {
		payloadData["alert_details"] = filteredDetails
	}

	return payloadData
}

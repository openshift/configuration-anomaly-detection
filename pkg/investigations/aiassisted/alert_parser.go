package aiassisted

import (
	"github.com/openshift/configuration-anomaly-detection/pkg/pagerduty"
)

func buildInvestigationPayload(firingResult *pagerduty.FiringAlertsResult, details *pagerduty.AlertCustomDetails, incidentURL string) map[string]interface{} {
	payloadData := make(map[string]interface{})

	payloadData["incident_url"] = incidentURL

	if firingResult != nil {
		if len(firingResult.Alerts) > 0 {
			payloadData["firing_alerts"] = firingResult.Alerts
		}
		if len(firingResult.RawFallbacks) > 0 {
			payloadData["firing_json_raw"] = firingResult.RawFallbacks
		}
		if firingResult.Partial {
			payloadData["firing_alerts_partial"] = true
		}
	}

	if details == nil {
		return payloadData
	}

	alertDetails := make(map[string]interface{})
	if details.Link != "" {
		alertDetails["link"] = details.Link
	}
	if details.NumFiring != "" {
		alertDetails["num_firing"] = details.NumFiring
	}
	if details.NumResolved != "" {
		alertDetails["num_resolved"] = details.NumResolved
	}
	if details.OCMLink != "" {
		alertDetails["ocm_link"] = details.OCMLink
	}
	if details.Region != "" {
		alertDetails["region"] = details.Region
	}
	if details.Dashboard != "" {
		alertDetails["dashboard"] = details.Dashboard
	}
	if len(alertDetails) > 0 {
		payloadData["alert_details"] = alertDetails
	}

	return payloadData
}

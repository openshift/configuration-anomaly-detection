package pagerduty

import (
	"context"

	sdk "github.com/PagerDuty/go-pagerduty"
	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
)

// EscalationSkippedError means no escalation update was sent. Callers must not
// interpret a skip as a successful CAD escalation. PagerDuty's timer is the backstop.
type EscalationSkippedError struct{ Reason string }

// Error describes why no escalation update was sent.
func (e *EscalationSkippedError) Error() string { return "escalation skipped: " + e.Reason }

// skipEscalation logs a fixed reason without SDK response text or identifiers.
func skipEscalation(reason string) error {
	logging.Warnf("Skipping PagerDuty escalation; leaving automatic escalation in control: %s", reason)
	return &EscalationSkippedError{Reason: reason}
}

// checkEscalationEligibility retains CAD's existing policy assumption: incidents
// start at level 1 and CAD escalates to level 2. It does not validate policy layout.
// History supplies evidence of prior escalation; assignments alone do not.
// This is NOT atomic with the subsequent PUT: PagerDuty documents no applicable
// conditional update, so external actions can still race this best-effort guard.
func (c *SdkClient) checkEscalationEligibility(ctx context.Context) error {
	id := c.GetIncidentID()
	// Read the complete history, not just the overview or first page. Unknown
	// events fail closed, including reassignment and escalation-path restarts.
	foundTrigger := false
	complete := false
	for offset := uint(0); offset < 10000; {
		page, err := c.sdkClient.ListIncidentLogEntriesWithContext(ctx, id, sdk.ListIncidentLogEntriesOptions{Limit: 100, Offset: offset})
		if err != nil {
			return skipEscalation("incident history lookup failed")
		}
		if page == nil {
			return skipEscalation("missing incident history")
		}
		for _, entry := range page.LogEntries {
			switch entry.Type {
			case "trigger_log_entry":
				foundTrigger = true
			case "notify_log_entry", "annotate_log_entry":
			default:
				return skipEscalation("prior handling or ambiguous history event")
			}
		}
		if !page.More {
			complete = true
			break
		}
		if len(page.LogEntries) == 0 {
			return skipEscalation("incomplete history pagination")
		}
		offset += uint(len(page.LogEntries))
	}
	if !complete || !foundTrigger {
		return skipEscalation("complete initial-trigger history unavailable")
	}
	// This final fresh read is immediately before the update. Do not use the
	// webhook snapshot as the final status guard.
	incident, err := c.sdkClient.GetIncidentWithContext(ctx, id)
	if err != nil {
		return skipEscalation("incident status lookup failed")
	}
	if incident == nil || incident.Status != "triggered" || len(incident.Acknowledgements) != 0 {
		return skipEscalation("incident is not confirmed triggered and unacknowledged")
	}
	return nil
}

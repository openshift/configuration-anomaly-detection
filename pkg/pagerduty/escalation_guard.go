package pagerduty

import (
	"context"
	"strings"

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
	// Read complete history, not just the overview or newest page. Deny positive
	// evidence of responder handling rather than requiring an idealized history.
	cadUsers := map[string]bool{} // Per attempt only; do not cache identity across runs.
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
			case "escalate_log_entry", "acknowledge_log_entry", "resolve_log_entry", "unacknowledge_log_entry":
				return skipEscalation("prior responder handling")
			case "assign_log_entry", "delegate_log_entry":
				if err := c.checkRoutingEntry(ctx, entry, cadUsers); err != nil {
					return err
				}
			default:
				// Other events, including grouping, urgency changes, and unknown
				// future types, are not evidence of handling under this denylist.
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

// checkRoutingEntry distinguishes CAD policy routing from user intervention.
// Automatic/non-user assignments are normal at trigger time and after policy
// delegation. Timer escalation is detected by its separate escalate event.
// Missing/non-user actors are not positive evidence of manual reassignment;
// this is deliberately a denylist, not proof of exclusive CAD ownership.
func (c *SdkClient) checkRoutingEntry(ctx context.Context, entry sdk.LogEntry, cadUsers map[string]bool) error {
	if !isUserReference(entry.Agent.Type) {
		return nil
	}
	cad, err := c.isCADUser(ctx, entry.Agent.ID, cadUsers)
	if err != nil {
		return err
	}
	if cad {
		// updateIncident always uses CADEmailAddress, including silent-policy
		// moves and organization routing. Their target need not be the CAD user.
		return nil
	}
	if entry.Type == "delegate_log_entry" || len(entry.Assignees) == 0 {
		return skipEscalation("non-CAD user changed incident routing")
	}
	for _, target := range entry.Assignees {
		if !isUserReference(target.Type) {
			return skipEscalation("non-CAD user changed incident routing")
		}
		cad, err := c.isCADUser(ctx, target.ID, cadUsers)
		if err != nil {
			return err
		}
		if !cad {
			return skipEscalation("reassigned to a non-CAD target")
		}
	}
	return nil
}

func isUserReference(kind string) bool {
	return kind == "user" || kind == "user_reference"
}

func (c *SdkClient) isCADUser(ctx context.Context, id string, cache map[string]bool) (bool, error) {
	if id == "" {
		return false, skipEscalation("routing user identity missing")
	}
	if cad, ok := cache[id]; ok {
		return cad, nil
	}
	user, err := c.sdkClient.GetUserWithContext(ctx, id, sdk.GetUserOptions{})
	if err != nil || user == nil || user.Email == "" {
		return false, skipEscalation("routing user lookup failed")
	}
	cad := strings.EqualFold(user.Email, CADEmailAddress)
	cache[id] = cad
	return cad, nil
}

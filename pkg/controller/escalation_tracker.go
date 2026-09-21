package controller

import (
	"sync"

	"github.com/openshift/configuration-anomaly-detection/pkg/pagerduty"
)

// trackingPDClient wraps a pagerduty.Client and de-duplicates escalations at
// the source: EscalateIncident/EscalateIncidentWithNote only ever reach the
// real client once per incident, no matter how many callers (an
// investigation's direct call, an investigation's action via the executor,
// or the controller's own fallback/failure-handling logic) try to escalate.
// A single instance is shared across all of those paths (via
// incidentNotifier.AttachToBuilder and the executor construction), so the
// guard applies regardless of which caller gets there first. The mutex makes
// this correct even if a future change parallelizes PagerDuty action
// execution or investigation runs, which are currently sequential but not
// guaranteed to stay that way.
type trackingPDClient struct {
	pagerduty.Client
	mu        sync.Mutex
	escalated bool
}

func newTrackingPDClient(client pagerduty.Client) *trackingPDClient {
	return &trackingPDClient{Client: client}
}

func (t *trackingPDClient) EscalateIncident() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.escalated {
		return nil
	}
	if err := t.Client.EscalateIncident(); err != nil {
		return err
	}
	t.escalated = true
	return nil
}

// EscalateIncidentWithNote degrades to a plain note if the incident was
// already escalated, so the note's content isn't lost even though the
// (already-happened) escalation itself isn't repeated.
func (t *trackingPDClient) EscalateIncidentWithNote(note string) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.escalated {
		return t.AddNote(note)
	}
	if err := t.Client.EscalateIncidentWithNote(note); err != nil {
		return err
	}
	t.escalated = true
	return nil
}

// HasEscalated reports whether this incident has already been escalated,
// through any path (investigation action, direct call, or note-attached
// escalation).
func (t *trackingPDClient) HasEscalated() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.escalated
}

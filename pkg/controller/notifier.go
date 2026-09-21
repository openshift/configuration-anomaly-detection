package controller

import (
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/investigation"
	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
)

// incidentNotifier abstracts PagerDuty incident operations so that
// manual (non-PD) runs use a no-op implementation instead of
// nil-checking a *trackingPDClient.
type incidentNotifier interface {
	AddNote(note string) error
	Escalate() error
	EscalateWithNote(note string) error
	AttachToBuilder(builder investigation.ResourceBuilder)
	HasPagerDuty() bool
}

// pdIncidentNotifier wraps a real PagerDuty client.
type pdIncidentNotifier struct {
	client *trackingPDClient
}

func newPDIncidentNotifier(client *trackingPDClient) incidentNotifier {
	return &pdIncidentNotifier{client: client}
}

func (n *pdIncidentNotifier) AddNote(note string) error {
	return n.client.AddNote(note)
}

func (n *pdIncidentNotifier) Escalate() error {
	return n.client.EscalateIncident()
}

func (n *pdIncidentNotifier) EscalateWithNote(note string) error {
	return n.client.EscalateIncidentWithNote(note)
}

func (n *pdIncidentNotifier) AttachToBuilder(builder investigation.ResourceBuilder) {
	builder.WithPdClient(n.client)
}

func (n *pdIncidentNotifier) HasPagerDuty() bool {
	return true
}

// noopIncidentNotifier is used by ManualController where no PagerDuty client exists.
type noopIncidentNotifier struct{}

func newNoopIncidentNotifier() incidentNotifier {
	return &noopIncidentNotifier{}
}

func (n *noopIncidentNotifier) AddNote(note string) error {
	logging.Infof("Skipping PD note (manual mode): %s", note)
	return nil
}

func (n *noopIncidentNotifier) Escalate() error {
	logging.Infof("Skipping PD escalation (manual mode)")
	return nil
}

func (n *noopIncidentNotifier) EscalateWithNote(note string) error {
	logging.Infof("Skipping PD escalation (manual mode): %s", note)
	return nil
}

func (n *noopIncidentNotifier) AttachToBuilder(_ investigation.ResourceBuilder) {}

func (n *noopIncidentNotifier) HasPagerDuty() bool {
	return false
}

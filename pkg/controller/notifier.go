package controller

import (
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/investigation"
	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
	"github.com/openshift/configuration-anomaly-detection/pkg/pagerduty"
)

// incidentNotifier abstracts PagerDuty incident operations so that
// manual (non-PD) runs use a no-op implementation instead of
// nil-checking a *pagerduty.SdkClient.
type incidentNotifier interface {
	EscalateWithNote(note string) error
	AttachToBuilder(builder investigation.ResourceBuilder)
	IsActive() bool
}

// pdIncidentNotifier wraps a real PagerDuty client.
type pdIncidentNotifier struct {
	client *pagerduty.SdkClient
}

func newPDIncidentNotifier(client *pagerduty.SdkClient) incidentNotifier {
	return &pdIncidentNotifier{client: client}
}

func (n *pdIncidentNotifier) EscalateWithNote(note string) error {
	return n.client.EscalateIncidentWithNote(note)
}

func (n *pdIncidentNotifier) AttachToBuilder(builder investigation.ResourceBuilder) {
	builder.WithPdClient(n.client)
}

func (n *pdIncidentNotifier) IsActive() bool {
	return true
}

// noopIncidentNotifier is used by ManualController where no PagerDuty client exists.
type noopIncidentNotifier struct{}

func newNoopIncidentNotifier() incidentNotifier {
	return &noopIncidentNotifier{}
}

func (n *noopIncidentNotifier) EscalateWithNote(note string) error {
	logging.Infof("Skipping PD escalation (manual mode)")
	return nil
}

func (n *noopIncidentNotifier) AttachToBuilder(_ investigation.ResourceBuilder) {}

func (n *noopIncidentNotifier) IsActive() bool {
	return false
}

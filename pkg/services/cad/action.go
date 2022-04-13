package cad

import (
	"fmt"
)

//go:generate mockgen -destination mock/pagerduty.go -package $GOPACKAGE github.com/openshift/configuration-anomaly-detection/pkg/cad PagerDuty

// PagerDuty provides an interface for mockups for PagerDuty specific functions
type PagerDuty interface {
	AddNote(incidentID string, noteContent string) error
	MoveToEscalationPolicy(incidentID string, escalationPolicyID string) error
}

var defaultEscalationPolicy = "Openshift Escalation Policy"
var silenceEscalationPolicy = "Silent Test"

// EscalateAlert will ensure that an incident informs a SRE.
// Optionally notes can be added to the incident
func EscalateAlert(pd PagerDuty, incidentID, notes string) error {
	return updatePagerduty(pd, incidentID, notes, defaultEscalationPolicy)
}

// SilenceAlert annotates the PagerDuty alert with the given notes and silences it via
// assigning the "Silent Test" escalation policy
func SilenceAlert(pd PagerDuty, incidentID, notes string) error {
	return updatePagerduty(pd, incidentID, notes, silenceEscalationPolicy)
}

// updatePagerduty attaches notes to an incident and moves it to a escalation policy
func updatePagerduty(pd PagerDuty, incidentID, notes, escalationPolicy string) error {
	if notes != "" {
		err := pd.AddNote(incidentID, notes) // notes == service log
		if err != nil {
			return fmt.Errorf("failed to attach notes to incident: %w", err)
		}
	}

	err := pd.MoveToEscalationPolicy(incidentID, escalationPolicy)
	if err != nil {
		return fmt.Errorf("failed to change incident escalation policy: %w", err)
	}
	return nil
}

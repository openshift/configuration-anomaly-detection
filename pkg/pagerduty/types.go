package pagerduty

// Incident represents a PagerDuty Incident
type Incident struct {
	// ID is the unique ID of the Incident
	ID string
	// EscalationPolicy is the Incident's EscalationPolicy
	EscalationPolicy EscalationPolicy
}

// EscalationPolicy represents a PagerDuty Escalation Policy
type EscalationPolicy struct {
	// ID is the unique ID of the EscalationPolicy
	ID string
}

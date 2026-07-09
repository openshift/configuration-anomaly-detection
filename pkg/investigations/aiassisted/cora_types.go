package aiassisted

import "time"

// CoraInvestigationResult represents the structured JSON output from the Cora agent
type CoraInvestigationResult struct {
	InvestigationID  string            `json:"investigation_id"`
	ClusterID        string            `json:"cluster_id"`
	AlertName        string            `json:"alert_name"`
	Timestamp        time.Time         `json:"timestamp"`
	DurationSeconds  float64           `json:"duration_seconds"`
	Summary          string            `json:"summary"`
	Confidence       string            `json:"confidence"`
	Reasoning        string            `json:"reasoning"`
	Evidence         string            `json:"evidence"`
	RemediationSteps []RemediationStep `json:"remediation_steps"`
	NeedsEscalation  bool              `json:"needs_escalation"`
	EscalationReason *string           `json:"escalation_reason"` // Pointer to handle null values
}

// RemediationStep represents a single remediation action
type RemediationStep struct {
	Action  string  `json:"action"`
	Command *string `json:"command"` // Pointer to handle null values
}

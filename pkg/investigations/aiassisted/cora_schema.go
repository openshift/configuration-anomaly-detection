package aiassisted

import "time"

// CoraInvestigationResult represents the structured JSON output from the Cora agent
type CoraInvestigationResult struct {
	InvestigationID string    `json:"investigation_id"`
	ClusterID       string    `json:"cluster_id"`
	AlertName       string    `json:"alert_name"`
	Timestamp       time.Time `json:"timestamp"`
	DurationSeconds float64   `json:"duration_seconds"`
	Status          string    `json:"status"`
	RootCause       RootCause `json:"root_cause"`
	Remediation     Remediation `json:"remediation"`
	Evidence        []Evidence  `json:"evidence"`
	Escalation      Escalation  `json:"escalation"`
}

// RootCause contains the root cause analysis
type RootCause struct {
	Summary         string  `json:"summary"`
	Category        string  `json:"category"`
	Confidence      string  `json:"confidence"`
	ConfidenceScore float64 `json:"confidence_score"`
	Reasoning       string  `json:"reasoning"`
}

// Remediation contains the remediation plan
type Remediation struct {
	Steps             []RemediationStep `json:"steps"`
	RequiresElevation bool              `json:"requires_elevation"`
	EstimatedImpact   string            `json:"estimated_impact"`
	AutomationReady   bool              `json:"automation_ready"`
}

// RemediationStep represents a single remediation action
type RemediationStep struct {
	Action            string  `json:"action"`
	Command           *string `json:"command"` // Pointer to handle null values
	RiskLevel         string  `json:"risk_level"`
	RequiresElevation bool    `json:"requires_elevation"`
}

// Evidence contains diagnostic evidence from the investigation
type Evidence struct {
	Command         string `json:"command"`
	Output          string `json:"output"`
	OutputTruncated bool   `json:"output_truncated"`
	Analysis        string `json:"analysis"`
	Relevance       string `json:"relevance"`
}

// Escalation contains escalation routing metadata
type Escalation struct {
	Recommended bool    `json:"recommended"`
	Reason      string  `json:"reason"`
	Urgency     string  `json:"urgency"`
	TargetTeam  *string `json:"target_team"` // Pointer to handle null values
}

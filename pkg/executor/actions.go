// Package reporter provides external system update functionality for investigation results
package executor

import (
	"context"
	"fmt"
	"strings"

	"github.com/openshift/configuration-anomaly-detection/pkg/ocm"
	"github.com/openshift/configuration-anomaly-detection/pkg/types"
)

// Action is the types.Action interface - all reporter actions implement it
type Action = types.Action

// ExecutionContext is the types.ExecutionContext - aliased for convenience
type ExecutionContext = types.ExecutionContext

// ActionType identifies the kind of action
type ActionType string

const (
	ActionTypeServiceLog       ActionType = "service_log"
	ActionTypeLimitedSupport   ActionType = "limited_support"
	ActionTypePagerDutyNote    ActionType = "pagerduty_note"
	ActionTypeSilenceIncident  ActionType = "silence_incident"
	ActionTypeEscalateIncident ActionType = "escalate_incident"
	ActionTypeBackplaneReport  ActionType = "backplane_report"
)

// ServiceLogAction sends a service log via OCM
type ServiceLogAction struct {
	// ServiceLog to send
	ServiceLog *ocm.ServiceLog

	// Reason explains why this service log is being sent (for logging/metrics)
	Reason string

	// AllowDuplicates permits sending even if identical SL exists
	AllowDuplicates bool
}

func (a *ServiceLogAction) Type() string {
	return string(ActionTypeServiceLog)
}

func (a *ServiceLogAction) ActionType() ActionType {
	return ActionTypeServiceLog
}

func (a *ServiceLogAction) Validate() error {
	if a.ServiceLog == nil {
		return fmt.Errorf("ServiceLog cannot be nil")
	}
	if a.ServiceLog.Summary == "" {
		return fmt.Errorf("ServiceLog.Summary is required")
	}
	if a.ServiceLog.Severity == "" {
		return fmt.Errorf("ServiceLog.Severity is required")
	}
	return nil
}

func (a *ServiceLogAction) Execute(ctx context.Context, execCtx *ExecutionContext) error {
	if execCtx.Cluster == nil {
		return fmt.Errorf("cluster required for ServiceLog action")
	}

	execCtx.Logger.Infof("Sending service log: %s (reason: %s)",
		a.ServiceLog.Summary, a.Reason)

	// Optional: Check for duplicates
	if !a.AllowDuplicates {
		existing, err := execCtx.OCMClient.GetServiceLog(execCtx.Cluster,
			fmt.Sprintf("summary='%s'", a.ServiceLog.Summary))
		if err == nil && existing.Total() > 0 {
			execCtx.Logger.Infof("Skipping duplicate service log: %s", a.ServiceLog.Summary)
			return nil
		}
	}

	return execCtx.OCMClient.PostServiceLog(execCtx.Cluster, a.ServiceLog)
}

// LimitedSupportAction sets a cluster into limited support
type LimitedSupportAction struct {
	// Reason for limited support
	Reason *ocm.LimitedSupportReason

	// Context provides additional info for logging/metrics
	Context string

	// AllowDuplicates permits setting even if identical LS exists
	AllowDuplicates bool
}

func (a *LimitedSupportAction) Type() string {
	return string(ActionTypeLimitedSupport)
}

func (a *LimitedSupportAction) ActionType() ActionType {
	return ActionTypeLimitedSupport
}

func (a *LimitedSupportAction) Validate() error {
	if a.Reason == nil {
		return fmt.Errorf("reason cannot be nil")
	}
	if a.Reason.Summary == "" {
		return fmt.Errorf("reason.Summary is required")
	}
	if a.Reason.Details == "" {
		return fmt.Errorf("reason.Details is required")
	}
	return nil
}

func (a *LimitedSupportAction) Execute(ctx context.Context, execCtx *ExecutionContext) error {
	if execCtx.Cluster == nil {
		return fmt.Errorf("cluster required for LimitedSupport action")
	}

	execCtx.Logger.Infof("Setting limited support: %s (context: %s)",
		a.Reason.Summary, a.Context)

	// Note: OCM API handles duplicate checking internally
	return execCtx.OCMClient.PostLimitedSupportReason(execCtx.Cluster, a.Reason)
}

// PagerDutyNoteAction adds a note to the current PagerDuty incident
type PagerDutyNoteAction struct {
	// Content of the note (can be from notewriter.String())
	Content string
}

func (a *PagerDutyNoteAction) Type() string {
	return string(ActionTypePagerDutyNote)
}

func (a *PagerDutyNoteAction) ActionType() ActionType {
	return ActionTypePagerDutyNote
}

func (a *PagerDutyNoteAction) Validate() error {
	if strings.TrimSpace(a.Content) == "" {
		return fmt.Errorf("note content cannot be empty")
	}
	return nil
}

func (a *PagerDutyNoteAction) Execute(ctx context.Context, execCtx *ExecutionContext) error {
	execCtx.Logger.Infof("Adding PagerDuty note (%d chars)", len(a.Content))
	return execCtx.PDClient.AddNote(a.Content)
}

// SilenceIncidentAction silences the current PagerDuty incident
type SilenceIncidentAction struct {
	// Reason explains why we're silencing (for logging)
	Reason string
}

func (a *SilenceIncidentAction) Type() string {
	return string(ActionTypeSilenceIncident)
}

func (a *SilenceIncidentAction) ActionType() ActionType {
	return ActionTypeSilenceIncident
}

func (a *SilenceIncidentAction) Validate() error {
	return nil // No validation needed
}

func (a *SilenceIncidentAction) Execute(ctx context.Context, execCtx *ExecutionContext) error {
	execCtx.Logger.Infof("Silencing incident: %s", a.Reason)
	return execCtx.PDClient.SilenceIncident()
}

// EscalateIncidentAction escalates the current PagerDuty incident
type EscalateIncidentAction struct {
	// Reason explains why we're escalating (for logging)
	Reason string
}

func (a *EscalateIncidentAction) Type() string {
	return string(ActionTypeEscalateIncident)
}

func (a *EscalateIncidentAction) ActionType() ActionType {
	return ActionTypeEscalateIncident
}

func (a *EscalateIncidentAction) Validate() error {
	return nil // No validation needed
}

func (a *EscalateIncidentAction) Execute(ctx context.Context, execCtx *ExecutionContext) error {
	execCtx.Logger.Infof("Escalating incident: %s", a.Reason)
	return execCtx.PDClient.EscalateIncident()
}

// BackplaneReport is the minimal interface for report payloads
type BackplaneReport interface {
	// ToJSON serializes the report
	ToJSON() ([]byte, error)

	// Validate checks if report is valid
	Validate() error
}

// BackplaneReportAction uploads a report to backplane reports API
type BackplaneReportAction struct {
	// Report contains the structured report data
	Report BackplaneReport

	// ReportType identifies the kind of report
	ReportType string
}

func (a *BackplaneReportAction) Type() string {
	return string(ActionTypeBackplaneReport)
}

func (a *BackplaneReportAction) ActionType() ActionType {
	return ActionTypeBackplaneReport
}

func (a *BackplaneReportAction) Validate() error {
	if a.Report == nil {
		return fmt.Errorf("report cannot be nil")
	}
	return a.Report.Validate()
}

func (a *BackplaneReportAction) Execute(ctx context.Context, execCtx *ExecutionContext) error {
	execCtx.Logger.Infof("Uploading backplane report (type: %s)", a.ReportType)

	// Future implementation:
	// return exec.BackplaneClient.UploadReport(ctx, exec.Cluster.ID(), a.Report)

	return fmt.Errorf("backplane reports not yet implemented")
}

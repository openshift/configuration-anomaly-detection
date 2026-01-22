package executor

import (
	"fmt"
	"strings"

	"github.com/openshift/configuration-anomaly-detection/pkg/notewriter"
	"github.com/openshift/configuration-anomaly-detection/pkg/ocm"
)

// ServiceLogActionBuilder builds ServiceLogAction instances
type ServiceLogActionBuilder struct {
	severity        string
	serviceName     string
	summary         string
	description     string
	internalOnly    bool
	reason          string
	allowDuplicates bool
}

// NewServiceLogAction creates a builder with required fields
// severity: "Info", "Warning", "Major", "Critical"
// summary: Brief title of the service log
func NewServiceLogAction(severity, summary string) *ServiceLogActionBuilder {
	return &ServiceLogActionBuilder{
		severity:        severity,
		summary:         summary,
		serviceName:     "SREManualAction", // Default service name
		internalOnly:    false,             // Default to customer-visible
		allowDuplicates: false,             // Default to skip duplicates
	}
}

// WithDescription sets the detailed description
func (b *ServiceLogActionBuilder) WithDescription(description string) *ServiceLogActionBuilder {
	b.description = description
	return b
}

// WithServiceName sets the service name (defaults to "SREManualAction")
func (b *ServiceLogActionBuilder) WithServiceName(name string) *ServiceLogActionBuilder {
	b.serviceName = name
	return b
}

// InternalOnly marks the service log as internal-only (not visible to customer)
func (b *ServiceLogActionBuilder) InternalOnly() *ServiceLogActionBuilder {
	b.internalOnly = true
	return b
}

// WithReason sets the reason for logging purposes
func (b *ServiceLogActionBuilder) WithReason(reason string) *ServiceLogActionBuilder {
	b.reason = reason
	return b
}

// AllowDuplicates permits sending even if identical service log exists
func (b *ServiceLogActionBuilder) AllowDuplicates() *ServiceLogActionBuilder {
	b.allowDuplicates = true
	return b
}

// Build creates the ServiceLogAction
func (b *ServiceLogActionBuilder) Build() Action {
	return &ServiceLogAction{
		ServiceLog: &ocm.ServiceLog{
			Severity:     b.severity,
			ServiceName:  b.serviceName,
			Summary:      b.summary,
			Description:  b.description,
			InternalOnly: b.internalOnly,
		},
		Reason:          b.reason,
		AllowDuplicates: b.allowDuplicates,
	}
}

// LimitedSupportActionBuilder builds LimitedSupportAction instances
type LimitedSupportActionBuilder struct {
	summary         string
	details         string
	context         string
	allowDuplicates bool
}

// NewLimitedSupportAction creates a builder with required fields
// summary: Brief reason for limited support
// details: Detailed explanation including remediation steps
// context: Context string for metrics labeling (e.g., "StoppedInstances", "EgressBlocked")
func NewLimitedSupportAction(summary, details, context string) *LimitedSupportActionBuilder {
	return &LimitedSupportActionBuilder{
		summary:         summary,
		details:         details,
		context:         context,
		allowDuplicates: false, // Default to skip duplicates
	}
}

// AllowDuplicates permits setting even if identical LS exists
func (b *LimitedSupportActionBuilder) AllowDuplicates() *LimitedSupportActionBuilder {
	b.allowDuplicates = true
	return b
}

// Build creates the LimitedSupportAction
func (b *LimitedSupportActionBuilder) Build() Action {
	return &LimitedSupportAction{
		Reason: &ocm.LimitedSupportReason{
			Summary: b.summary,
			Details: b.details,
		},
		Context:         b.context,
		AllowDuplicates: b.allowDuplicates,
	}
}

// PagerDutyNoteActionBuilder builds PagerDutyNoteAction instances
type PagerDutyNoteActionBuilder struct {
	content strings.Builder
}

// NewPagerDutyNoteAction creates a builder
// Can be initialized empty and built up, or with initial content
func NewPagerDutyNoteAction(initialContent ...string) *PagerDutyNoteActionBuilder {
	b := &PagerDutyNoteActionBuilder{}

	if len(initialContent) > 0 {
		b.content.WriteString(initialContent[0])
	}

	return b
}

// WithContent sets the note content (replaces existing)
func (b *PagerDutyNoteActionBuilder) WithContent(content string) *PagerDutyNoteActionBuilder {
	b.content.Reset()
	b.content.WriteString(content)
	return b
}

// AppendLine adds a line to the note
func (b *PagerDutyNoteActionBuilder) AppendLine(line string) *PagerDutyNoteActionBuilder {
	if b.content.Len() > 0 {
		b.content.WriteString("\n")
	}
	b.content.WriteString(line)
	return b
}

// AppendSection adds a section with a header
func (b *PagerDutyNoteActionBuilder) AppendSection(header, content string) *PagerDutyNoteActionBuilder {
	if b.content.Len() > 0 {
		b.content.WriteString("\n\n")
	}
	b.content.WriteString(fmt.Sprintf("## %s\n%s", header, content))
	return b
}

// FromNoteWriter uses a notewriter's content
func (b *PagerDutyNoteActionBuilder) FromNoteWriter(nw *notewriter.NoteWriter) *PagerDutyNoteActionBuilder {
	return b.WithContent(nw.String())
}

// Build creates the PagerDutyNoteAction
func (b *PagerDutyNoteActionBuilder) Build() Action {
	return &PagerDutyNoteAction{
		Content: b.content.String(),
	}
}

// SilenceIncidentActionBuilder builds SilenceIncidentAction instances
type SilenceIncidentActionBuilder struct {
	reason string
}

// NewSilenceIncidentAction creates a builder
func NewSilenceIncidentAction(reason string) *SilenceIncidentActionBuilder {
	return &SilenceIncidentActionBuilder{
		reason: reason,
	}
}

// WithReason sets the reason for silencing
func (b *SilenceIncidentActionBuilder) WithReason(reason string) *SilenceIncidentActionBuilder {
	b.reason = reason
	return b
}

// Build creates the SilenceIncidentAction
func (b *SilenceIncidentActionBuilder) Build() Action {
	return &SilenceIncidentAction{
		Reason: b.reason,
	}
}

// EscalateIncidentActionBuilder builds EscalateIncidentAction instances
type EscalateIncidentActionBuilder struct {
	reason string
}

// NewEscalateIncidentAction creates a builder
func NewEscalateIncidentAction(reason string) *EscalateIncidentActionBuilder {
	return &EscalateIncidentActionBuilder{
		reason: reason,
	}
}

// WithReason sets the reason for escalating
func (b *EscalateIncidentActionBuilder) WithReason(reason string) *EscalateIncidentActionBuilder {
	b.reason = reason
	return b
}

// Build creates the EscalateIncidentAction
func (b *EscalateIncidentActionBuilder) Build() Action {
	return &EscalateIncidentAction{
		Reason: b.reason,
	}
}

// BackplaneReportActionBuilder builds BackplaneReportAction instances
type BackplaneReportActionBuilder struct {
	report     BackplaneReport
	reportType string
}

// NewBackplaneReportAction creates a builder with required fields
func NewBackplaneReportAction(reportType string, report BackplaneReport) *BackplaneReportActionBuilder {
	return &BackplaneReportActionBuilder{
		reportType: reportType,
		report:     report,
	}
}

// WithReport sets the report payload
func (b *BackplaneReportActionBuilder) WithReport(report BackplaneReport) *BackplaneReportActionBuilder {
	b.report = report
	return b
}

// Build creates the BackplaneReportAction
func (b *BackplaneReportActionBuilder) Build() Action {
	return &BackplaneReportAction{
		Report:     b.report,
		ReportType: b.reportType,
	}
}

// Convenience functions for simple cases

// ServiceLog creates a basic service log action
func ServiceLog(severity, summary, description string) Action {
	return NewServiceLogAction(severity, summary).
		WithDescription(description).
		Build()
}

// LimitedSupport creates a basic limited support action
// context is required for metrics labeling (e.g., "StoppedInstances", "EgressBlocked")
func LimitedSupport(summary, details, context string) Action {
	return NewLimitedSupportAction(summary, details, context).Build()
}

// Note creates a PagerDuty note action
func Note(content string) Action {
	return NewPagerDutyNoteAction(content).Build()
}

// NoteFrom creates a PagerDuty note from a notewriter
func NoteFrom(nw *notewriter.NoteWriter) Action {
	return NewPagerDutyNoteAction().FromNoteWriter(nw).Build()
}

// Silence creates a silence incident action
func Silence(reason string) Action {
	return NewSilenceIncidentAction(reason).Build()
}

// Escalate creates an escalate incident action
func Escalate(reason string) Action {
	return NewEscalateIncidentAction(reason).Build()
}

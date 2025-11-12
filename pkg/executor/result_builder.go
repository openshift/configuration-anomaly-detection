package executor

import (
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/investigation"
	"github.com/openshift/configuration-anomaly-detection/pkg/notewriter"
	"github.com/openshift/configuration-anomaly-detection/pkg/types"
)

// ResultWithActionsBuilder helps build InvestigationResults with actions
type ResultWithActionsBuilder struct {
	actions []Action
}

// NewResultWithActions creates a new builder
func NewResultWithActions() *ResultWithActionsBuilder {
	return &ResultWithActionsBuilder{
		actions: []Action{},
	}
}

// AddAction adds a pre-built action
func (b *ResultWithActionsBuilder) AddAction(action Action) *ResultWithActionsBuilder {
	b.actions = append(b.actions, action)
	return b
}

// AddServiceLog adds a service log action with a builder function
func (b *ResultWithActionsBuilder) AddServiceLog(
	severity, summary string,
	configure func(*ServiceLogActionBuilder),
) *ResultWithActionsBuilder {
	builder := NewServiceLogAction(severity, summary)
	if configure != nil {
		configure(builder)
	}
	b.actions = append(b.actions, builder.Build())
	return b
}

// AddLimitedSupport adds a limited support action with a builder function
func (b *ResultWithActionsBuilder) AddLimitedSupport(
	summary, details string,
	configure func(*LimitedSupportActionBuilder),
) *ResultWithActionsBuilder {
	builder := NewLimitedSupportAction(summary, details)
	if configure != nil {
		configure(builder)
	}
	b.actions = append(b.actions, builder.Build())
	return b
}

// AddNote adds a PagerDuty note
func (b *ResultWithActionsBuilder) AddNote(content string) *ResultWithActionsBuilder {
	b.actions = append(b.actions,
		NewPagerDutyNoteAction(content).Build())
	return b
}

// AddNoteFromNoteWriter adds a PagerDuty note from a notewriter
func (b *ResultWithActionsBuilder) AddNoteFromNoteWriter(nw *notewriter.NoteWriter) *ResultWithActionsBuilder {
	b.actions = append(b.actions,
		NewPagerDutyNoteAction().FromNoteWriter(nw).Build())
	return b
}

// Silence adds a silence action
func (b *ResultWithActionsBuilder) Silence(reason string) *ResultWithActionsBuilder {
	b.actions = append(b.actions,
		NewSilenceIncidentAction(reason).Build())
	return b
}

// Escalate adds an escalate action
func (b *ResultWithActionsBuilder) Escalate(reason string) *ResultWithActionsBuilder {
	b.actions = append(b.actions,
		NewEscalateIncidentAction(reason).Build())
	return b
}

// Build creates the InvestigationResult
func (b *ResultWithActionsBuilder) Build() investigation.InvestigationResult {
	// Convert reporter.Action to types.Action
	// They are the same type (alias), so we can just assign the slice
	invActions := make([]types.Action, len(b.actions))
	copy(invActions, b.actions)

	return investigation.InvestigationResult{
		Actions: invActions,
	}
}

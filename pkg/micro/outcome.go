package micro

import (
	"github.com/openshift/configuration-anomaly-detection/pkg/executor"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/investigation"
	"github.com/openshift/configuration-anomaly-detection/pkg/notewriter"
)

// Outcome reduces early-exit boilerplate in investigations.
// Each investigation creates an Outcome, calls micro functions in sequence,
// and uses Stop for early exits or Finalize for the normal completion path.
type Outcome struct {
	notes     *notewriter.NoteWriter
	clusterID string
	name      string
	actions   []executor.Action
}

// NewOutcome creates an Outcome bound to the investigation's note writer,
// cluster ID, and investigation name.
func NewOutcome(notes *notewriter.NoteWriter, clusterID, name string) *Outcome {
	return &Outcome{notes: notes, clusterID: clusterID, name: name}
}

// Stop returns an InvestigationResult for an early-exit finding.
func (o *Outcome) Stop(actions ...executor.Action) investigation.InvestigationResult {
	return investigation.InvestigationResult{
		Actions: executor.FinalizeResult(o.notes, o.clusterID, o.name, actions...),
	}
}

// Collect accumulates non-terminal actions (e.g., OHSS cases) to be
// included in the final result.
func (o *Outcome) Collect(actions ...executor.Action) {
	o.actions = append(o.actions, actions...)
}

// Finalize returns the accumulated result at the end of the investigation.
func (o *Outcome) Finalize(actions ...executor.Action) investigation.InvestigationResult {
	combined := make([]executor.Action, 0, len(o.actions)+len(actions))
	combined = append(combined, o.actions...)
	combined = append(combined, actions...)
	return investigation.InvestigationResult{
		Actions: executor.FinalizeResult(o.notes, o.clusterID, o.name, combined...),
	}
}

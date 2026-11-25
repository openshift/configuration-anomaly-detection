package micro

import (
	"github.com/openshift/configuration-anomaly-detection/pkg/executor"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/investigation"
	"github.com/openshift/configuration-anomaly-detection/pkg/notewriter"
	"github.com/openshift/configuration-anomaly-detection/pkg/types"
)

// ClusterAccessError checks whether a Build error is a known cluster access
// issue and returns an escalation result if so. Pure — no external calls.
func ClusterAccessError(err error, notes *notewriter.NoteWriter) Result {
	msg, ok := investigation.ClusterAccessErrorMessage(err)
	if !ok {
		return Result{Done: false}
	}

	notes.AppendWarning("%s", msg)
	return Result{
		Done: true,
		Actions: []types.Action{
			executor.Escalate(msg),
		},
	}
}

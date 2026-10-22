package executor

import (
	"context"
	"errors"
	"testing"

	cmv1 "github.com/openshift-online/ocm-sdk-go/clustersmgmt/v1"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

type orderedReportingAction struct {
	kind   ActionType
	events *[]string
	fail   bool
}

func (a orderedReportingAction) Type() string    { return string(a.kind) }
func (a orderedReportingAction) Validate() error { return nil }
func (a orderedReportingAction) Execute(context.Context, *ExecutionContext) error {
	*a.events = append(*a.events, string(a.kind))
	if a.fail {
		return errors.New("reporting unavailable")
	}
	return nil
}

func TestReportingAttemptsPrecedeEscalationEvenOnFailure(t *testing.T) {
	for _, concurrent := range []bool{false, true} {
		for _, fail := range []bool{false, true} {
			var events []string
			cluster, err := cmv1.NewCluster().ID("test").Build()
			require.NoError(t, err)
			exec := NewWebhookExecutor(nil, nil, nil, zap.NewNop().Sugar())
			err = exec.Execute(context.Background(), &ExecutorInput{
				InvestigationName: "aiassisted", Cluster: cluster,
				Actions: []Action{
					orderedReportingAction{ActionTypeBackplaneReport, &events, fail},
					orderedReportingAction{ActionTypePagerDutyNote, &events, fail},
					orderedReportingAction{ActionTypeEscalateIncident, &events, false},
				},
				Options: ExecutionOptions{StopOnError: false, ConcurrentActions: concurrent},
			})
			if fail {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, []string{string(ActionTypeBackplaneReport), string(ActionTypePagerDutyNote), string(ActionTypeEscalateIncident)}, events)
		}
	}
}

package interceptor

import (
	"errors"
	"fmt"
	"testing"

	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
	"github.com/openshift/configuration-anomaly-detection/pkg/pagerduty"
	pdmock "github.com/openshift/configuration-anomaly-detection/pkg/pagerduty/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

// TestUnsupportedAlertEscalation distinguishes guarded skips from actual update failures.
func TestUnsupportedAlertEscalation(t *testing.T) {
	const failure = "failure"
	for _, tc := range []struct {
		name string
		err  error
	}{
		{name: "success"},
		{name: "skip", err: &pagerduty.EscalationSkippedError{Reason: "already handled"}},
		{name: "wrapped skip", err: fmt.Errorf("guard: %w", &pagerduty.EscalationSkippedError{Reason: "already handled"})},
		{name: failure, err: errors.New("update failed")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			core, logs := observer.New(zap.DebugLevel)
			original := logging.RawLogger
			logging.RawLogger = zap.New(core).Sugar()
			t.Cleanup(func() { logging.RawLogger = original })
			client := pdmock.NewMockClient(gomock.NewController(t))
			client.EXPECT().EscalateIncidentWithNote(gomock.Any()).DoAndReturn(func(note string) error {
				require.Contains(t, note, "requesting guarded escalation")
				return tc.err
			})
			if tc.name == failure {
				client.EXPECT().GetIncidentID().Return("I")
			}
			escalateUnsupportedAlert(client)
			switch {
			case tc.err == nil:
				require.Zero(t, logs.Len())
			case tc.name == failure:
				require.Equal(t, 1, logs.FilterLevelExact(zap.ErrorLevel).Len())
			default:
				require.Zero(t, logs.FilterLevelExact(zap.ErrorLevel).Len())
				require.Equal(t, 1, logs.FilterMessage("Unsupported-alert escalation skipped; PagerDuty automatic escalation remains in control").Len())
			}
		})
	}
}

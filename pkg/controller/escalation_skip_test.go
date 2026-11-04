package controller

import (
	"fmt"
	"testing"

	"github.com/openshift/configuration-anomaly-detection/pkg/pagerduty"
	pdmock "github.com/openshift/configuration-anomaly-detection/pkg/pagerduty/mock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestTrackingPDClient_SkipsDoNotEscalateOrInterruptReporting(t *testing.T) {
	for _, withNote := range []bool{false, true} {
		t.Run(fmt.Sprintf("withNote=%t", withNote), func(t *testing.T) {
			client := pdmock.NewMockClient(gomock.NewController(t))
			skipped := fmt.Errorf("guard: %w", &pagerduty.EscalationSkippedError{Reason: "history lookup unavailable"})
			tracked := newTrackingPDClient(client)
			if withNote {
				client.EXPECT().EscalateIncidentWithNote("context").Return(skipped)
				require.NoError(t, tracked.EscalateIncidentWithNote("context"))
			} else {
				client.EXPECT().EscalateIncident().Return(skipped)
				require.NoError(t, tracked.EscalateIncident())
			}
			assert.False(t, tracked.HasEscalated())
			client.EXPECT().AddNote("report").Return(nil)
			require.NoError(t, tracked.AddNote("report"))
			// A later request may retry: a skipped attempt is not an escalation.
			client.EXPECT().EscalateIncident().Return(nil)
			require.NoError(t, tracked.EscalateIncident())
			assert.True(t, tracked.HasEscalated())
		})
	}
}

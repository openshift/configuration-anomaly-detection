package controller

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	pdmock "github.com/openshift/configuration-anomaly-detection/pkg/pagerduty/mock"
)

// TestInvestigate_NoMatchedAlert_EscalatesExactlyOnce is a regression test for
// ROSAENG-66516: CAD double-escalated PagerDuty incidents on the AI-fallback
// path because Investigate unconditionally issued a second, generic
// escalation after its fallback chain ran. With no configured Cfg at all
// (cfg == nil), Investigate skips both the matched-alert chain and the
// AI-fallback chain entirely and falls straight to the generic escalation —
// the simplest reachable path to that final call. This exercises the real
// wiring introduced by the fix: PagerDutyController.pdClient and
// investigationRunner.notifier must share the same trackingPDClient so
// HasEscalated() reflects reality, and EscalateIncident must fire exactly
// once.
func TestInvestigate_NoMatchedAlert_EscalatesExactlyOnce(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockPD := pdmock.NewMockClient(ctrl)
	mockPD.EXPECT().RetrieveClusterID().Return("cluster123", nil)
	mockPD.EXPECT().GetIncidentRef().Return("INC-1").AnyTimes()
	mockPD.EXPECT().GetServiceID().Return("SVC-1").AnyTimes()
	mockPD.EXPECT().GetServiceName().Return("some-service").AnyTimes()
	mockPD.EXPECT().GetTitle().Return("SomeUnhandledAlert").AnyTimes()
	// The regression: this must be called exactly once. Before the fix,
	// Investigate had no way to know an escalation already happened and
	// could call this a second time.
	mockPD.EXPECT().EscalateIncident().Return(nil).Times(1)

	tracked := newTrackingPDClient(mockPD)
	c := &PagerDutyController{
		pdClient: tracked,
		investigationRunner: investigationRunner{
			// dependencies.Cfg is nil, so Investigate finds no matched alert
			// and no AI agent config: both the alert-chain and AI-fallback
			// blocks are skipped, landing directly on the generic escalate.
			dependencies: &Dependencies{},
			notifier:     newPDIncidentNotifier(tracked),
		},
	}

	err := c.Investigate(context.Background())
	require.NoError(t, err)
	require.True(t, tracked.HasEscalated())
}

// TestInvestigate_AlreadyEscalated_DoesNotEscalateAgain directly covers the
// guard added for ROSAENG-66516: once an incident has been escalated by any
// path sharing the trackingPDClient, Investigate's final fallback must not
// call EscalateIncident a second time.
func TestInvestigate_AlreadyEscalated_DoesNotEscalateAgain(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockPD := pdmock.NewMockClient(ctrl)
	mockPD.EXPECT().RetrieveClusterID().Return("cluster123", nil)
	mockPD.EXPECT().GetIncidentRef().Return("INC-1").AnyTimes()
	mockPD.EXPECT().GetServiceID().Return("SVC-1").AnyTimes()
	mockPD.EXPECT().GetServiceName().Return("some-service").AnyTimes()
	mockPD.EXPECT().GetTitle().Return("SomeUnhandledAlert").AnyTimes()
	// Simulates the one prior escalation (e.g. from aiassisted). No
	// EscalateIncident expectation is set at all: gomock fails the test if
	// Investigate's fallback tries to escalate a second time.
	mockPD.EXPECT().EscalateIncidentWithNote("already handled upstream").Return(nil).Times(1)

	tracked := newTrackingPDClient(mockPD)
	notifier := newPDIncidentNotifier(tracked)

	// Simulate an investigation elsewhere in the chain (e.g. aiassisted)
	// having already escalated this incident on its own.
	require.NoError(t, notifier.EscalateWithNote("already handled upstream"))

	c := &PagerDutyController{
		pdClient: tracked,
		investigationRunner: investigationRunner{
			dependencies: &Dependencies{},
			notifier:     notifier,
		},
	}

	err := c.Investigate(context.Background())
	require.NoError(t, err)
}

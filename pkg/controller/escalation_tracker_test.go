package controller

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/investigation"
	pdmock "github.com/openshift/configuration-anomaly-detection/pkg/pagerduty/mock"
)

// TestTrackingPDClient guards against CAD double-escalating PagerDuty
// incidents (ROSAENG-66516): every code path that might escalate an incident
// (an investigation's direct call, an investigation's action, or the
// controller's own generic fallback) goes through the same trackingPDClient,
// so HasEscalated() is the single source of truth for "has this incident
// already been escalated".
func TestTrackingPDClient(t *testing.T) {
	t.Run("starts unescalated", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		tracked := newTrackingPDClient(pdmock.NewMockClient(ctrl))

		assert.False(t, tracked.HasEscalated())
	})

	t.Run("EscalateIncident marks it escalated", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockClient := pdmock.NewMockClient(ctrl)
		mockClient.EXPECT().EscalateIncident().Return(nil)

		tracked := newTrackingPDClient(mockClient)
		require.NoError(t, tracked.EscalateIncident())
		assert.True(t, tracked.HasEscalated())
	})

	t.Run("EscalateIncidentWithNote marks it escalated", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockClient := pdmock.NewMockClient(ctrl)
		mockClient.EXPECT().EscalateIncidentWithNote("reason").Return(nil)

		tracked := newTrackingPDClient(mockClient)
		require.NoError(t, tracked.EscalateIncidentWithNote("reason"))
		assert.True(t, tracked.HasEscalated())
	})

	t.Run("a failed escalation is not tracked", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockClient := pdmock.NewMockClient(ctrl)
		mockClient.EXPECT().EscalateIncident().Return(errors.New("pagerduty unavailable"))

		tracked := newTrackingPDClient(mockClient)
		assert.Error(t, tracked.EscalateIncident())
		assert.False(t, tracked.HasEscalated())
	})

	t.Run("a second EscalateIncident call never reaches the real client", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		mockClient := pdmock.NewMockClient(ctrl)
		// No .Times()/.AnyTimes(): gomock's default expectation of exactly
		// one call means a second real EscalateIncident call fails the test.
		mockClient.EXPECT().EscalateIncident().Return(nil)

		tracked := newTrackingPDClient(mockClient)
		require.NoError(t, tracked.EscalateIncident())
		require.NoError(t, tracked.EscalateIncident())
		assert.True(t, tracked.HasEscalated())
	})

	t.Run("EscalateIncidentWithNote degrades to a note once already escalated", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		mockClient := pdmock.NewMockClient(ctrl)
		mockClient.EXPECT().EscalateIncident().Return(nil)
		mockClient.EXPECT().AddNote("still relevant context").Return(nil)

		tracked := newTrackingPDClient(mockClient)
		require.NoError(t, tracked.EscalateIncident())
		// No EscalateIncidentWithNote expectation set: if this fell through
		// to the real client instead of degrading to AddNote, gomock fails.
		require.NoError(t, tracked.EscalateIncidentWithNote("still relevant context"))
	})

	t.Run("a failed escalation allows a later attempt to actually retry", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		mockClient := pdmock.NewMockClient(ctrl)
		gomock.InOrder(
			mockClient.EXPECT().EscalateIncident().Return(errors.New("pagerduty unavailable")),
			mockClient.EXPECT().EscalateIncident().Return(nil),
		)

		tracked := newTrackingPDClient(mockClient)
		assert.Error(t, tracked.EscalateIncident())
		assert.False(t, tracked.HasEscalated())

		require.NoError(t, tracked.EscalateIncident())
		assert.True(t, tracked.HasEscalated())
	})
}

// TestPDIncidentNotifier_AttachToBuilder_SharesEscalationState is a wiring
// invariant test: everything this fix depends on requires that the client
// handed to investigations via AttachToBuilder is the *same* trackingPDClient
// instance the notifier and executor use. If AttachToBuilder is ever changed
// to hand out a different or unwrapped client, an escalation made by an
// investigation would go unnoticed by the rest of the pipeline, and this
// test fails.
func TestPDIncidentNotifier_AttachToBuilder_SharesEscalationState(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockPD := pdmock.NewMockClient(ctrl)
	mockPD.EXPECT().EscalateIncident().Return(nil).Times(1)

	tracked := newTrackingPDClient(mockPD)
	notifier := newPDIncidentNotifier(tracked)

	builder := &investigation.ResourceBuilderMock{Resources: &investigation.Resources{}}
	notifier.AttachToBuilder(builder)

	// Simulate an investigation escalating through the client it was handed
	// via Resources.PdClient - exactly what aiassisted.Run does.
	require.NoError(t, builder.Resources.PdClient.EscalateIncident())

	assert.True(t, tracked.HasEscalated())
}

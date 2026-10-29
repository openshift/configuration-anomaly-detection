package controller

import (
	"testing"

	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/investigation"
	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
	"github.com/openshift/configuration-anomaly-detection/pkg/notewriter"
	"github.com/openshift/configuration-anomaly-detection/pkg/ocm"
	"github.com/openshift/configuration-anomaly-detection/pkg/pagerduty"
	pdmock "github.com/openshift/configuration-anomaly-detection/pkg/pagerduty/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

// TestDocumentationMismatchReporting retains context for successful, skipped, and deduplicated escalations.
func TestDocumentationMismatchReporting(t *testing.T) {
	const skippedOutcome = "skipped"
	for _, outcome := range []string{"escalated", skippedOutcome, "already escalated"} {
		t.Run(outcome, func(t *testing.T) {
			mockPD := pdmock.NewMockClient(gomock.NewController(t))
			tracked := newTrackingPDClient(mockPD)
			notifier := newPDIncidentNotifier(tracked)
			docErr := &ocm.DocumentationMismatchError{
				ExpectedProduct: ocm.ProductROSA,
				DetectedProduct: ocm.ProductOSD,
				Summary:         "documentation mismatch",
				Details:         "manual review required",
			}
			resources := &investigation.Resources{Notes: notewriter.New("test", logging.RawLogger)}
			resources.Notes.AppendWarning("Earlier investigation context")
			var posted string
			if outcome == "already escalated" {
				mockPD.EXPECT().EscalateIncident().Return(nil)
				require.NoError(t, tracked.EscalateIncident())
				mockPD.EXPECT().AddNote(gomock.Any()).DoAndReturn(func(note string) error {
					posted = note
					return nil
				})
			} else {
				mockPD.EXPECT().EscalateIncidentWithNote(gomock.Any()).DoAndReturn(func(note string) error {
					posted = note
					if outcome == skippedOutcome {
						return &pagerduty.EscalationSkippedError{Reason: "already acknowledged"}
					}
					return nil
				})
			}
			escalateDocumentationMismatch(docErr, resources, notifier)
			require.Contains(t, posted, docErr.EscalationMessage())
			require.Contains(t, posted, "Earlier investigation context")
			require.Equal(t, resources.Notes.String(), posted)
			require.Equal(t, outcome != skippedOutcome, tracked.HasEscalated())
		})
	}
}

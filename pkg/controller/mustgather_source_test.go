package controller

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/openshift/configuration-anomaly-detection/pkg/config"
	"github.com/openshift/configuration-anomaly-detection/pkg/metrics"
)

func TestMustGatherSource(t *testing.T) {
	tests := []struct {
		name        string
		notifier    incidentNotifier
		alertConfig *config.AlertConfig
		want        string
	}{
		{
			name:        "dedicated CreateMustGather alert is legacy",
			notifier:    newPDIncidentNotifier(nil),
			alertConfig: &config.AlertConfig{AlertTitle: "MustGather", Name: "mustgather"},
			want:        metrics.MustGatherSourceLegacy,
		},
		{
			name:        "CreateMustGather alert without name is legacy",
			notifier:    newPDIncidentNotifier(nil),
			alertConfig: &config.AlertConfig{AlertTitle: "CreateMustGather"},
			want:        metrics.MustGatherSourceLegacy,
		},
		{
			name:        "MustGather alert without name is legacy",
			notifier:    newPDIncidentNotifier(nil),
			alertConfig: &config.AlertConfig{AlertTitle: "MustGather"},
			want:        metrics.MustGatherSourceLegacy,
		},
		{
			name:        "mustgather entry in another alert chain is sampled",
			notifier:    newPDIncidentNotifier(nil),
			alertConfig: &config.AlertConfig{AlertTitle: "ClusterHasGoneMissing", Name: "chgm"},
			want:        metrics.MustGatherSourceSampled,
		},
		{
			name:        "alert without name falls back to title and is sampled",
			notifier:    newPDIncidentNotifier(nil),
			alertConfig: &config.AlertConfig{AlertTitle: "SomeAlert"},
			want:        metrics.MustGatherSourceSampled,
		},
		{
			name:        "manual run without PagerDuty",
			notifier:    newNoopIncidentNotifier(),
			alertConfig: &config.AlertConfig{AlertTitle: "mustgather", Name: "mustgather"},
			want:        metrics.MustGatherSourceManual,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &investigationRunner{notifier: tt.notifier}
			assert.Equal(t, tt.want, c.mustGatherSource(tt.alertConfig))
		})
	}
}

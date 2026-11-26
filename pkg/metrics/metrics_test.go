package metrics

import (
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type sample struct {
	labels map[string]string
	value  float64
}

// samples returns all series currently held by the given counter vector.
func samples(t *testing.T, vec *prometheus.CounterVec) []sample {
	t.Helper()
	reg := prometheus.NewRegistry()
	require.NoError(t, reg.Register(vec))
	families, err := reg.Gather()
	require.NoError(t, err)

	var out []sample
	for _, mf := range families {
		for _, m := range mf.GetMetric() {
			labels := map[string]string{}
			for _, lp := range m.GetLabel() {
				labels[lp.GetName()] = lp.GetValue()
			}
			out = append(out, sample{labels: labels, value: m.GetCounter().GetValue()})
		}
	}
	return out
}

func resetAll() {
	for _, c := range pushedCollectors() {
		c.Reset()
	}
}

func TestMustGatherAttempt_EmitsOncePerAttempt(t *testing.T) {
	resetAll()
	t.Cleanup(resetAll)

	StartMustGatherAttempt(MustGatherSourceSampled, "chgm", "ROSA HCP").Finish(MustGatherStatusSuccess, "completed")

	started := samples(t, MustGatherStarted)
	require.Len(t, started, 1)
	assert.Equal(t, 1.0, started[0].value)
	assert.Equal(t, map[string]string{
		"source":     "sampled",
		"alert_type": "chgm",
		"product":    "ROSA HCP",
	}, started[0].labels)

	outcomes := samples(t, MustGatherOutcome)
	require.Len(t, outcomes, 1)
	assert.Equal(t, 1.0, outcomes[0].value)
	assert.Equal(t, map[string]string{
		"status":     "success",
		"reason":     "completed",
		"source":     "sampled",
		"alert_type": "chgm",
		"product":    "ROSA HCP",
	}, outcomes[0].labels)
}

func TestMustGatherAttempt_NoFinishLeavesOutcomeEmpty(t *testing.T) {
	resetAll()
	t.Cleanup(resetAll)

	// Simulates an OOM-killed or timed-out run: started is recorded, outcome is not.
	StartMustGatherAttempt(MustGatherSourceLegacy, "mustgather", "ROSA classic")

	assert.Len(t, samples(t, MustGatherStarted), 1)
	assert.Empty(t, samples(t, MustGatherOutcome))
}

func TestMustGatherAttempt_EmptyLabelsAreUnknown(t *testing.T) {
	resetAll()
	t.Cleanup(resetAll)

	StartMustGatherAttempt("", "", "ROSA classic").Finish(MustGatherStatusSkipped, "must_gather_in_progress")

	started := samples(t, MustGatherStarted)
	require.Len(t, started, 1)
	assert.Equal(t, "unknown", started[0].labels["source"])
	assert.Equal(t, "unknown", started[0].labels["alert_type"])

	outcomes := samples(t, MustGatherOutcome)
	require.Len(t, outcomes, 1)
	assert.Equal(t, "unknown", outcomes[0].labels["source"])
	assert.Equal(t, "unknown", outcomes[0].labels["alert_type"])
}

// fakeGateway records the bodies pushed to it and answers with the given status.
type fakeGateway struct {
	mu     sync.Mutex
	bodies []string
	status int
}

func (g *fakeGateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		// Reject unreadable pushes so Push keeps its counters, like a real gateway would.
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	g.mu.Lock()
	g.bodies = append(g.bodies, string(body))
	status := g.status
	g.mu.Unlock()
	w.WriteHeader(status)
}

func (g *fakeGateway) setStatus(status int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.status = status
}

func TestPush_RepeatedPushesDoNotResendCounters(t *testing.T) {
	resetAll()
	t.Cleanup(resetAll)

	gw := &fakeGateway{status: http.StatusOK}
	srv := httptest.NewServer(gw)
	defer srv.Close()
	t.Setenv("CAD_PROMETHEUS_PUSHGATEWAY", srv.URL)

	Inc(Alerts, "mustgather")
	StartMustGatherAttempt(MustGatherSourceLegacy, "mustgather", "ROSA classic")
	Push() // early push

	attemptSeries := `cad_investigate_must_gather_started_total{alert_type="mustgather",product="ROSA classic",source="legacy"} 1`
	alertSeries := `cad_investigate_alerts_total{alert_type="mustgather"} 1`

	Push() // final push without new increments

	require.Len(t, gw.bodies, 2)
	assert.Contains(t, gw.bodies[0], alertSeries)
	assert.Contains(t, gw.bodies[0], attemptSeries)
	assert.NotContains(t, gw.bodies[1], "cad_investigate_alerts_total")
	assert.NotContains(t, gw.bodies[1], "cad_investigate_must_gather_started_total")
}

func TestPush_KeepsCountersWhenPushFails(t *testing.T) {
	resetAll()
	t.Cleanup(resetAll)

	gw := &fakeGateway{status: http.StatusInternalServerError}
	srv := httptest.NewServer(gw)
	defer srv.Close()
	t.Setenv("CAD_PROMETHEUS_PUSHGATEWAY", srv.URL)

	Inc(Alerts, "mustgather")
	Push()

	got := samples(t, Alerts)
	require.Len(t, got, 1)
	assert.Equal(t, 1.0, got[0].value)

	gw.setStatus(http.StatusOK)
	Push()
	assert.Empty(t, samples(t, Alerts))
}

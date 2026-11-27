// Package metrics provides prometheus instrumentation for CAD
package metrics

import (
	"context"
	"os"
	"time"

	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/push"
	"github.com/prometheus/common/expfmt"
)

const pushTimeout = 10 * time.Second

// pushedCollectors are the counters sent to the pushgateway on every Push.
func pushedCollectors() []*prometheus.CounterVec {
	return []*prometheus.CounterVec{
		Alerts,
		AlertsFiltered,
		LimitedSupportSet,
		ServicelogPrepared,
		ServicelogSent,
		MustGatherPerformed,
		MustGatherStarted,
		MustGatherOutcome,
		EtcdDatabaseAnalysis,
		EtcdSnapshotCleanup,
		ManualInvestigationStarted,
		ManualInvestigationCompleted,
	}
}

// Push collects and pushes metrics to the configured pushgateway.
//
// The aggregation gateway sums every pushed sample into its running total, so
// pushing the same in-process counter twice would count it twice. To make
// repeated Push calls safe (e.g. an early push to survive OOM kills followed by
// the final push at process exit), the counters are reset after each successful
// push, so every push only carries the increments since the previous one.
// On failure the counters are kept so the next push can deliver them.
func Push() {
	pushgateway := os.Getenv("CAD_PROMETHEUS_PUSHGATEWAY")
	if pushgateway == "" {
		logging.Warn("metrics disabled, set env 'CAD_PROMETHEUS_PUSHGATEWAY' to push metrics")
		return
	}

	collectors := pushedCollectors()
	promPusher := push.New(pushgateway, "cad").Format(expfmt.NewFormat(expfmt.TypeTextPlain))
	for _, c := range collectors {
		promPusher.Collector(c)
	}
	ctx, cancel := context.WithTimeout(context.Background(), pushTimeout)
	defer cancel()
	if err := promPusher.AddContext(ctx); err != nil {
		logging.Errorf("failed to push metrics: %w", err)
		return
	}
	for _, c := range collectors {
		c.Reset()
	}
}

// Inc takes a counterVec and a set of label values and increases by one
func Inc(counterVec *prometheus.CounterVec, lsv ...string) {
	metric, err := counterVec.GetMetricWithLabelValues(lsv...)
	if err != nil {
		logging.Error(err)
	}
	metric.Inc()
}

const (
	namespace            = "cad"
	subsystemInvestigate = "investigate"
	alertTypeLabel       = "alert_type"
	lsSummaryLabel       = "ls_summary"
	mustgatherLabel      = "product"
	dryRunLabel          = "dry_run"
	statusLabel          = "status"
	reasonLabel          = "reason"
	sourceLabel          = "source"
)

// Values for the source label of the must-gather attempt metrics.
const (
	// MustGatherSourceLegacy is a run triggered by the dedicated CreateMustGather alert.
	MustGatherSourceLegacy = "legacy"
	// MustGatherSourceSampled is a run sampled as a side-effect of another alert's chain.
	MustGatherSourceSampled = "sampled"
	// MustGatherSourceManual is a run triggered via `cadctl investigate manual`.
	MustGatherSourceManual = "manual"
	// MustGatherSourceUnknown is used when the caller did not provide a source.
	MustGatherSourceUnknown = "unknown"
)

// Values for the status label of MustGatherOutcome.
const (
	MustGatherStatusSuccess = "success"
	MustGatherStatusFailed  = "failed"
	MustGatherStatusSkipped = "skipped"
)

var (
	// Alerts is a metric counting all alerts CAD received
	Alerts = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace, Subsystem: subsystemInvestigate,
			Name: "alerts_total",
			Help: "counts investigated alerts by alert and event type",
		}, []string{alertTypeLabel})
	// LimitedSupportSet is a counter for limited support reasons set by cad
	LimitedSupportSet = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace, Subsystem: subsystemInvestigate,
			Name: "limitedsupport_set_total",
			Help: "counts investigations resulting in setting a limited support reason",
		}, []string{alertTypeLabel, lsSummaryLabel})
	// ServicelogPrepared is a counter for investigation ending in a prepared servicelog
	ServicelogPrepared = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace, Subsystem: subsystemInvestigate,
			Name: "servicelog_prepared_total",
			Help: "counts investigations resulting in a prepared servicelog attached to the incident notes",
		}, []string{alertTypeLabel})
	// ServicelogSent is a counter for investigation ending in a sent servicelog
	ServicelogSent = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace, Subsystem: subsystemInvestigate,
			Name: "servicelog_sent_total",
			Help: "counts investigations resulting in a sent servicelog",
		}, []string{alertTypeLabel})
	AlertsFiltered = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace, Subsystem: subsystemInvestigate,
			Name: "alerts_filtered_total",
			Help: "counts alerts filtered out by investigation filter configuration",
		}, []string{alertTypeLabel})
	MustGatherPerformed = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace, Subsystem: subsystemInvestigate,
			Name: "must_gather_performed_total",
			Help: "counts the total number of must-gathers performed",
		}, []string{alertTypeLabel, mustgatherLabel})
	// MustGatherStarted counts must-gather attempts entering the collection phase.
	// Use together with MustGatherOutcome: started - outcomes are attempts that
	// never finished (e.g. OOM-killed or timed out pods).
	MustGatherStarted = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace, Subsystem: subsystemInvestigate,
			Name: "must_gather_started_total",
			Help: "counts must-gather attempts that entered the collection phase",
		}, []string{sourceLabel, alertTypeLabel, mustgatherLabel})
	// MustGatherOutcome counts the final outcome of must-gather attempts.
	MustGatherOutcome = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace, Subsystem: subsystemInvestigate,
			Name: "must_gather_outcome_total",
			Help: "counts must-gather attempt outcomes by status and reason",
		}, []string{statusLabel, reasonLabel, sourceLabel, alertTypeLabel, mustgatherLabel})
	// EtcdDatabaseAnalysis tracks etcddatabasequotalowspace investigation outcomes
	EtcdDatabaseAnalysis = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace, Subsystem: subsystemInvestigate,
			Name: "etcd_database_analysis_total",
			Help: "counts etcddatabasequotalowspace investigation outcomes by status and reason",
		}, []string{alertTypeLabel, "status", "reason"})
	// EtcdSnapshotCleanup tracks etcd snapshot cleanup success/failure
	EtcdSnapshotCleanup = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace, Subsystem: subsystemInvestigate,
			Name: "etcd_snapshot_cleanup_total",
			Help: "counts etcd snapshot cleanup attempts by alert type and status",
		}, []string{alertTypeLabel, "status"})
	// ManualInvestigationStarted tracks when manual investigations are initiated
	ManualInvestigationStarted = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace, Subsystem: subsystemInvestigate,
			Name: "manual_started_total",
			Help: "counts manually triggered investigations by investigation name and dry-run mode",
		}, []string{alertTypeLabel, dryRunLabel})
	// ManualInvestigationCompleted tracks manual investigation outcomes
	ManualInvestigationCompleted = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace, Subsystem: subsystemInvestigate,
			Name: "manual_completed_total",
			Help: "counts manually triggered investigation completions by name, status, and dry-run mode",
		}, []string{alertTypeLabel, statusLabel, dryRunLabel})
)

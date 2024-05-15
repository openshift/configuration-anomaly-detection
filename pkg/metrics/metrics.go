// Package metrics provides prometheus instrumentation for CAD
package metrics

import (
	"os"

	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/push"
	"github.com/prometheus/common/expfmt"
)

// Push collects and pushes metrics to the configured pushgateway
func Push() {
	var promPusher *push.Pusher
	if pushgateway := os.Getenv("CAD_PROMETHEUS_PUSHGATEWAY"); pushgateway != "" {
		promPusher = push.New(pushgateway, "cad").Format(expfmt.FmtText)
		promPusher.Collector(Alerts)
		promPusher.Collector(LimitedSupportSet)
		promPusher.Collector(ServicelogPrepared)
		promPusher.Collector(ServicelogSent)
		err := promPusher.Add()
		if err != nil {
			logging.Errorf("failed to push metrics: %w", err)
		}
	} else {
		logging.Warn("metrics disabled, set env 'CAD_PROMETHEUS_PUSHGATEWAY' to push metrics")
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
)

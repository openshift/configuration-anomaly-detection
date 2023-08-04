// Package metrics provides prometheus instrumentation for CAD
package metrics

import (
	"os"

	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/push"
	"github.com/prometheus/common/expfmt"
)

const (
	namespace      = "cad"
	investigate    = "investigate"
	alertTypeLabel = "alert_type"
	eventTypeLabel = "event_type"
)

// Push collects and pushes metrics to the configured pushgateway
func Push() {
	var promPusher *push.Pusher
	if pushgateway := os.Getenv("CAD_PROMETHEUS_PUSHGATEWAY"); pushgateway != "" {
		promPusher = push.New(pushgateway, "cad").Format(expfmt.FmtText)
		promPusher.Collector(Alerts)
		promPusher.Collector(LimitedSupportSet)
		promPusher.Collector(LimitedSupportLifted)
		promPusher.Collector(ServicelogPrepared)
		err := promPusher.Add()
		if err != nil {
			logging.Errorf("failed to push metrics: %w", err)
		}
	} else {
		logging.Warn("metrics disabled, set env 'CAD_PROMETHEUS_PUSHGATEWAY' to push metrics")
	}
}

// Alerts is a metric counting all alerts CAD received
// Labeled with alert and event type
var (
	Alerts     = prometheus.NewCounterVec(alertsOpts, []string{alertTypeLabel, eventTypeLabel})
	alertsOpts = prometheus.CounterOpts{Namespace: namespace, Subsystem: investigate, Name: "alerts"}
)

// LimitedSupportSet is a metric counting investigations that ended with posting a limited support reason
// Labeled with alert and event type
var (
	LimitedSupportSet     = prometheus.NewCounterVec(limitedSupportSetOpts, []string{alertTypeLabel, eventTypeLabel})
	limitedSupportSetOpts = prometheus.CounterOpts{Namespace: namespace, Subsystem: investigate, Name: "limitedsupport_set"}
)

// LimitedSupportLifted is a metric counting investigations ending with lifting a limited support reason
// Labeled with alert and event type
var (
	LimitedSupportLifted     = prometheus.NewCounterVec(limitedSupportLiftedOpts, []string{alertTypeLabel, eventTypeLabel})
	limitedSupportLiftedOpts = prometheus.CounterOpts{Namespace: namespace, Subsystem: investigate, Name: "limitedsupport_lifted"}
)

// ServicelogPrepared is a metric counting investigations ending with a prepared servicelog attached to incident notes
var (
	ServicelogPrepared     = prometheus.NewCounterVec(servicelogPreparedOpts, []string{alertTypeLabel, eventTypeLabel})
	servicelogPreparedOpts = prometheus.CounterOpts{Namespace: namespace, Subsystem: investigate, Name: "servicelog_prepared"}
)

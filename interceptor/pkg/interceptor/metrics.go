package interceptor

import (
	"strconv"

	"sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	requestsCountMetricName = "cad_interceptor_requests_total"
	requestsCountMetricHelp = "Number of times CAD interceptor has been called (through a PagerDuty webhook, normally)"

	errorsCountMetricName = "cad_interceptor_errors_total"
	errorsCountMetricHelp = "Number of times CAD interceptor has been failed to process a request"
)

var (
	requestsCountMetricDesc = prometheus.NewDesc(
		requestsCountMetricName,
		requestsCountMetricHelp,
		nil, nil)

	errorsCountMetricDesc = prometheus.NewDesc(
		errorsCountMetricName,
		errorsCountMetricHelp,
		[]string{"error_code", "reason"}, nil)
)

type interceptorMetricsCollector struct {
	stats *InterceptorStats
}

func CreateAndRegisterMetricsCollector(stats *InterceptorStats) {
	metrics.Registry.MustRegister(&interceptorMetricsCollector{stats})
}

func (c *interceptorMetricsCollector) Describe(ch chan<- *prometheus.Desc) {
	prometheus.DescribeByCollect(c, ch)
}

func (c *interceptorMetricsCollector) Collect(ch chan<- prometheus.Metric) {
	ch <- prometheus.MustNewConstMetric(
		requestsCountMetricDesc,
		prometheus.CounterValue,
		float64(c.stats.RequestsCount),
	)

	for codeWithReason, errorsCount := range c.stats.CodeWithReasonToErrorsCount {
		ch <- prometheus.MustNewConstMetric(
			errorsCountMetricDesc,
			prometheus.CounterValue,
			float64(errorsCount),
			strconv.Itoa(codeWithReason.ErrorCode),
			codeWithReason.Reason,
		)
	}
}

// Package utils contains utility functions
package utils

import (
	"fmt"
	"time"

	cmv1 "github.com/openshift-online/ocm-sdk-go/clustersmgmt/v1"
	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
	"github.com/openshift/configuration-anomaly-detection/pkg/ocm"
	"github.com/openshift/configuration-anomaly-detection/pkg/pagerduty"
)

// WithRetries runs a function with up to 10 retries on error
func WithRetries(fn func() error) error {
	const defaultRetries = 10
	const defaultInitialBackoff = time.Second * 2

	return WithRetriesConfigurable(defaultRetries, defaultInitialBackoff, fn)
}

// WithRetriesConfigurable runs a function with a configurable retry count and backoff interval on error
func WithRetriesConfigurable(count int, initialBackoff time.Duration, fn func() error) error {
	var err error
	for i := 0; i < count; i++ {
		if i > 0 {
			logging.Warnf("Retry %d: %s \n", i, err.Error())
			time.Sleep(initialBackoff)
			initialBackoff *= 2
		}
		err = fn()
		if err == nil {
			return nil
		}
	}
	return fmt.Errorf("failed after %d retries: %w", count, err)
}

// EscalateAlertIfNotLS escalates an alert with the given reason if the cluster is not in limited support, else assigns the alert to silent test
func EscalateAlertIfNotLS(escalationReason string, cluster *cmv1.Cluster, pdClient pagerduty.Client, ocmClient ocm.Client) error {
	ls, err := ocmClient.IsInLimitedSupport(cluster.ID())
	if err != nil {
		return err
	}

	if ls {
		return pdClient.SilenceAlertWithNote("Cluster is in limited support. Silencing instead of escalating.")
	}

	return pdClient.EscalateAlertWithNote(escalationReason)
}

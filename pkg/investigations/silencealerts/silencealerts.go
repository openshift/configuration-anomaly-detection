// Package silencealerts contains functionality to silence alerts based on a cluster id
package silencealerts

import (
	"github.com/openshift/configuration-anomaly-detection/pkg/pagerduty"
)

// ResolveClusterAlerts resolves all alerts for cluster
func ResolveClusterAlerts(clusterID string, pdClient pagerduty.Client) error {
	return pdClient.ResolveAlertsForCluster(clusterID)
}

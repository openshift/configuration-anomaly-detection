// Package ccam Cluster Credentials Are Missing (CCAM) provides a service for detecting missing cluster credentials
package ccam

import (
	"fmt"
	"strings"

	cmv1 "github.com/openshift-online/ocm-sdk-go/clustersmgmt/v1"
	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
	"github.com/openshift/configuration-anomaly-detection/pkg/metrics"
	"github.com/openshift/configuration-anomaly-detection/pkg/ocm"
	"github.com/openshift/configuration-anomaly-detection/pkg/pagerduty"
)

var ccamLimitedSupport = ocm.LimitedSupportReason{
	Summary: "Restore missing cloud credentials",
	Details: "Your cluster requires you to take action because Red Hat is not able to access the infrastructure with the provided credentials. Please restore the credentials and permissions provided during install",
}

// This error is the response from backplane calls when:
// - trust policy of ManagedOpenShift-Support-Role is changed
// - installer role is deleted (it falls back to old flow, which results in access denied)
// - installer and support role are deleted
// - support role is deleted
const accessDeniedError string = "could not assume support role in customer's account: AccessDenied:"

// Evaluate estimates if the awsError is a cluster credentials are missing error. If it determines that it is,
// the cluster is placed into limited support (if the cluster state allows it), otherwise an error is returned.
func Evaluate(cluster *cmv1.Cluster, bpError error, ocmClient ocm.Client, pdClient pagerduty.Client, alertType string) error {
	logging.Info("Investigating possible missing cloud credentials...")

	// We aren't able to jumpRole because of an error that is different than
	// a removed support role/policy
	if !strings.Contains(bpError.Error(), accessDeniedError) {
		return fmt.Errorf("credentials are there, error is different: %w", bpError)
	}

	// The jumprole failed because of a missing support role/policy:
	// we need to figure out if we cluster state allows us to set limited support
	// (the cluster is in a ready state, not uninstalling, installing, etc.)

	switch cluster.State() {
	case cmv1.ClusterStateReady:
		// Cluster is in functional sate but we can't jumprole to it: post limited support
		metrics.Inc(metrics.LimitedSupportSet, alertType, ccamLimitedSupport.Summary)
		err := ocmClient.PostLimitedSupportReason(ccamLimitedSupport, cluster.ID())
		if err != nil {
			return fmt.Errorf("could not post limited support reason for %s: %w", cluster.Name(), err)
		}

		return pdClient.SilenceAlertWithNote(fmt.Sprintf("Added the following Limited Support reason to cluster: %#v. Silencing alert.\n", ccamLimitedSupport))
	case cmv1.ClusterStateUninstalling:
		// A cluster in uninstalling state should not alert primary - we just skip this
		return pdClient.SilenceAlertWithNote(fmt.Sprintf("Skipped adding limited support reason '%s': cluster is already uninstalling.", ccamLimitedSupport.Summary))
	default:
		// Anything else is an unknown state to us and/or requires investigation.
		// E.g. we land here if we run into a CPD alert where credentials were removed (installing state) and don't want to put it in LS yet.
		return pdClient.EscalateAlertWithNote(fmt.Sprintf("Cluster has invalid cloud credentials (support role/policy is missing) and the cluster is in state '%s'. Please investigate.", cluster.State()))
	}
}

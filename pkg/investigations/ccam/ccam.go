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
	"github.com/openshift/configuration-anomaly-detection/pkg/utils"
)

// NOTE: USE CAUTION WHEN CHANGING THESE TEMPLATES!!
// Changing the templates' summaries will likely prevent CAD from removing clusters with these Limited Support reasons in the future, since it identifies which reasons to delete via their summaries.
// If the summaries *must* be modified, it's imperative that existing clusters w/ these LS reasons have the new summary applied to them (currently, the only way to do this is to delete the current
// reason & apply the new one). Failure to do so will result in orphan clusters that are not managed by CAD.

var ccamLimitedSupport = ocm.LimitedSupportReason{
	Summary: "Restore missing cloud credentials",
	Details: "Your cluster requires you to take action because Red Hat is not able to access the infrastructure with the provided credentials. Please restore the credentials and permissions provided during install",
}

// CAUTION!!

// This error is the response from backplane calls when:
// - trust policy of ManagedOpenShift-Support-Role is changed
// - installer role is deleted (it falls back to old flow, which results in access denied)
// - installer and support role are deleted
// - support role is deleted
const accessDeniedError string = "could not assume support role in customer's account: AccessDenied:"

// Evaluate estimates if the awsError is a cluster credentials are missing error. If it determines that it is,
// the cluster is placed into limited support, otherwise an error is returned. If the cluster already has a CCAM
// LS reason, no additional reasons are added and incident is sent to SilentTest.
func Evaluate(cluster *cmv1.Cluster, bpError error, ocmClient ocm.Client, pdClient pagerduty.Client, alertType string) error {
	logging.Info("Investigating possible missing cloud credentials...")

	// We aren't able to jumpRole because of an error that is different than
	// a removed support role/policy
	if !strings.Contains(bpError.Error(), accessDeniedError) {
		return fmt.Errorf("credentials are there, error is different: %w", bpError)
	}

	ccamLsExists, err := ocmClient.LimitedSupportReasonExists(ccamLimitedSupport, cluster.ID())
	if err != nil {
		return fmt.Errorf("couldn't determine if limited support reason already exists: %w", err)
	}

	// The jumprole failed because of a missing support role/policy:
	// Case 1: if limited support already exists for that reason, no further action is needed
	// Case 2: if it doesn't exist yet, we need to figure out if we cluster state allows us to set limited support
	//        (the cluster is in a ready state, not uninstalling, installing, etc.)

	// Case 1
	if ccamLsExists {
		return pdClient.SilenceAlertWithNote(fmt.Sprintf("Cluster already has limited support for '%s'. Silencing alert.\n", ccamLimitedSupport.Summary))
	}

	// Case 2
	switch cluster.State() {
	case cmv1.ClusterStateReady:
		// Cluster is in functional sate but we can't jumprole to it: post limited support
		metrics.Inc(metrics.LimitedSupportSet, alertType, pdClient.GetEventType(), ccamLimitedSupport.Summary)
		err = ocmClient.PostLimitedSupportReason(ccamLimitedSupport, cluster.ID())
		if err != nil {
			return fmt.Errorf("could not post limited support reason for %s: %w", cluster.Name(), err)
		}

		return pdClient.SilenceAlertWithNote(fmt.Sprintf("Added the following Limited Support reason to cluster: %#v. Silencing alert.\n", ccamLimitedSupport))
	case cmv1.ClusterStateUninstalling:
		// A cluster in uninstalling state should not alert primary - we just skip this
		return pdClient.SilenceAlertWithNote(fmt.Sprintf("Skipped adding limited support reason '%s': cluster is already uninstalling.", ccamLimitedSupport.Summary))
	default:
		// Anything else is an unknown state to us and/or requires investigation.
		// E.g. we land here if we run into a CPD alert where credentials were removed (installing state)
		return pdClient.EscalateAlertWithNote(fmt.Sprintf("Cluster has invalid cloud credentials (support role/policy is missing) and the cluster is in state '%s'. Please investigate.", cluster.State()))
	}
}

// RemoveLimitedSupport will remove any CCAM limited support reason from the cluster,
// if it fails to do so, it will try to alert primary
// Run this after cloud credentials are confirmed
func RemoveLimitedSupport(cluster *cmv1.Cluster, ocmClient ocm.Client, pdClient pagerduty.Client, alertType string) error {
	removedReason := false
	err := utils.WithRetries(func() error {
		var err error
		removedReason, err = ocmClient.DeleteLimitedSupportReasons(ccamLimitedSupport, cluster.ID())
		return err
	})
	if err != nil {
		logging.Errorf("Failed to remove CCAM Limited support reason from cluster. Attempting to alert Primary.")
		originalErr := err
		err := utils.WithRetries(func() error {
			return pdClient.CreateNewAlert(buildAlertForCCAM(originalErr, cluster.ID()), pdClient.GetServiceID())
		})
		if err != nil {
			logging.Errorf("Failed to alert Primary")
			return err
		}
		logging.Info("Primary has been alerted")
		return nil
	}
	if removedReason {
		metrics.Inc(metrics.LimitedSupportLifted, alertType, pdClient.GetEventType(), ccamLimitedSupport.Summary)
	}
	return nil
}

// buildAlertForCCAM will return a NewAlert populated with cluster id and the specific error
func buildAlertForCCAM(lsError error, clusterID string) pagerduty.NewAlert {
	return pagerduty.NewAlert{
		Description: fmt.Sprintf("CAD is unable to remove a Limited Support reason from cluster %s", clusterID),
		Details: pagerduty.NewAlertCustomDetails{
			ClusterID:  clusterID,
			Error:      lsError.Error(),
			Resolution: "CAD has been unable to remove a Limited Support reason from this cluster. The cluster needs to be manually reviewed and have any appropriate Limited Support reasons removed. After corrective actions have been taken, this alert must be manually resolved.",
			SOP:        "https://github.com/openshift/ops-sop/blob/master/v4/alerts/CAD_ErrorRemovingLSReason.md",
		},
	}
}

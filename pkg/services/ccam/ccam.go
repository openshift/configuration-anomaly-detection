// Package ccam Cluster Credentials Are Missing (CCAM) provides a service for detecting missing cluster credentials
package ccam

import (
	"fmt"
	"regexp"

	v1 "github.com/openshift-online/ocm-sdk-go/clustersmgmt/v1"
	"github.com/openshift/configuration-anomaly-detection/pkg/ocm"
	"github.com/openshift/configuration-anomaly-detection/pkg/pagerduty"
	"github.com/openshift/configuration-anomaly-detection/pkg/services/logging"
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

var accessDeniedRegex = regexp.MustCompile(`failed to assume into support-role: AccessDenied`)

// checkMissing checks for missing credentials that are required for assuming
// into the support-role. If these credentials are missing we can silence the
// alert and post limited support reason.
func checkMissing(err error) bool {
	return accessDeniedRegex.MatchString(err.Error())
}

// Evaluate estimates if the awsError is a cluster credentials are missing error. If it determines that it is,
// the cluster is placed into limited support, otherwise an error is returned. If the cluster already has a CCAM
// LS reason, no additional reasons are added and incident is sent to SilentTest.
func Evaluate(cluster *v1.Cluster, awsError error, ocmClient ocm.Client, pdClient pagerduty.Client) error {

	logging.Info("Investigating possible missing cloud credentials...")
	if checkMissing(awsError) {
		return fmt.Errorf("credentials are there, error is different: %w", awsError)
	}

	lsExists, err := ocmClient.LimitedSupportReasonExists(ccamLimitedSupport, cluster.ID())
	if err != nil {
		return fmt.Errorf("couldn't determine if limited support reason already exists: %w", err)
	}

	note := fmt.Sprintf("Cluster already has limited support for '%s'. Silencing alert.\n", ccamLimitedSupport.Summary)

	if !lsExists {
		err = ocmClient.PostLimitedSupportReason(ccamLimitedSupport, cluster.ID())
		if err != nil {
			return fmt.Errorf("could not post limited support reason for %s: %w", cluster.Name(), err)
		}
		note = fmt.Sprintf("Added the following Limited Support reason to cluster: %#v. Silencing alert.\n", ccamLimitedSupport)
	}
	return pdClient.SilenceAlertWithNote(note)
}

// RemoveLimitedSupport will remove any CCAM limited support reason from the cluster,
// if it fails to do so, it will try to alert primary
// Run this after cloud credentials are confirmed
func RemoveLimitedSupport(cluster *v1.Cluster, ocmClient ocm.Client, pdClient pagerduty.Client) error {
	err := utils.WithRetries(func() error {
		return ocmClient.DeleteLimitedSupportReasons(ccamLimitedSupport, cluster.ID())
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
	return nil
}

// buildAlertForCCAM will return a NewAlert populated with cluster id and the specific error
func buildAlertForCCAM(lsError error, clusterID string) pagerduty.NewAlert {
	return pagerduty.NewAlert{
		Description: fmt.Sprintf("CAD is unable to remove a Limited Support reason from cluster %s", clusterID),
		Details: pagerduty.NewAlertDetails{
			ClusterID:  clusterID,
			Error:      lsError.Error(),
			Resolution: "CAD has been unable to remove a Limited Support reason from this cluster. The cluster needs to be manually reviewed and have any appropriate Limited Support reasons removed. After corrective actions have been taken, this alert must be manually resolved.",
			SOP:        "https://github.com/openshift/ops-sop/blob/master/v4/alerts/CAD_ErrorRemovingLSReason.md",
		},
	}
}

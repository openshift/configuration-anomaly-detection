// Package ccam Cluster Credentials Are Missing (CCAM) provides a service for detecting missing cluster credentials
package ccam

import (
	"fmt"
	"strings"

	cmv1 "github.com/openshift-online/ocm-sdk-go/clustersmgmt/v1"
	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
	"github.com/openshift/configuration-anomaly-detection/pkg/metrics"
	"github.com/openshift/configuration-anomaly-detection/pkg/notewriter"
	"github.com/openshift/configuration-anomaly-detection/pkg/ocm"
	"github.com/openshift/configuration-anomaly-detection/pkg/pagerduty"
)

var ccamSL = ocm.ServiceLog{
	Severity:     "Major",
	Summary:      "Action required: Restore missing cloud credentials",
	ServiceName:  "SREManualAction",
	Description:  "Your cluster requires you to take action because Red Hat is not able to access the infrastructure with the provided credentials. Please restore the credentials and permissions provided during install.",
	InternalOnly: false,
}

// Evaluate checks if the backplane error is due to a customer modification on the support/installer roles.
// If it determines that the above is the case, a service log is sent, otherwise an error is returned.
func Evaluate(cluster *cmv1.Cluster, bpError error, ocmClient ocm.Client, pdClient pagerduty.Client, alertType string) error {
	investigationName := "CloudCredentialsAreMissing"

	logging.Info("Investigating possible missing cloud credentials...")

	notes := notewriter.New(investigationName, logging.RawLogger)

	if customerRemovedPermissions := customerRemovedPermissions(bpError.Error()); !customerRemovedPermissions {
		// We aren't able to jumpRole because of an error that is different than
		// a removed support role/policy or removed installer role/policy
		// This would normally be a backplane failure or an incompability with the backplane error messages.
		return fmt.Errorf("credentials are there, error is different: %w", bpError)
	}

	switch cluster.State() {
	case cmv1.ClusterStateUninstalling:
		// A cluster in uninstalling state should not alert primary - we just skip this
		notes.AppendAutomation("Skipped sending service log '%s': cluster is already uninstalling.", ccamSL.Summary)
		return pdClient.SilenceAlertWithNote(notes.String())
	default:
		// Cluster is not yet uninstalling and we can't jumprole to it: send a service log
		metrics.Inc(metrics.ServicelogSent, investigationName)
		err := ocmClient.PostServiceLog(cluster.ID(), &ccamSL)
		if err != nil {
			return fmt.Errorf("could not post service log for %s: %w", cluster.Name(), err)
		}
		notes.AppendAutomation("Sent service log to cluster: '%s'. Silencing alert.\n", ccamSL.Summary)

		return pdClient.SilenceAlertWithNote(notes.String())
	}
}

// This error is the response from backplane calls when:
// - trust policy of ManagedOpenShift-Support-Role is changed
// - support role is deleted
const accessDeniedErrorSupportRole string = "could not assume support role in customer's account: AccessDenied:"

// - installer role is deleted (it falls back to old flow, which results in access denied)
// - installer and support role are deleted
const accessDeniedErrorInstallerRole string = "RH-Managed-OpenShift-Installer/OCM is not authorized to perform: sts:AssumeRole on resource:"

func customerRemovedPermissions(backplaneError string) bool {
	return strings.Contains(backplaneError, accessDeniedErrorSupportRole) || strings.Contains(backplaneError, accessDeniedErrorInstallerRole)
}

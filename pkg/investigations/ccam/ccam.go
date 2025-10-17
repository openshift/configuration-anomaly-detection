// Package ccam Cluster Credentials Are Missing (CCAM) provides a service for detecting missing cluster credentials
package ccam

import (
	"fmt"
	"log"
	"regexp"

	cmv1 "github.com/openshift-online/ocm-sdk-go/clustersmgmt/v1"
	investigation "github.com/openshift/configuration-anomaly-detection/pkg/investigations/investigation"
	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
	"github.com/openshift/configuration-anomaly-detection/pkg/ocm"
)

type Investigation struct{}

var ccamLimitedSupport = &ocm.LimitedSupportReason{
	Summary: "Restore missing cloud credentials",
	Details: "Your cluster requires you to take action because Red Hat is not able to access the infrastructure with the provided credentials. Please restore the credentials and permissions provided during install",
}

// Evaluate estimates if the awsError is a cluster credentials are missing error. If it determines that it is,
// the cluster is placed into limited support (if the cluster state allows it), otherwise an error is returned.
func (c *Investigation) Run(r investigation.ResourceBuilder) (investigation.InvestigationResult, error) {
	result := investigation.InvestigationResult{}
	// Apart from the defaults this investigation requires an AWS client which can fail to build
	resources, err := r.WithAwsClient().Build()
	logging.Info("Investigating possible missing cloud credentials...")
	if err != nil {
		if customerRemovedPermissions := customerRemovedPermissions(err.Error()); !customerRemovedPermissions {
			// We aren't able to jumpRole because of an error that is different than
			// a removed support role/policy or removed installer role/policy
			// This would normally be a backplane failure.
			return result, err
		}
		cluster := resources.Cluster
		ocmClient := resources.OcmClient
		pdClient := resources.PdClient

		// The jumprole failed because of a missing support role/policy:
		// we need to figure out if we cluster state allows us to set limited support
		// (the cluster is in a ready state, not uninstalling, installing, etc.)

		switch cluster.State() {
		case cmv1.ClusterStateReady:
			// Cluster is in functional sate but we can't jumprole to it: post limited support
			result.LimitedSupportSet.Performed = true
			result.LimitedSupportSet.Labels = []string{ccamLimitedSupport.Summary}
			err := ocmClient.PostLimitedSupportReason(cluster, ccamLimitedSupport)
			if err != nil {
				return result, fmt.Errorf("could not post limited support reason for %s: %w", cluster.Name(), err)
			}

			return result, pdClient.SilenceIncidentWithNote(fmt.Sprintf("Added the following Limited Support reason to cluster: %#v. Silencing alert.\n", ccamLimitedSupport))
		case cmv1.ClusterStateUninstalling:
			// A cluster in uninstalling state should not alert primary - we just skip this
			return result, pdClient.SilenceIncidentWithNote(fmt.Sprintf("Skipped adding limited support reason '%s': cluster is already uninstalling.", ccamLimitedSupport.Summary))
		default:
			// Anything else is an unknown state to us and/or requires investigation.
			// E.g. we land here if we run into a CPD alert where credentials were removed (installing state) and don't want to put it in LS yet.
			return result, pdClient.EscalateIncidentWithNote(fmt.Sprintf("Cluster has invalid cloud credentials (support role/policy is missing) and the cluster is in state '%s'. Please investigate.", cluster.State()))
		}
	}
	return result, nil
}

func (c *Investigation) Name() string {
	return "Cluster Credentials Are Missing (CCAM)"
}

func (c *Investigation) Description() string {
	return "Detects missing cluster credentials"
}

func (c *Investigation) ShouldInvestigateAlert(alert string) bool {
	return false
}

func (c *Investigation) IsExperimental() bool {
	return false
}

// userCausedErrors contains the list of backplane returned error strings that we map to
// customer modifications/role deletions.
var userCausedErrors = []string{
	// OCM can't access the installer role to determine the trust relationship on the support role,
	// therefore we don't know if it's the isolated access flow or the old flow, e.g.:
	// status is 404, identifier is '404', code is 'CLUSTERS-MGMT-404' and operation identifier is '<id>': Failed to find trusted relationship to support role 'RH-Technical-Support-Access'
	// See https://issues.redhat.com/browse/OSD-24270
	".*Failed to find trusted relationship to support role 'RH-Technical-Support-Access'.*",

	// OCM role can't access the installer role, this happens when customer deletes/modifies the trust policy of the installer role, e.g.:
	// status is 400, identifier is '400', code is 'CLUSTERS-MGMT-400' and operation identifier is '<id>': Please make sure IAM role 'arn:aws:iam::<ocm_role_aws_id>:role/ManagedOpenShift-Installer-Role' exists, and add 'arn:aws:iam::<id>:role/RH-Managed-OpenShift-Installer' to the trust policy on IAM role 'arn:aws:iam::<id>:role/ManagedOpenShift-Installer-Role': Failed to assume role: User: arn:aws:sts::<id>:assumed-role/RH-Managed-OpenShift-Installer/OCM is not authorized to perform: sts:AssumeRole on resource: arn:aws:iam::<customer_aws_id>:role/ManagedOpenShift-Installer-Role
	".*RH-Managed-OpenShift-Installer/OCM is not authorized to perform: sts:AssumeRole on resource.*",

	// Customer deleted the support role, e.g.:
	// status is 404, identifier is '404', code is 'CLUSTERS-MGMT-404' and operation identifier is '<id>': Support role, used with cluster '<cluster_id>', does not exist in the customer's AWS account
	".*Support role, used with cluster '[a-z0-9]{32}', does not exist in the customer's AWS account.*",

	// This error is the response from backplane calls when:
	// trust policy of ManagedOpenShift-Support-Role is changed
	".*could not assume support role in customer's account: .*AccessDenied:.*",

	// Customer removed the `GetRole` permission from the Installer role.
	// Failed to get role: User: arn:aws:sts::<id>:assumed-role/ManagedOpenShift-Installer-Role/OCM is not authorized to perform: iam:GetRole on resource: role ManagedOpenShift-Support-Role because no identity-based policy allows the iam:GetRole action
	".*is not authorized to perform: iam:GetRole on resource: role.*",
}

func customerRemovedPermissions(backplaneError string) bool {
	for _, str := range userCausedErrors {
		re, err := regexp.Compile(str)
		if err != nil {
			// This should never happen on production as we would run into it during unit tests
			log.Fatal("failed to regexp.Compile string in `userCausedErrors`")
		}

		if re.MatchString(backplaneError) {
			return true
		}
	}

	return false
}

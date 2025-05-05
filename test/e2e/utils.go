//go:build osde2e
// +build osde2e

package osde2etests

import (
	"fmt"

	"github.com/openshift/configuration-anomaly-detection/pkg/ocm"
)

// PostStoppedInfraLimitedSupport posts a limited support reason to OCM for a cluster
// with blocked egress
func PostStoppedInfraLimitedSupport(clusterID string, ocmCli ocm.Client) error {
	egressLS := ocm.LimitedSupportReason{
		Summary: "Cluster is in Limited Support due to unsupported cloud provider configuration",
		Details: "Your cluster requires you to take action. SRE has observed that there have been changes made to the network configuration which impacts normal working of the cluster, including lack of network egress to internet-based resources which are required for the cluster operation and support. Please revert changes, and refer to documentation regarding firewall requirements for PrivateLink clusters: https://access.redhat.com/documentation/en-us/red_hat_openshift_service_on_aws/4/html/prepare_your_environment/rosa-sts-aws-prereqs#osd-aws-privatelink-firewall-prerequisites_rosa-sts-aws-prereqs#",
	}

	err := ocmCli.PostLimitedSupportReason(&egressLS, clusterID)
	if err != nil {
		return fmt.Errorf("failed sending service log: %w", err)
	}
	return nil
}

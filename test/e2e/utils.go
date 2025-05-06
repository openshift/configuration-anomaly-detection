//go:build osde2e
// +build osde2e

package osde2etests

import (
	"fmt"

	cmv1 "github.com/openshift-online/ocm-sdk-go/clustersmgmt/v1"
	servicelogsv1 "github.com/openshift-online/ocm-sdk-go/servicelogs/v1"
	"github.com/openshift/configuration-anomaly-detection/pkg/ocm"
	ocme2e "github.com/openshift/osde2e-common/pkg/clients/ocm"
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

func GetLimitedSupportReasons(ocme2eCli *ocme2e.Client, clusterID string) (*cmv1.LimitedSupportReasonsListResponse, error) {

	lsResponse, err := ocme2eCli.ClustersMgmt().V1().Clusters().Cluster(clusterID).LimitedSupportReasons().List().Send()

	if err != nil {
		return nil, fmt.Errorf("failed sending service log: %w", err)
	}
	return lsResponse, nil
}

func GetServiceLogs(ocmCli ocm.Client, cluster *cmv1.Cluster) (*servicelogsv1.ClusterLogsUUIDListResponse, error) {
	filter := "log_type='cluster-state-updates'"
	clusterLogsUUIDListResponse, err := ocmCli.GetServiceLog(cluster, filter)
	if err != nil {
		return nil, fmt.Errorf("Failed to get service log: %w", err)
	}
	return clusterLogsUUIDListResponse, nil
}

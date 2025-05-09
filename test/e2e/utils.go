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

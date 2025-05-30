//go:build osde2e
// +build osde2e

package utils

import (
	"fmt"

	cmv1 "github.com/openshift-online/ocm-sdk-go/clustersmgmt/v1"
	servicelogsv1 "github.com/openshift-online/ocm-sdk-go/servicelogs/v1"
	"github.com/openshift/configuration-anomaly-detection/pkg/ocm"
	ocme2e "github.com/openshift/osde2e-common/pkg/clients/ocm"
	"k8s.io/client-go/tools/clientcmd"
	pclient "sigs.k8s.io/controller-runtime/pkg/client"
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

func CreateClientFromKubeConfig(kubeConfigPath string) (pclient.Client, error) {
	// Load kubeconfig file and create a client
	cfg, err := clientcmd.BuildConfigFromFlags("", kubeConfigPath)
	if err != nil {
		return nil, fmt.Errorf("failed to build kubeconfig: %v", err)
	}
	cl, err := pclient.New(cfg, pclient.Options{})
	if err != nil {
		return nil, fmt.Errorf("failed to create Kubernetes client: %v", err)
	}
	return cl, nil
}

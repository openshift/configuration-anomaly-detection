//go:build osde2e
// +build osde2e

package utils

import (
	"context"
	"fmt"

	cmv1 "github.com/openshift-online/ocm-sdk-go/clustersmgmt/v1"
	servicelogsv1 "github.com/openshift-online/ocm-sdk-go/servicelogs/v1"
	"github.com/openshift/configuration-anomaly-detection/pkg/ocm"
	ocme2e "github.com/openshift/osde2e-common/pkg/clients/ocm"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
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

// FetchConfigMap fetches the ConfigMap from Kubernetes.
func FetchConfigMap(kubeClient kubernetes.Interface, namespace, configMapName string, ctx context.Context) (*corev1.ConfigMap, error) {
	return kubeClient.CoreV1().ConfigMaps(namespace).Get(ctx, configMapName, metav1.GetOptions{})
}

// UpdateConfigMap applies the provided data to the ConfigMap.
func UpdateConfigMap(kubeClient kubernetes.Interface, namespace, configMapName string, updatedData map[string]string, ctx context.Context) error {
	cm, err := FetchConfigMap(kubeClient, namespace, configMapName, ctx)
	if err != nil {
		return fmt.Errorf("failed to fetch ConfigMap %s/%s: %w", namespace, configMapName, err)
	}
	if cm.Data == nil {
		cm.Data = make(map[string]string)
	}
	for k, v := range updatedData {
		cm.Data[k] = v
	}
	_, err = kubeClient.CoreV1().ConfigMaps(namespace).Update(ctx, cm, metav1.UpdateOptions{})
	return err
}

package networkverifier

import (
	"encoding/json"
	"fmt"

	v1 "github.com/openshift-online/ocm-sdk-go/clustersmgmt/v1"
	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
	"github.com/openshift/configuration-anomaly-detection/pkg/ocm"
	hivev1 "github.com/openshift/hive/apis/hive/v1"
	corev1 "k8s.io/api/core/v1"
)

const caBundleConfigMapKey = "ca-bundle.crt"

// GetAdditionalTrustBundle retrieves the additional CA trust bundle for a
// cluster from its Hive SyncSets via the OCM cluster resources API.
func GetAdditionalTrustBundle(ocmClient ocm.Client, cluster *v1.Cluster) (string, error) {
	if cluster == nil || cluster.AdditionalTrustBundle() == "" {
		return "", nil
	}

	logging.Infof("Cluster has an additional trust bundle configured, retrieving from Hive...")

	syncSets, err := ocmClient.GetSyncSets(cluster.ID())
	if err != nil {
		return "", fmt.Errorf("failed to get SyncSets: %w", err)
	}

	for i := range syncSets {
		if syncSets[i].Name == "proxy" {
			caBundle, err := getCaBundleFromSyncSet(&syncSets[i])
			if err != nil {
				return "", fmt.Errorf("failed to extract CA bundle from SyncSet: %w", err)
			}
			logging.Infof("Successfully retrieved additional trust bundle from Hive")
			return caBundle, nil
		}
	}

	return "", fmt.Errorf("proxy SyncSet not found in cluster resources")
}

// getCaBundleFromSyncSet extracts the CA trust bundle from a Hive SyncSet's embedded ConfigMap resources.
func getCaBundleFromSyncSet(ss *hivev1.SyncSet) (string, error) {
	for i := range ss.Spec.Resources {
		cm := &corev1.ConfigMap{}
		if err := json.Unmarshal(ss.Spec.Resources[i].Raw, cm); err != nil {
			logging.Debugf("Skipping SyncSet resource %d: failed to unmarshal as ConfigMap: %v", i, err)
			continue
		}

		if bundle, ok := cm.Data[caBundleConfigMapKey]; ok {
			return bundle, nil
		}
	}

	return "", fmt.Errorf("ca-bundle.crt ConfigMap not found in SyncSet %s/%s", ss.Namespace, ss.Name)
}

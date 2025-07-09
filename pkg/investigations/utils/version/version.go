package version

import (
	"context"
	"fmt"

	configv1 "github.com/openshift/api/config/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func GetClusterVersion(k8scli client.Client) (*configv1.ClusterVersion, error) {
	clusterVersion := &configv1.ClusterVersion{}
	err := k8scli.Get(context.TODO(), client.ObjectKey{Name: "version"}, clusterVersion)
	if err != nil {
		return nil, fmt.Errorf("failed to get ClusterVersion: %w", err)
	}
	return clusterVersion, nil
}

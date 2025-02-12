package k8sclient

import (
	"fmt"
	"os"

	configv1 "github.com/openshift/api/config/v1"
	"github.com/openshift/backplane-cli/pkg/cli/config"
	bpremediation "github.com/openshift/backplane-cli/pkg/remediation"
	"github.com/openshift/configuration-anomaly-detection/pkg/ocm"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func New(clusterID string, ocmClient ocm.Client, remediation string) (client.Client, error) {
	backplaneURL := os.Getenv("BACKPLANE_URL")
	if backplaneURL == "" {
		return nil, fmt.Errorf("could not create new k8sclient: missing environment variable BACKPLANE_URL")
	}

	cfg, err := bpremediation.CreateRemediationWithConn(config.BackplaneConfiguration{URL: backplaneURL}, ocmClient.GetConnection(), clusterID, remediation)
	if err != nil {
		return nil, err
	}

	scheme, err := initScheme()
	if err != nil {
		return nil, err
	}

	return client.New(cfg, client.Options{Scheme: scheme})
}

func Cleanup(clusterID string, ocmClient ocm.Client, remediation string) error {
	backplaneURL := os.Getenv("BACKPLANE_URL")
	if backplaneURL == "" {
		return fmt.Errorf("could not create new k8sclient: missing environment variable BACKPLANE_URL")
	}
	return bpremediation.DeleteRemediationWithConn(config.BackplaneConfiguration{URL: backplaneURL}, ocmClient.GetConnection(), clusterID, remediation)
}

// Initialize all apis we need in CAD
func initScheme() (*runtime.Scheme, error) {
	scheme := runtime.NewScheme()

	// Add corev1 to scheme for core k8s
	if err := corev1.AddToScheme(scheme); err != nil {
		return nil, fmt.Errorf("unable to add corev1 scheme: %w", err)
	}

	// Add config.openshift.io/v1 to scheme for clusteroperator
	if err := configv1.Install(scheme); err != nil {
		return nil, fmt.Errorf("unable to add openshift/api/config scheme: %w", err)
	}
	return scheme, nil
}

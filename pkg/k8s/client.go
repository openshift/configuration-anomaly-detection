package k8sclient

import (
	"fmt"
	"os"

	"github.com/openshift/backplane-cli/pkg/cli/config"
	bpremediation "github.com/openshift/backplane-cli/pkg/remediation"
	"github.com/openshift/configuration-anomaly-detection/pkg/ocm"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// New returns a Kubernetes client for the given cluster scoped to a given remediation's permissions.
func New(clusterID string, ocmClient ocm.Client, remediation string) (client.Client, error) {
	backplaneURL := os.Getenv("BACKPLANE_URL")
	if backplaneURL == "" {
		return nil, fmt.Errorf("could not create new k8sclient: missing environment variable BACKPLANE_URL")
	}

	cfg, err := bpremediation.CreateRemediationWithConn(
		config.BackplaneConfiguration{URL: backplaneURL},
		ocmClient.GetConnection(),
		clusterID,
		remediation,
	)
	if err != nil {
		if isAPIServerUnavailable(err) {
			return nil, fmt.Errorf("%w: %w", ErrAPIServerUnavailable, err)
		}
		return nil, err
	}

	scheme, err := initScheme()
	if err != nil {
		return nil, err
	}

	return client.New(cfg, client.Options{Scheme: scheme})
}

// Cleanup removes the remediation created for the cluster.
func Cleanup(clusterID string, ocmClient ocm.Client, remediation string) error {
	backplaneURL := os.Getenv("BACKPLANE_URL")
	if backplaneURL == "" {
		return fmt.Errorf("could not clean up k8sclient: missing environment variable BACKPLANE_URL")
	}

	return bpremediation.DeleteRemediationWithConn(
		config.BackplaneConfiguration{URL: backplaneURL},
		ocmClient.GetConnection(),
		clusterID,
		remediation,
	)
}

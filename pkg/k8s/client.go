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
	k8scli "sigs.k8s.io/controller-runtime/pkg/client"
)

type Client struct {
	k8scli.Client
	clusterID   string
	ocmClient   ocm.Client
	remediation string
}

func (c *Client) Close() error {
	backplaneURL := os.Getenv("BACKPLANE_URL")
	if backplaneURL == "" {
		return fmt.Errorf("could not create new k8sclient: missing environment variable BACKPLANE_URL")
	}
	return bpremediation.DeleteRemediationWithConn(config.BackplaneConfiguration{URL: backplaneURL}, c.ocmClient.GetConnection(), c.clusterID, c.remediation)
}

func New(clusterID string, ocmClient ocm.Client, remediation string) (*Client, error) {
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

	k8scli, err := k8scli.New(cfg, k8scli.Options{Scheme: scheme})
	if err != nil {
		return nil, err
	}

	return &Client{Client: k8scli, clusterID: clusterID, ocmClient: ocmClient, remediation: remediation}, nil
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

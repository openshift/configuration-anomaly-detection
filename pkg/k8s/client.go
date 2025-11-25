// Package k8sclient handles creation and cleanup of backplane remediations meaning a kube-apiserver access to clusters with RBAC defined in an investigations metadata
package k8sclient

import (
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type Client interface {
	client.Client
}

type clientImpl struct {
	client.Client
	restConfig *rest.Config
}

// New returns a Kubernetes client for the given cluster scoped to a given remediation's permissions.
func New(cfg *rest.Config) (k8scli Client, err error) {
	scheme, err := initScheme()
	if err != nil {
		return nil, err
	}

	decoratedClient, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		return nil, err
	}

	return clientImpl{
		Client:     decoratedClient,
		restConfig: cfg,
	}, nil
}

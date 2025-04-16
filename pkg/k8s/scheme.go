package k8sclient

import (
	"fmt"

	configv1 "github.com/openshift/api/config/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// initScheme initializes the runtime scheme with required APIs.
func initScheme() (*runtime.Scheme, error) {
	scheme := runtime.NewScheme()

	if err := corev1.AddToScheme(scheme); err != nil {
		return nil, fmt.Errorf("unable to add corev1 scheme: %w", err)
	}

	if err := configv1.Install(scheme); err != nil {
		return nil, fmt.Errorf("unable to add config.openshift.io/v1 scheme: %w", err)
	}

	return scheme, nil
}

package k8sclient

import (
	"fmt"

	configv1 "github.com/openshift/api/config/v1"
	machinev1beta1 "github.com/openshift/api/machine/v1beta1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// initScheme initializes the runtime scheme with required APIs.
func initScheme() (*runtime.Scheme, error) {
	scheme := runtime.NewScheme()

	if err := corev1.AddToScheme(scheme); err != nil {
		return nil, fmt.Errorf("unable to add corev1 scheme: %w", err)
	}

	if err := batchv1.AddToScheme(scheme); err != nil {
		return nil, fmt.Errorf("unable to add batchv1 scheme: %w", err)
	}

	if err := configv1.Install(scheme); err != nil {
		return nil, fmt.Errorf("unable to add config.openshift.io/v1 scheme: %w", err)
	}

	if err := machinev1beta1.AddToScheme(scheme); err != nil {
		return nil, fmt.Errorf("unable to add machine.openshift.io/v1beta1 scheme: %w", err)
	}

	return scheme, nil
}

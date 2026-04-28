package k8sclient

import (
	"fmt"

	configv1 "github.com/openshift/api/config/v1"
	machinev1beta1 "github.com/openshift/api/machine/v1beta1"
	mcfgv1 "github.com/openshift/api/machineconfiguration/v1"
	batchv1 "k8s.io/api/batch/v1"
	certsv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
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

	if err := mcfgv1.Install(scheme); err != nil {
		return nil, fmt.Errorf("unable to add machineconfiguration.openshift.io/v1 scheme: %w", err)
	}

	if err := certsv1.AddToScheme(scheme); err != nil {
		return nil, fmt.Errorf("unable to add certificates.k8s.io/v1 scheme: %w", err)
	}

	if err := policyv1.AddToScheme(scheme); err != nil {
		return nil, fmt.Errorf("unable to add policy/v1 scheme: %w", err)
	}

	return scheme, nil
}

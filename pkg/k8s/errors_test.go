package k8sclient

import (
	"errors"
	"testing"
)

func TestMatchError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected error
	}{
		{
			name: "Cluster down message present",
			err: errors.New(`Error: Internal error occurred: failed calling webhook "namespace.operator.tekton.dev": failed to call webhook: Post "https://tekton-operator-proxy-webhook.openshift-pipelines.svc:443/namespace-validation?timeout=10s": context deadline exceeded
	The cluster could be down or under heavy load
	`),
			expected: ErrAPIServerUnavailable,
		},
		{
			name:     "Cannot access infra message present",
			err:      errors.New("cannot create remediations on hive, management or service clusters"),
			expected: ErrCannotAccessInfra,
		},
		{
			name:     "Unrelated error message",
			err:      errors.New("some other error occurred"),
			expected: errors.New("some other error occurred"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := matchError(tt.err)
			if !errors.Is(result, tt.expected) && result.Error() != tt.expected.Error() {
				t.Errorf("For test '%s', expected %v, got %v", tt.name, tt.expected, result)
			}
		})
	}
}

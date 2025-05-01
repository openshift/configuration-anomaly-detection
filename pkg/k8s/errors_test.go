package k8sclient

import (
	"errors"
	"testing"
)

func TestIsAPIServerUnavailable(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name: "Cluster down message present",
			err: errors.New(`Error: Internal error occurred: failed calling webhook "namespace.operator.tekton.dev": failed to call webhook: Post "https://tekton-operator-proxy-webhook.openshift-pipelines.svc:443/namespace-validation?timeout=10s": context deadline exceeded
	The cluster could be down or under heavy load
	`),
			expected: true,
		},
		{
			name:     "Unrelated error message",
			err:      errors.New("some other error occurred"),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err == nil && isAPIServerUnavailable(tt.err) {
				t.Errorf("Expected false for nil error, but got true")
			} else if tt.err != nil && isAPIServerUnavailable(tt.err) != tt.expected {
				t.Errorf("For test '%s', expected %v, got %v", tt.name, tt.expected, !tt.expected)
			}
		})
	}
}

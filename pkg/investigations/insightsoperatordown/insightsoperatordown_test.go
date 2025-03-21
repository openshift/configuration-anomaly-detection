package insightsoperatordown

import (
	"testing"

	configv1 "github.com/openshift/api/config/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestIsOCPBUG22226(t *testing.T) {
	tests := []struct {
		name     string
		co       configv1.ClusterOperator
		expected bool
	}{
		{
			name: "SCA certs pull failure detected",
			co: configv1.ClusterOperator{
				ObjectMeta: v1.ObjectMeta{Name: "insights"},
				Status: configv1.ClusterOperatorStatus{
					Conditions: []configv1.ClusterOperatorStatusCondition{
						{Type: "SCAAvailable", Message: "Failed to pull SCA certs"},
					},
				},
			},
			expected: true,
		},
		{
			name: "No SCA certs pull failure",
			co: configv1.ClusterOperator{
				ObjectMeta: v1.ObjectMeta{Name: "insights"},
				Status: configv1.ClusterOperatorStatus{
					Conditions: []configv1.ClusterOperatorStatusCondition{
						{Type: "SCAAvailable", Message: "All systems operational"},
					},
				},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if isOCPBUG22226(&tt.co) != tt.expected {
				t.Fatalf("expected %v, got %v", tt.expected, !tt.expected)
			}
		})
	}
}

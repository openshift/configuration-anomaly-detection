package insightsoperatordown

import (
	"testing"

	configv1 "github.com/openshift/api/config/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// var (
// 	statusConditionAvailable                 = configv1.ClusterOperatorStatusCondition{Type: "Available", Status: "True"}
// 	statusConditionSCAAvailable              = configv1.ClusterOperatorStatusCondition{Type: "SCAAvailable", Status: "False", Message: `some unrelated issue`}
// 	statusConditionSCAAvailableSymptomsMatch = configv1.ClusterOperatorStatusCondition{Type: "SCAAvailable", Status: "False", Message: `Failed to pull SCA certs from https://api.openshift.com/api/accounts_mgmt/v1/certificates: OCM API https://api.openshift.com/api/accounts_mgmt/v1/certificates returned HTTP 500: {"code":"ACCT-MGMT-9","href":"/api/accounts_mgmt/v1/errors/9","id":"9","kind":"Error","operation_id":"123","reason":"400 Bad Request"}`}
// )
//
// func TestSymptomMatches(t *testing.T) {
// 	co := configv1.ClusterOperator{
// 		ObjectMeta: v1.ObjectMeta{Name: "insights"},
// 		Status: configv1.ClusterOperatorStatus{
// 			Conditions: []configv1.ClusterOperatorStatusCondition{statusConditionSCAAvailableSymptomsMatch, statusConditionAvailable},
// 		},
// 	}
// 	if !isOCPBUG22226(&co) {
// 		t.Fatal("expected symptoms to match")
// 	}
// }
//
// func TestSymptomNoMatch(t *testing.T) {
// 	co := configv1.ClusterOperator{
// 		ObjectMeta: v1.ObjectMeta{Name: "insights"},
// 		Status: configv1.ClusterOperatorStatus{
// 			Conditions: []configv1.ClusterOperatorStatusCondition{statusConditionAvailable, statusConditionSCAAvailable},
// 		},
// 	}
// 	if isOCPBUG22226(&co) {
// 		t.Fatal("expected symptoms to not match")
// 	}
// }

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
						{Message: "Failed to pull SCA certs"},
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
						{Message: "All systems operational"},
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

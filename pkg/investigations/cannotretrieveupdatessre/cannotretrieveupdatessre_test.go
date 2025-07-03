package cannotretrieveupdatessre

import (
	"testing"

	configv1 "github.com/openshift/api/config/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestGetUpdateRetrievalFailures(t *testing.T) {
	tests := []struct {
		name           string
		clusterVersion *configv1.ClusterVersion
		expectedNote   string
	}{
		{
			name: "RemoteFailed condition",
			clusterVersion: &configv1.ClusterVersion{
				ObjectMeta: metav1.ObjectMeta{
					Name: "version",
				},
				Spec: configv1.ClusterVersionSpec{
					Channel: "stable-4.18",
				},
				Status: configv1.ClusterVersionStatus{
					Conditions: []configv1.ClusterOperatorStatusCondition{
						{
							Type:    "RetrievedUpdates",
							Status:  configv1.ConditionFalse,
							Reason:  "RemoteFailed",
							Message: "Unable to retrieve available updates",
						},
					},
				},
			},
			expectedNote: "(Reason: RemoteFailed). Unable to retrieve available updates",
		},
		{
			name: "VersionNotFound condition",
			clusterVersion: &configv1.ClusterVersion{
				ObjectMeta: metav1.ObjectMeta{
					Name: "version",
				},
				Spec: configv1.ClusterVersionSpec{
					Channel: "stable-4.18",
				},
				Status: configv1.ClusterVersionStatus{
					Conditions: []configv1.ClusterOperatorStatusCondition{
						{
							Type:    "RetrievedUpdates",
							Status:  configv1.ConditionFalse,
							Reason:  "VersionNotFound",
							Message: "Unable to retrieve available updates",
						},
					},
				},
			},
			expectedNote: "(Reason: VersionNotFound). Unable to retrieve available updates",
		},
		{
			name: "Happy path",
			clusterVersion: &configv1.ClusterVersion{
				ObjectMeta: metav1.ObjectMeta{
					Name: "version",
				},
				Spec: configv1.ClusterVersionSpec{
					Channel: "stable-4.18",
				},
				Status: configv1.ClusterVersionStatus{
					Conditions: []configv1.ClusterOperatorStatusCondition{
						{
							Type:    "RetrievedUpdates",
							Status:  configv1.ConditionTrue,
							Reason:  "UpdatesRetrieved",
							Message: "Available updates retrieved successfully",
						},
					},
				},
			},
			expectedNote: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reason := getUpdateRetrievalFailures(tt.clusterVersion)
			if reason != tt.expectedNote {
				t.Errorf("Expected note %q, got %q", tt.expectedNote, reason)
			}
		})
	}
}

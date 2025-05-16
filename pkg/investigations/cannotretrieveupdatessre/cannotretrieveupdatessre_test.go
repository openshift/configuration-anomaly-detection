package cannotretrieveupdatessre

import (
	"strings"
	"testing"

	configv1 "github.com/openshift/api/config/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func newFakeClient(objs ...client.Object) (client.Client, error) {
	s := scheme.Scheme
	err := configv1.AddToScheme(s)
	if err != nil {
		return nil, err
	}

	client := fake.NewClientBuilder().WithScheme(s).WithObjects(objs...).Build()
	return client, nil
}

func TestCheckClusterVersion(t *testing.T) {
	tests := []struct {
		name            string
		clusterVersion  *configv1.ClusterVersion
		expectedVersion string
		expectError     bool
		expectedNote    string
	}{
		{
			name: "RemoteFailed condition",
			clusterVersion: &configv1.ClusterVersion{
				ObjectMeta: metav1.ObjectMeta{
					Name: "version",
				},
				Spec: configv1.ClusterVersionSpec{
					Channel:   "stable-4.18-test",
					ClusterID: "d1ba89f3-fd3e-48d2-91c6-test",
				},
				Status: configv1.ClusterVersionStatus{
					Desired: configv1.Release{Version: "4.18.10"},
					Conditions: []configv1.ClusterOperatorStatusCondition{
						{
							Type:    "RetrievedUpdates",
							Status:  "False",
							Reason:  "RemoteFailed",
							Message: "Unable to retrieve available updates",
						},
					},
				},
			},
			expectedVersion: "",
			expectError:     true,
			expectedNote:    "ClusterVersion issue detected: Unable to retrieve available updates",
		},
		{
			name: "VersionNotFound condition",
			clusterVersion: &configv1.ClusterVersion{
				ObjectMeta: metav1.ObjectMeta{
					Name: "version",
				},
				Spec: configv1.ClusterVersionSpec{
					Channel:   "stable-4.18-test",
					ClusterID: "d1ba89f3-fd3e-48d2-91c6-test",
				},
				Status: configv1.ClusterVersionStatus{
					Desired: configv1.Release{Version: "4.18.10"},
					Conditions: []configv1.ClusterOperatorStatusCondition{
						{
							Type:    "RetrievedUpdates",
							Status:  "False",
							Reason:  "VersionNotFound",
							Message: "Unable to retrieve available updates: version 4.18.10 not found in channel stable-4.18-test",
						},
					},
				},
			},
			expectedVersion: "",
			expectError:     true,
			expectedNote:    "ClusterVersion issue detected: Unable to retrieve available updates: version 4.18.10 not found in channel stable-4.18-test.",
		},
		{
			name: "Happy path",
			clusterVersion: &configv1.ClusterVersion{
				ObjectMeta: metav1.ObjectMeta{
					Name: "version",
				},
				Spec: configv1.ClusterVersionSpec{
					Channel:   "stable-4.18",
					ClusterID: "d1ba89f3-fd3e-48d2-91c6-test",
				},
				Status: configv1.ClusterVersionStatus{
					Desired: configv1.Release{Version: "4.18.10"},
					Conditions: []configv1.ClusterOperatorStatusCondition{
						{
							Type:    "RetrievedUpdates",
							Status:  "True",
							Reason:  "UpdatesRetrieved",
							Message: "Available updates retrieved successfully",
						},
					},
				},
			},
			expectedVersion: "4.18.10",
			expectError:     false,
			expectedNote:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k8scli, err := newFakeClient(tt.clusterVersion)
			if err != nil {
				t.Fatalf("failed to create a fake client: %v", err)
			}
			version, note, err := checkClusterVersion(k8scli, "test-cluster")

			// Check version
			if version != tt.expectedVersion {
				t.Errorf("Expected version %q, got %q", tt.expectedVersion, version)
			}

			// Check note
			if !strings.HasPrefix(note, tt.expectedNote) {
				t.Errorf("Expected note to start with %q, got %q", tt.expectedNote, note)
			}

			// Check error
			if tt.expectError && err == nil {
				t.Errorf("Expected an error, got none")
			} else if !tt.expectError && err != nil {
				t.Errorf("Expected no error, got %v", err)
			}
		})
	}
}

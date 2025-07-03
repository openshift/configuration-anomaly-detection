package version

import (
	"strings"
	"testing"

	configv1 "github.com/openshift/api/config/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
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

func TestGetClusterVersion(t *testing.T) {
	tests := []struct {
		name            string
		clusterVersion  *configv1.ClusterVersion
		expectedVersion string
		expectError     bool
	}{
		{
			name: "Valid ClusterVersion",
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
				},
			},
			expectedVersion: "4.18.10",
			expectError:     false,
		},
		{
			name:            "ClusterVersion Not Found",
			clusterVersion:  nil,
			expectedVersion: "",
			expectError:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var k8scli client.Client
			var err error
			if tt.clusterVersion != nil {
				k8scli, err = newFakeClient(tt.clusterVersion)
			} else {
				k8scli, err = newFakeClient()
			}
			if err != nil {
				t.Fatalf("failed to create a fake client: %v", err)
			}

			got, err := GetClusterVersion(k8scli)

			if tt.expectError && err == nil {
				t.Errorf("Expected an error, got none")
			} else if !tt.expectError && err != nil {
				t.Errorf("Expected no error, got %v", err)
			}

			if !tt.expectError {
				if got.Status.Desired.Version != tt.expectedVersion {
					t.Errorf("Expected version %q, got %q", tt.expectedVersion, got.Status.Desired.Version)
				}
			} else {
				if got != nil {
					t.Errorf("Expected nil ClusterVersion error, got %v", got)
				}
				if err != nil && !apierrors.IsNotFound(err) && !strings.Contains(err.Error(), "failed to get ClusterVersion") {
					t.Errorf("Expected error to be related about failed to get the ClusterVersion, got %v", err)
				}
			}
		})
	}
}

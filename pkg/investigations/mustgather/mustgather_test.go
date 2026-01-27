package mustgather

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// TestInvestigation_Run tests the Run method
func TestInvestigation_Run(t *testing.T) {
	t.Skip("Not tested - Run functions similar to a main function and calls mostly tested subfunctions. Refer to testing/README.md")
}

func TestWaitForMustGatherNamespaceDeletion(t *testing.T) {
	// Use shorter timeouts for tests
	testTimeout := 2 * time.Second
	testPollInterval := 100 * time.Millisecond

	tests := []struct {
		name          string
		namespaces    []*corev1.Namespace
		expectError   bool
		errorContains string
	}{
		{
			name: "no must-gather namespace exists - other namespaces present",
			namespaces: []*corev1.Namespace{
				{ObjectMeta: metav1.ObjectMeta{Name: "default"}},
				{ObjectMeta: metav1.ObjectMeta{Name: "kube-system"}},
				{ObjectMeta: metav1.ObjectMeta{Name: "openshift-monitoring"}},
			},
			expectError: false,
		},
		{
			name: "operator namespace is ignored - should not wait",
			namespaces: []*corev1.Namespace{
				{ObjectMeta: metav1.ObjectMeta{Name: "openshift-must-gather-operator"}},
				{ObjectMeta: metav1.ObjectMeta{Name: "default"}},
			},
			expectError: false,
		},
		{
			name: "must-gather namespace exists and times out",
			namespaces: []*corev1.Namespace{
				{ObjectMeta: metav1.ObjectMeta{Name: "openshift-must-gather-abc123"}},
			},
			expectError:   true,
			errorContains: "timeout waiting for must-gather namespace to be deleted",
		},
		{
			name: "temporary namespace exists with operator namespace - should wait",
			namespaces: []*corev1.Namespace{
				{ObjectMeta: metav1.ObjectMeta{Name: "openshift-must-gather-operator"}},
				{ObjectMeta: metav1.ObjectMeta{Name: "openshift-must-gather-xyz789"}},
			},
			expectError:   true,
			errorContains: "timeout waiting for must-gather namespace to be deleted",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fakeClient := newFakeClient(t, tt.namespaces...)

			err := waitForMustGatherNamespaceDeletion(context.Background(), fakeClient, testTimeout, testPollInterval)

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
					return
				}
				if tt.errorContains != "" && !strings.Contains(err.Error(), tt.errorContains) {
					t.Errorf("expected error containing %q but got: %v", tt.errorContains, err)
				}
			} else if err != nil {
				t.Errorf("expected no error but got: %v", err)
			}
		})
	}
}

func TestWaitForMustGatherNamespaceDeletion_NamespaceDeletedDuringWait(t *testing.T) {
	testTimeout := 5 * time.Second
	testPollInterval := 100 * time.Millisecond

	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: "openshift-must-gather-test123"},
	}

	// Create fake client with the namespace
	fakeClient := newFakeClient(t, ns)

	// Start a goroutine that deletes the namespace after a short delay
	go func() {
		time.Sleep(500 * time.Millisecond)
		_ = fakeClient.Delete(context.Background(), ns)
	}()

	// Run the function - should wait and then succeed when namespace is deleted
	err := waitForMustGatherNamespaceDeletion(context.Background(), fakeClient, testTimeout, testPollInterval)
	if err != nil {
		t.Errorf("expected no error after namespace deletion but got: %v", err)
	}
}

func TestGetAcmHcpMustGatherImage(t *testing.T) {
	tests := []struct {
		name     string
		envValue string
		expected string
	}{
		{
			name:     "default image when env var not set",
			envValue: "",
			expected: defaultAcmHcpMustGatherImage,
		},
		{
			name:     "custom image when env var is set",
			envValue: "custom.registry.io/my-image:v1.0",
			expected: "custom.registry.io/my-image:v1.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Save original env var and restore after test
			originalEnv := os.Getenv("CAD_ACM_HCP_MUST_GATHER_IMAGE")
			defer func() {
				if originalEnv != "" {
					_ = os.Setenv("CAD_ACM_HCP_MUST_GATHER_IMAGE", originalEnv)
				} else {
					_ = os.Unsetenv("CAD_ACM_HCP_MUST_GATHER_IMAGE")
				}
			}()

			// Set env var for test
			if tt.envValue != "" {
				_ = os.Setenv("CAD_ACM_HCP_MUST_GATHER_IMAGE", tt.envValue)
			} else {
				_ = os.Unsetenv("CAD_ACM_HCP_MUST_GATHER_IMAGE")
			}

			// Run test
			got := getAcmHcpMustGatherImage()
			if got != tt.expected {
				t.Errorf("getAcmHcpMustGatherImage() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// newFakeClient creates a fake Kubernetes client with the given objects
func newFakeClient(t *testing.T, namespaces ...*corev1.Namespace) client.Client {
	t.Helper()

	s := scheme.Scheme

	// Convert namespaces to client.Object slice
	objs := make([]client.Object, len(namespaces))
	for i, ns := range namespaces {
		objs[i] = ns
	}

	return fake.NewClientBuilder().WithScheme(s).WithObjects(objs...).Build()
}

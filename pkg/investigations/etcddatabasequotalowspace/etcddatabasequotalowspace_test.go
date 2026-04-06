package etcddatabasequotalowspace

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	cmv1 "github.com/openshift-online/ocm-sdk-go/clustersmgmt/v1"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/investigation"
	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
	"github.com/openshift/configuration-anomaly-detection/pkg/notewriter"
	"github.com/openshift/configuration-anomaly-detection/pkg/rhobs"
	rhobsmock "github.com/openshift/configuration-anomaly-detection/pkg/rhobs/mock"
)

func TestIsHCPCluster(t *testing.T) {
	tests := []struct {
		name        string
		cluster     *cmv1.Cluster
		expectedHCP bool
		expectError bool
	}{
		{
			name: "HCP cluster with hypershift enabled",
			cluster: func() *cmv1.Cluster {
				cluster, _ := cmv1.NewCluster().
					Hypershift(cmv1.NewHypershift().Enabled(true)).
					Build()
				return cluster
			}(),
			expectedHCP: true,
			expectError: false,
		},
		{
			name: "Non-HCP cluster with hypershift disabled",
			cluster: func() *cmv1.Cluster {
				cluster, _ := cmv1.NewCluster().
					Hypershift(cmv1.NewHypershift().Enabled(false)).
					Build()
				return cluster
			}(),
			expectedHCP: false,
			expectError: false,
		},
		{
			name: "Non-HCP cluster without hypershift configuration",
			cluster: func() *cmv1.Cluster {
				cluster, _ := cmv1.NewCluster().Build()
				return cluster
			}(),
			expectedHCP: false,
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isHCP, err := isHCPCluster(tt.cluster)

			if tt.expectError {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tt.expectedHCP, isHCP)
		})
	}
}

func TestInvestigationMethods(t *testing.T) {
	inv := &Investigation{}

	t.Run("Name", func(t *testing.T) {
		expected := "etcddatabasequotalowspace"
		got := inv.Name()
		assert.Equal(t, expected, got)
	})

	t.Run("AlertTitle", func(t *testing.T) {
		expected := "etcdDatabaseQuotaLowSpace"
		got := inv.AlertTitle()
		assert.Equal(t, expected, got)
	})

	t.Run("Description", func(t *testing.T) {
		expected := "Takes etcd snapshots and performs database analysis for etcd quota issues"
		got := inv.Description()
		assert.Equal(t, expected, got)
	})
}

func TestSnapshotResult(t *testing.T) {
	result := &SnapshotResult{
		PodName:      "etcd-test-pod",
		NodeName:     "test-node",
		SnapshotPath: "/var/lib/etcd/etcd.snapshot",
		SnapshotSize: 100000000, // 100 MB
		Namespace:    "openshift-etcd",
	}

	assert.Equal(t, "etcd-test-pod", result.PodName)
	assert.Equal(t, "test-node", result.NodeName)
	assert.Equal(t, "/var/lib/etcd/etcd.snapshot", result.SnapshotPath)
	assert.Equal(t, int64(100000000), result.SnapshotSize)
	assert.Equal(t, "openshift-etcd", result.Namespace)
}

func TestExtractTimestampFromPath(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected string
	}{
		{
			name:     "standard snapshot path",
			path:     "/var/lib/etcd/etcd_20231224_143012.snapshot",
			expected: "20231224_143012",
		},
		{
			name:     "different timestamp format",
			path:     "/var/lib/etcd/etcd_20250101_000000.snapshot",
			expected: "20250101_000000",
		},
		{
			name:     "path without directory",
			path:     "etcd_20231224_143012.snapshot",
			expected: "20231224_143012",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractTimestampFromPath(tt.path)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGetEtcdctlContainerImage(t *testing.T) {
	tests := []struct {
		name          string
		pod           *corev1.Pod
		expectedImage string
		expectError   bool
	}{
		{
			name: "pod with reset-member init container",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name: "etcd-0",
				},
				Spec: corev1.PodSpec{
					InitContainers: []corev1.Container{
						{
							Name:  "reset-member",
							Image: "quay.io/openshift/etcd:v4.15",
						},
					},
				},
			},
			expectedImage: "quay.io/openshift/etcd:v4.15",
			expectError:   false,
		},
		{
			name: "pod without reset-member init container",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name: "etcd-2",
				},
				Spec: corev1.PodSpec{
					InitContainers: []corev1.Container{
						{
							Name:  "other-init",
							Image: "quay.io/openshift/other:v4.15",
						},
					},
				},
			},
			expectError: true,
		},
		{
			name: "pod with no init containers",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name: "etcd-3",
				},
				Spec: corev1.PodSpec{
					InitContainers: []corev1.Container{},
				},
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			image, err := getEtcdctlContainerImage(tt.pod)

			if tt.expectError {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tt.expectedImage, image)
		})
	}
}

func TestRunHCPEtcdAnalysis_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	cluster, _ := cmv1.NewCluster().
		ID("test-cluster-id").
		ExternalID("external-cluster-id").
		Hypershift(cmv1.NewHypershift().Enabled(true)).
		Build()

	etcdPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "etcd-0",
			Namespace: "ocm-test-namespace",
			Labels: map[string]string{
				"k8s-app": "etcd",
			},
		},
		Spec: corev1.PodSpec{
			NodeName: "test-node",
			InitContainers: []corev1.Container{
				{
					Name:  "reset-member",
					Image: "quay.io/openshift/etcd:v4.15",
				},
			},
		},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
		},
	}

	fakeK8s := fake.NewClientBuilder().
		WithObjects(etcdPod).
		WithStatusSubresource(&batchv1.Job{}).
		Build()

	ctx := t.Context()

	go func() {
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				jobList := &batchv1.JobList{}
				if err := fakeK8s.List(ctx, jobList, client.InNamespace("ocm-test-namespace")); err != nil {
					continue
				}

				for i := range jobList.Items {
					job := &jobList.Items[i]
					if job.Status.Succeeded == 0 {
						// Mark job as succeeded
						job.Status.Succeeded = 1
						_ = fakeK8s.Status().Update(ctx, job)
					}
				}
			}
		}
	}()

	// Create mock RHOBS client
	mockRHOBSClient := rhobsmock.NewMockClient(ctrl)

	// Mock log entries to return
	mockTimestamp := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
	mockLogResult := &rhobs.LogQueryResult{
		Entries: []rhobs.LogEntry{
			{Timestamp: mockTimestamp, Line: "Starting etcd analysis"},
			{Timestamp: mockTimestamp.Add(time.Second), Line: "Analysis complete"},
		},
		TotalLines:  2,
		StreamCount: 1,
	}

	// Set up expectation for QueryLogs call
	mockRHOBSClient.EXPECT().
		QueryLogs(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), 1000).
		Return(mockLogResult, nil).
		Times(1)

	// Override the factory to return our mock
	originalFactory := rhobsClientFactory
	rhobsClientFactory = func(baseURL, token string) (rhobs.Client, error) {
		return mockRHOBSClient, nil
	}
	defer func() { rhobsClientFactory = originalFactory }()

	rb := &investigation.ResourceBuilderMock{
		Resources: &investigation.Resources{
			Cluster:               cluster,
			ManagementK8sClient:   fakeK8s,
			HCPNamespace:          "ocm-test-namespace",
			ManagementClusterName: "test-management-cluster",
			RHOBSCell:             "grafana.rhobs.example.com",
			GrafanaToken:          "test-token",
			Notes:                 notewriter.New("etcddatabasequotalowspace_test", logging.RawLogger),
		},
	}

	inv := &Investigation{}
	result, err := inv.runHCPEtcdAnalysis(ctx, rb)

	assert.NoError(t, err)
	assert.True(t, result.EtcdDatabaseAnalysis.Performed)
	assert.Contains(t, result.EtcdDatabaseAnalysis.Labels, "success")
	assert.Contains(t, result.EtcdDatabaseAnalysis.Labels, "completed")
	assert.Len(t, result.Actions, 3) // NoteAndReportFrom (2 actions) + Escalate (1 action)

	// Verify logs were fetched and included in notes
	notesContent := rb.Resources.Notes.String()
	assert.Contains(t, notesContent, "Successfully fetched logs from RHOBS")
	assert.Contains(t, notesContent, "Starting etcd analysis")
	assert.Contains(t, notesContent, "Analysis complete")
	assert.Contains(t, notesContent, "View full logs in Grafana")
	assert.Contains(t, notesContent, "https://grafana.rhobs.example.com/explore")
}

func TestRunHCPEtcdAnalysis_RHOBSFetchFailure(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	cluster, _ := cmv1.NewCluster().
		ID("test-cluster-id").
		ExternalID("external-cluster-id").
		Hypershift(cmv1.NewHypershift().Enabled(true)).
		Build()

	etcdPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "etcd-0",
			Namespace: "ocm-test-namespace",
			Labels: map[string]string{
				"k8s-app": "etcd",
			},
		},
		Spec: corev1.PodSpec{
			NodeName: "test-node",
			InitContainers: []corev1.Container{
				{
					Name:  "reset-member",
					Image: "quay.io/openshift/etcd:v4.15",
				},
			},
		},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
		},
	}

	fakeK8s := fake.NewClientBuilder().
		WithObjects(etcdPod).
		WithStatusSubresource(&batchv1.Job{}).
		Build()

	ctx := t.Context()

	go func() {
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				jobList := &batchv1.JobList{}
				if err := fakeK8s.List(ctx, jobList, client.InNamespace("ocm-test-namespace")); err != nil {
					continue
				}

				for i := range jobList.Items {
					job := &jobList.Items[i]
					if job.Status.Succeeded == 0 {
						job.Status.Succeeded = 1
						_ = fakeK8s.Status().Update(ctx, job)
					}
				}
			}
		}
	}()

	// Create mock RHOBS client that returns an error
	mockRHOBSClient := rhobsmock.NewMockClient(ctrl)
	mockRHOBSClient.EXPECT().
		QueryLogs(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), 1000).
		Return(nil, assert.AnError).
		Times(1)

	// Override the factory to return our mock
	originalFactory := rhobsClientFactory
	rhobsClientFactory = func(baseURL, token string) (rhobs.Client, error) {
		return mockRHOBSClient, nil
	}
	defer func() { rhobsClientFactory = originalFactory }()

	rb := &investigation.ResourceBuilderMock{
		Resources: &investigation.Resources{
			Cluster:               cluster,
			ManagementK8sClient:   fakeK8s,
			HCPNamespace:          "ocm-test-namespace",
			ManagementClusterName: "test-management-cluster",
			RHOBSCell:             "grafana.rhobs.example.com",
			GrafanaToken:          "test-token",
			Notes:                 notewriter.New("etcddatabasequotalowspace_test", logging.RawLogger),
		},
	}

	inv := &Investigation{}
	result, err := inv.runHCPEtcdAnalysis(ctx, rb)

	// Investigation should handle RHOBS failure gracefully but mark as failed
	assert.NoError(t, err)
	assert.True(t, result.EtcdDatabaseAnalysis.Performed)
	assert.Contains(t, result.EtcdDatabaseAnalysis.Labels, "failure")
	assert.Contains(t, result.EtcdDatabaseAnalysis.Labels, "rhobs_logs_failed")
	assert.Len(t, result.Actions, 3)

	// Verify error message appears in notes
	notesContent := rb.Resources.Notes.String()
	assert.Contains(t, notesContent, "Failed to fetch RHOBS logs")
}

func TestRunHCPEtcdAnalysis_NoEtcdPod(t *testing.T) {
	cluster, _ := cmv1.NewCluster().
		ID("test-cluster-id").
		ExternalID("external-cluster-id").
		Hypershift(cmv1.NewHypershift().Enabled(true)).
		Build()

	// Create fake client with no etcd pods
	fakeK8s := fake.NewClientBuilder().Build()

	rb := &investigation.ResourceBuilderMock{
		Resources: &investigation.Resources{
			Cluster:             cluster,
			ManagementK8sClient: fakeK8s,
			HCPNamespace:        "ocm-test-namespace",
			Notes:               notewriter.New("etcddatabasequotalowspace_test", logging.RawLogger),
		},
	}

	inv := &Investigation{}
	result, err := inv.runHCPEtcdAnalysis(context.TODO(), rb)

	assert.NoError(t, err)
	assert.True(t, result.EtcdDatabaseAnalysis.Performed)
	assert.Contains(t, result.EtcdDatabaseAnalysis.Labels, "failure")
	assert.Contains(t, result.EtcdDatabaseAnalysis.Labels, "etcd_not_found")
}

func TestRunHCPEtcdAnalysis_NoRunningEtcdPod(t *testing.T) {
	cluster, _ := cmv1.NewCluster().
		ID("test-cluster-id").
		ExternalID("external-cluster-id").
		Hypershift(cmv1.NewHypershift().Enabled(true)).
		Build()

	// Create etcd pod that's not running
	etcdPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "etcd-0",
			Namespace: "ocm-test-namespace",
			Labels: map[string]string{
				"k8s-app": "etcd",
			},
		},
		Status: corev1.PodStatus{
			Phase: corev1.PodPending,
		},
	}

	fakeK8s := fake.NewClientBuilder().WithObjects(etcdPod).Build()

	rb := &investigation.ResourceBuilderMock{
		Resources: &investigation.Resources{
			Cluster:             cluster,
			ManagementK8sClient: fakeK8s,
			HCPNamespace:        "ocm-test-namespace",
			Notes:               notewriter.New("etcddatabasequotalowspace_test", logging.RawLogger),
		},
	}

	inv := &Investigation{}
	result, err := inv.runHCPEtcdAnalysis(context.TODO(), rb)

	assert.NoError(t, err)
	assert.True(t, result.EtcdDatabaseAnalysis.Performed)
	assert.Contains(t, result.EtcdDatabaseAnalysis.Labels, "failure")
	assert.Contains(t, result.EtcdDatabaseAnalysis.Labels, "etcd_not_found")
}

func TestRunHCPEtcdAnalysis_MissingResetMemberContainer(t *testing.T) {
	cluster, _ := cmv1.NewCluster().
		ID("test-cluster-id").
		ExternalID("external-cluster-id").
		Hypershift(cmv1.NewHypershift().Enabled(true)).
		Build()

	// Create etcd pod without reset-member init container
	etcdPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "etcd-0",
			Namespace: "ocm-test-namespace",
			Labels: map[string]string{
				"k8s-app": "etcd",
			},
		},
		Spec: corev1.PodSpec{
			InitContainers: []corev1.Container{
				{
					Name:  "other-init",
					Image: "quay.io/openshift/other:v4.15",
				},
			},
		},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
		},
	}

	fakeK8s := fake.NewClientBuilder().WithObjects(etcdPod).Build()

	rb := &investigation.ResourceBuilderMock{
		Resources: &investigation.Resources{
			Cluster:             cluster,
			ManagementK8sClient: fakeK8s,
			HCPNamespace:        "ocm-test-namespace",
			Notes:               notewriter.New("etcddatabasequotalowspace_test", logging.RawLogger),
		},
	}

	inv := &Investigation{}
	result, err := inv.runHCPEtcdAnalysis(context.TODO(), rb)

	assert.NoError(t, err)
	assert.True(t, result.EtcdDatabaseAnalysis.Performed)
	assert.Contains(t, result.EtcdDatabaseAnalysis.Labels, "failure")
	assert.Contains(t, result.EtcdDatabaseAnalysis.Labels, "etcdctl_container_image_not_found")
}

package etcddatabasequotalowspace

import (
	"testing"

	"github.com/stretchr/testify/assert"

	cmv1 "github.com/openshift-online/ocm-sdk-go/clustersmgmt/v1"
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
		expected := "etcdDatabaseQuotaLowSpace CRITICAL (1)"
		got := inv.AlertTitle()
		assert.Equal(t, expected, got)
	})

	t.Run("Description", func(t *testing.T) {
		expected := "Takes etcd snapshots for non-HCP clusters for analysis"
		got := inv.Description()
		assert.Equal(t, expected, got)
	})

	t.Run("IsExperimental", func(t *testing.T) {
		assert.True(t, inv.IsExperimental())
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

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

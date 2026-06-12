package srelib

import (
	"testing"

	amsv1 "github.com/openshift-online/ocm-sdk-go/accountsmgmt/v1"
	cmv1 "github.com/openshift-online/ocm-sdk-go/clustersmgmt/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockSrelibClient is a minimal mock of srelib's v1.Client for unit testing.
type mockSrelibClient struct {
	cluster      *cmv1.Cluster
	subscription *amsv1.Subscription
	organization *amsv1.Organization
	supportARN   string
	awsAccountID string
}

func (m *mockSrelibClient) GetCluster(string) (*cmv1.Cluster, error) {
	return m.cluster, nil
}

func (m *mockSrelibClient) GetClusterAnyStatus(string) (*cmv1.Cluster, error) {
	return m.cluster, nil
}

func (m *mockSrelibClient) GetClusters([]string) ([]*cmv1.Cluster, error) {
	return []*cmv1.Cluster{m.cluster}, nil
}

func (m *mockSrelibClient) GetManagementCluster(string) (*cmv1.Cluster, error) {
	return m.cluster, nil
}

func (m *mockSrelibClient) GetSubscription(string) (*amsv1.Subscription, error) {
	return m.subscription, nil
}

func (m *mockSrelibClient) GetOrganization(string) (*amsv1.Organization, error) {
	return m.organization, nil
}

func (m *mockSrelibClient) GetSupportRoleArnForCluster(string) (string, error) {
	return m.supportARN, nil
}

func (m *mockSrelibClient) GetAWSAccountIdForCluster(string) (string, error) {
	return m.awsAccountID, nil
}

func TestAdapter_GetClusterInfo(t *testing.T) {
	cluster, err := cmv1.NewCluster().ID("test-cluster-id").Name("test-cluster").Build()
	require.NoError(t, err)

	adapter := NewAdapter(&mockSrelibClient{cluster: cluster})

	got, err := adapter.GetClusterInfo("test-cluster-id")
	require.NoError(t, err)
	assert.Equal(t, "test-cluster-id", got.ID())
	assert.Equal(t, "test-cluster", got.Name())
}

func TestAdapter_GetSupportRoleARN(t *testing.T) {
	adapter := NewAdapter(&mockSrelibClient{
		supportARN: "arn:aws:iam::123456:role/RH-Technical-Support-Access",
	})

	arn, err := adapter.GetSupportRoleARN("cluster-123")
	require.NoError(t, err)
	assert.Equal(t, "arn:aws:iam::123456:role/RH-Technical-Support-Access", arn)
}

func TestAdapter_UnsupportedMethods(t *testing.T) {
	adapter := NewAdapter(&mockSrelibClient{})

	_, err := adapter.GetClusterMachinePools("x")
	assert.ErrorContains(t, err, "not supported")

	err = adapter.PostLimitedSupportReason(nil, nil)
	assert.ErrorContains(t, err, "not supported")

	assert.Nil(t, adapter.GetConnection())
}

// Package srelib provides an adapter that wraps the srelib plugin's v1.Client
// and exposes it as a CAD-compatible ocm.Client for cluster lookups.
package srelib

import (
	"fmt"

	sdk "github.com/openshift-online/ocm-sdk-go"
	amv1 "github.com/openshift-online/ocm-sdk-go/accountsmgmt/v1"
	cmv1 "github.com/openshift-online/ocm-sdk-go/clustersmgmt/v1"
	servicelogsv1 "github.com/openshift-online/ocm-sdk-go/servicelogs/v1"
	hivev1 "github.com/openshift/hive/apis/hive/v1"

	v1 "github.com/petrkotas/srelib/sdk/v1"

	"github.com/openshift/configuration-anomaly-detection/pkg/ocm"
)

// Adapter wraps a srelib v1.Client and implements CAD's ocm.Client interface.
// Methods that srelib supports are delegated; the rest return "not supported" errors.
type Adapter struct {
	srelib v1.Client
}

var _ ocm.Client = (*Adapter)(nil)

func NewAdapter(client v1.Client) *Adapter {
	return &Adapter{srelib: client}
}

func (a *Adapter) GetClusterInfo(identifier string) (*cmv1.Cluster, error) {
	return a.srelib.GetCluster(identifier)
}

func (a *Adapter) GetOrganizationID(clusterID string) (string, error) {
	cluster, err := a.srelib.GetCluster(clusterID)
	if err != nil {
		return "", err
	}
	cmv1Sub, ok := cluster.GetSubscription()
	if !ok {
		return "", nil
	}
	org, err := a.srelib.GetOrganization(cmv1Sub.ID())
	if err != nil {
		return "", err
	}
	return org.ID(), nil
}

func (a *Adapter) GetSupportRoleARN(internalClusterID string) (string, error) {
	return a.srelib.GetSupportRoleArnForCluster(internalClusterID)
}

// --- Methods below are not covered by srelib and return unsupported errors. ---
// In a full integration these would either stay backed by the existing OCM SDK
// client or be added to srelib over time.

func (a *Adapter) GetClusterMachinePools(string) ([]*cmv1.MachinePool, error) {
	return nil, fmt.Errorf("srelib adapter: GetClusterMachinePools not supported")
}

func (a *Adapter) PostLimitedSupportReason(*cmv1.Cluster, *ocm.LimitedSupportReason) error {
	return fmt.Errorf("srelib adapter: PostLimitedSupportReason not supported")
}

func (a *Adapter) GetServiceLog(*cmv1.Cluster, string) (*servicelogsv1.ClusterLogsUUIDListResponse, error) {
	return nil, fmt.Errorf("srelib adapter: GetServiceLog not supported")
}

func (a *Adapter) PostServiceLog(*cmv1.Cluster, *ocm.ServiceLog) error {
	return fmt.Errorf("srelib adapter: PostServiceLog not supported")
}

func (a *Adapter) AwsClassicJumpRoleCompatible(*cmv1.Cluster) (bool, error) {
	return false, fmt.Errorf("srelib adapter: AwsClassicJumpRoleCompatible not supported")
}

func (a *Adapter) GetConnection() *sdk.Connection {
	return nil
}

func (a *Adapter) IsAccessProtected(*cmv1.Cluster) (bool, error) {
	return false, fmt.Errorf("srelib adapter: IsAccessProtected not supported")
}

func (a *Adapter) GetClusterHypershiftConfig(*cmv1.Cluster) (*cmv1.HypershiftConfig, error) {
	return nil, fmt.Errorf("srelib adapter: GetClusterHypershiftConfig not supported")
}

func (a *Adapter) IsManagingCluster(string) (bool, error) {
	return false, fmt.Errorf("srelib adapter: IsManagingCluster not supported")
}

func (a *Adapter) GetDynatraceURL(*cmv1.Cluster) (string, error) {
	return "", fmt.Errorf("srelib adapter: GetDynatraceURL not supported")
}

func (a *Adapter) CheckIfUserBanned(*cmv1.Cluster) error {
	return fmt.Errorf("srelib adapter: CheckIfUserBanned not supported")
}

func (a *Adapter) GetCreatorFromCluster(*cmv1.Cluster) (*amv1.Account, error) {
	return nil, fmt.Errorf("srelib adapter: GetCreatorFromCluster not supported")
}

func (a *Adapter) GetClusterDeployment(string) (*hivev1.ClusterDeployment, error) {
	return nil, fmt.Errorf("srelib adapter: GetClusterDeployment not supported")
}

package investigation

import (
	"context"
	"fmt"

	cmv1 "github.com/openshift-online/ocm-sdk-go/clustersmgmt/v1"
	"github.com/openshift/backplane-cli/pkg/cli/config"
	bpremediation "github.com/openshift/backplane-cli/pkg/remediation"

	hivev1 "github.com/openshift/hive/apis/hive/v1"
	"k8s.io/client-go/rest"

	"github.com/openshift/configuration-anomaly-detection/pkg/aws"
	"github.com/openshift/configuration-anomaly-detection/pkg/backplane"
	k8sclient "github.com/openshift/configuration-anomaly-detection/pkg/k8s"
	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
	"github.com/openshift/configuration-anomaly-detection/pkg/managedcloud"
	"github.com/openshift/configuration-anomaly-detection/pkg/notewriter"
	"github.com/openshift/configuration-anomaly-detection/pkg/oc"
	"github.com/openshift/configuration-anomaly-detection/pkg/ocm"
	"github.com/openshift/configuration-anomaly-detection/pkg/pagerduty"
	"github.com/openshift/configuration-anomaly-detection/pkg/types"
)

type InvestigationStep struct {
	Performed bool
	Labels    []string
}

type InvestigationResult struct {
	// NEW: Actions to execute via reporter (modern approach)
	Actions []types.Action

	// EXISTING: Legacy fields (deprecated, maintained for backwards compatibility)
	LimitedSupportSet    InvestigationStep
	ServiceLogPrepared   InvestigationStep
	ServiceLogSent       InvestigationStep
	MustGatherPerformed  InvestigationStep
	EtcdDatabaseAnalysis InvestigationStep

	// If multiple investigations might be run this can indicate a fatal error that makes running additional investigations useless.
	// If nil, investigations should continue. If not nil, should contain a meaningful error message explaining why investigations must stop.
	StopInvestigations error
}

func NewResourceBuilder(
	ocmClient *ocm.SdkClient,
	bpClient backplane.Client,
	clusterId string,
	name string,
	backplaneUrl string,
) (ResourceBuilder, error) {
	rb := &ResourceBuilderT{
		clusterId:    clusterId,
		name:         name,
		ocmClient:    ocmClient,
		backplaneUrl: backplaneUrl,
		builtResources: &Resources{
			BpClient:  bpClient,
			OcmClient: ocmClient,
		},
	}

	return rb, nil
}

type Investigation interface {
	Run(builder ResourceBuilder) (InvestigationResult, error)
	// Please note that when adding an investigation the name and the directory currently need to be the same,
	// so that backplane-api can fetch the metadata.yaml
	Name() string
	AlertTitle() string
	Description() string
	IsExperimental() bool
}

// Resources holds all resources/tools required for alert investigations
type Resources struct {
	Name                 string
	Cluster              *cmv1.Cluster
	ClusterDeployment    *hivev1.ClusterDeployment
	AwsClient            aws.Client
	BpClient             backplane.Client
	RestConfig           *RestConfig
	K8sClient            k8sclient.Client
	OcmClient            ocm.Client
	PdClient             pagerduty.Client
	Notes                *notewriter.NoteWriter
	OCClient             oc.Client
	ManagementRestConfig *RestConfig
	ManagementOCClient   oc.Client
	ManagementCluster    *cmv1.Cluster
	ManagementClusterID  string
	HCPNamespace         string
	IsHCP                bool
}

type ResourceBuilder interface {
	WithCluster() ResourceBuilder
	WithClusterDeployment() ResourceBuilder
	WithAwsClient() ResourceBuilder
	WithRestConfig() ResourceBuilder
	WithK8sClient() ResourceBuilder
	WithPdClient(pdClient pagerduty.Client) ResourceBuilder
	WithOC() ResourceBuilder
	WithNotes() ResourceBuilder
	WithManagementRestConfig() ResourceBuilder
	WithManagementOCClient() ResourceBuilder
	Build() (*Resources, error)
}

type ResourceBuilderT struct {
	buildCluster           bool
	buildClusterDeployment bool
	buildAwsClient         bool
	buildRestConfig        bool
	buildK8sClient         bool
	buildOC                bool
	buildNotes             bool
	buildManagementRestConfig bool
	buildManagementOCClient   bool

	clusterId    string
	name         string
	logLevel     string
	pipelineName string
	backplaneUrl string

	ocmClient *ocm.SdkClient

	// cache
	builtResources *Resources
	buildErr       error
}

func (r *ResourceBuilderT) WithCluster() ResourceBuilder {
	r.buildCluster = true
	return r
}

func (r *ResourceBuilderT) WithClusterDeployment() ResourceBuilder {
	r.WithCluster()
	r.buildClusterDeployment = true
	return r
}

func (r *ResourceBuilderT) WithRestConfig() ResourceBuilder {
	r.WithCluster()
	r.buildRestConfig = true
	return r
}

func (r *ResourceBuilderT) WithAwsClient() ResourceBuilder {
	r.WithCluster()
	r.buildAwsClient = true
	return r
}

func (r *ResourceBuilderT) WithOC() ResourceBuilder {
	r.WithRestConfig()
	r.buildOC = true
	return r
}

func (r *ResourceBuilderT) WithK8sClient() ResourceBuilder {
	r.WithRestConfig()
	r.buildK8sClient = true
	return r
}

func (r *ResourceBuilderT) WithNotes() ResourceBuilder {
	r.buildNotes = true
	return r
}


func (r *ResourceBuilderT) WithPdClient(pdClient pagerduty.Client) ResourceBuilder {
	r.builtResources.PdClient = pdClient
	return r
}

func (r *ResourceBuilderT) WithManagementRestConfig() ResourceBuilder {
	r.WithCluster()
	r.buildManagementRestConfig = true
	return r
}

func (r *ResourceBuilderT) WithManagementOCClient() ResourceBuilder {
	r.WithManagementRestConfig()
	r.buildManagementOCClient = true
	return r
}

func (r *ResourceBuilderT) Build() (*Resources, error) {
	if r.buildErr != nil {
		// Return whatever managed to build + an error. this might allow some subset of checks to proceed.
		return r.builtResources, r.buildErr
	}

	// The Name is now set during construction.
	r.builtResources.Name = r.name

	var err error

	if r.buildCluster && r.builtResources.Cluster == nil {
		r.builtResources.Cluster, err = r.ocmClient.GetClusterInfo(r.clusterId)
		if err != nil {
			// Let the caller handle how to respond to this error.
			r.buildErr = ClusterNotFoundError{ClusterID: r.clusterId, Err: err}
			return r.builtResources, r.buildErr
		}
	}

	if r.buildNotes && r.builtResources.Notes == nil {
		r.builtResources.Notes = notewriter.New(r.name, logging.RawLogger)
	}

	internalClusterId := r.builtResources.Cluster.ID()

	if r.buildAwsClient && r.builtResources.AwsClient == nil {
		r.builtResources.AwsClient, err = managedcloud.CreateCustomerAWSClient(r.builtResources.Cluster, r.ocmClient)
		if err != nil {
			r.buildErr = AWSClientError{ClusterID: r.clusterId, Err: err}
			return r.builtResources, r.buildErr
		}
	}

	if r.buildRestConfig && r.builtResources.RestConfig == nil {
		r.builtResources.RestConfig, err = newRestConfig(r.builtResources.Cluster.ID(), r.backplaneUrl, r.ocmClient, r.name)
		if err != nil {
			r.buildErr = RestConfigError{ClusterID: r.clusterId, Err: err}
			return r.builtResources, r.buildErr
		}
	}

	if r.buildK8sClient && r.builtResources.K8sClient == nil {
		logging.Infof("creating k8s client for %s", r.name)
		r.builtResources.K8sClient, err = k8sclient.New(&r.builtResources.RestConfig.Config)
		if err != nil {
			r.buildErr = K8SClientError{ClusterID: r.clusterId, Err: err}
			return r.builtResources, r.buildErr
		}
	}

	if r.buildOC && r.builtResources.OCClient == nil {
		r.builtResources.OCClient, err = oc.New(context.Background(), &r.builtResources.RestConfig.Config)
		if err != nil {
			r.buildErr = OCClientError{ClusterID: r.clusterId, Err: err}
			return r.builtResources, r.buildErr
		}
	}

	if r.buildClusterDeployment && r.builtResources.ClusterDeployment == nil {
		r.builtResources.ClusterDeployment, err = r.ocmClient.GetClusterDeployment(internalClusterId)
		if err != nil {
			r.buildErr = ClusterDeploymentNotFoundError{ClusterID: r.clusterId, Err: err}
			return r.builtResources, r.buildErr
		}
	}


	// Check if this is an HCP cluster and build management cluster resources if requested
	if r.buildManagementRestConfig || r.buildManagementOCClient {
		err = r.buildManagementClusterResources()
		if err != nil {
			r.buildErr = err
			return r.builtResources, r.buildErr
		}
	}

	return r.builtResources, nil
}

// buildManagementClusterResources checks if the cluster is HCP and builds management cluster resources
func (r *ResourceBuilderT) buildManagementClusterResources() error {
	r.builtResources.IsHCP = false

	hypershift := r.builtResources.Cluster.Hypershift()
	if hypershift == nil || !hypershift.Enabled() {
		logging.Infof("Cluster %s is not an HCP cluster, skipping management cluster resource creation", r.clusterId)
		return nil
	}

	r.builtResources.IsHCP = true
	logging.Infof("Cluster %s is an HCP cluster, retrieving management cluster information", r.clusterId)

	hypershiftConfig, err := r.ocmClient.GetClusterHypershiftConfig(r.builtResources.Cluster)
	if err != nil {
		return ManagementClusterNotFoundError{ClusterID: r.clusterId, Err: err}
	}

	managementClusterID := hypershiftConfig.ManagementCluster()
	if managementClusterID == "" {
		return ManagementClusterNotFoundError{
			ClusterID: r.clusterId,
			Err:       fmt.Errorf("management cluster ID is empty in HypershiftConfig"),
		}
	}
	r.builtResources.ManagementClusterID = managementClusterID

	hcpNamespace := hypershiftConfig.HCPNamespace()
	if hcpNamespace == "" {
		return ManagementClusterNotFoundError{
			ClusterID: r.clusterId,
			Err:       fmt.Errorf("HCP namespace is empty in HypershiftConfig"),
		}
	}
	r.builtResources.HCPNamespace = hcpNamespace

	logging.Infof("Management cluster ID: %s, HCP namespace: %s", managementClusterID, hcpNamespace)

	r.builtResources.ManagementCluster, err = r.ocmClient.GetClusterInfo(managementClusterID)
	if err != nil {
		return ManagementClusterNotFoundError{ClusterID: r.clusterId, Err: err}
	}

	if r.buildManagementRestConfig && r.builtResources.ManagementRestConfig == nil {
		logging.Infof("Creating RestConfig for management cluster %s", managementClusterID)
		r.builtResources.ManagementRestConfig, err = newRestConfig(
			r.builtResources.ManagementCluster.ID(),
			r.backplaneUrl,
			r.ocmClient,
			fmt.Sprintf("%s-mgmt", r.name), // Use a unique remediation name for management cluster
		)
		if err != nil {
			return ManagementRestConfigError{
				ClusterID:           r.clusterId,
				ManagementClusterID: managementClusterID,
				Err:                 err,
			}
		}
	}

	if r.buildManagementOCClient && r.builtResources.ManagementOCClient == nil {
		logging.Infof("Creating OC client for management cluster %s", managementClusterID)
		r.builtResources.ManagementOCClient, err = oc.New(context.Background(), &r.builtResources.ManagementRestConfig.Config)
		if err != nil {
			return ManagementOCClientError{
				ClusterID:           r.clusterId,
				ManagementClusterID: managementClusterID,
				Err:                 err,
			}
		}
	}

	return nil
}

type remediationCleaner struct {
	clusterID             string
	ocmClient             ocm.Client
	remediationInstanceId string
	backplaneUrl          string
}

type Cleaner interface {
	Clean() error
}

type RestConfig struct {
	rest.Config
	backplaneUrl string
	Cleaner
}

func (cleaner remediationCleaner) Clean() error {
	return deleteRemediation(cleaner.clusterID, cleaner.backplaneUrl, cleaner.ocmClient, cleaner.remediationInstanceId)
}

// New returns a k8s rest config for the given cluster scoped to a given remediation's permissions.
func newRestConfig(clusterID, backplaneUrl string, ocmClient ocm.Client, remediationName string) (*RestConfig, error) {
	decoratedCfg, remediationInstanceId, err := bpremediation.CreateRemediationWithConn(
		config.BackplaneConfiguration{URL: backplaneUrl},
		ocmClient.GetConnection(),
		clusterID,
		remediationName,
	)
	if err != nil {
		return nil, err
	}

	return &RestConfig{*decoratedCfg, backplaneUrl, remediationCleaner{clusterID, ocmClient, remediationInstanceId, backplaneUrl}}, nil
}

// Cleanup removes the remediation created for the cluster.
func deleteRemediation(clusterID, backplaneUrl string, ocmClient ocm.Client, remediationInstanceId string) error {
	return bpremediation.DeleteRemediationWithConn(
		config.BackplaneConfiguration{URL: backplaneUrl},
		ocmClient.GetConnection(),
		clusterID,
		remediationInstanceId,
	)
}

// This is an implementation to be used in tests, but putting it into a _test.go file will make it not resolvable.
type ResourceBuilderMock struct {
	Resources  *Resources
	BuildError error
}

func (r *ResourceBuilderMock) WithCluster() ResourceBuilder {
	return r
}

func (r *ResourceBuilderMock) WithClusterDeployment() ResourceBuilder {
	return r
}

func (r *ResourceBuilderMock) WithAwsClient() ResourceBuilder {
	return r
}

func (r *ResourceBuilderMock) WithRestConfig() ResourceBuilder {
	return r
}

func (r *ResourceBuilderMock) WithOC() ResourceBuilder {
	return r
}

func (r *ResourceBuilderMock) WithNotes() ResourceBuilder {
	return r
}

func (r *ResourceBuilderMock) WithK8sClient() ResourceBuilder {
	return r
}


func (r *ResourceBuilderMock) WithPdClient(client pagerduty.Client) ResourceBuilder {
	r.Resources.PdClient = client
	return r
}

func (r *ResourceBuilderMock) WithManagementRestConfig() ResourceBuilder {
	return r
}

func (r *ResourceBuilderMock) WithManagementOCClient() ResourceBuilder {
	return r
}

func (r *ResourceBuilderMock) Build() (*Resources, error) {
	if r.BuildError != nil {
		return nil, r.BuildError
	}
	return r.Resources, nil
}

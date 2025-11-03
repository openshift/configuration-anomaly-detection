package investigation

import (
	cmv1 "github.com/openshift-online/ocm-sdk-go/clustersmgmt/v1"
	hivev1 "github.com/openshift/hive/apis/hive/v1"

	"github.com/openshift/configuration-anomaly-detection/pkg/aws"
	k8sclient "github.com/openshift/configuration-anomaly-detection/pkg/k8s"
	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
	"github.com/openshift/configuration-anomaly-detection/pkg/managedcloud"
	"github.com/openshift/configuration-anomaly-detection/pkg/notewriter"
	"github.com/openshift/configuration-anomaly-detection/pkg/ocm"
	"github.com/openshift/configuration-anomaly-detection/pkg/pagerduty"
)

type InvestigationStep struct {
	Performed bool
	Labels    []string
}

type InvestigationResult struct {
	LimitedSupportSet  InvestigationStep
	ServiceLogPrepared InvestigationStep
	ServiceLogSent     InvestigationStep

	// If multiple investigations might be run this can indicate a fatal error that makes running additional investigations useless.
	// If nil, investigations should continue. If not nil, should contain a meaningful error message explaining why investigations must stop.
	StopInvestigations error
}

func NewResourceBuilder(pdClient pagerduty.Client, ocmClient *ocm.SdkClient, clusterId string, name string, logLevel string, pipelineName string) (ResourceBuilder, error) {
	rb := &ResourceBuilderT{
		buildLogger:  true,
		clusterId:    clusterId,
		name:         name,
		logLevel:     logLevel,
		pipelineName: pipelineName,
		ocmClient:    ocmClient,
		builtResources: &Resources{
			PdClient:  pdClient,
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
	Name              string
	Cluster           *cmv1.Cluster
	ClusterDeployment *hivev1.ClusterDeployment
	AwsClient         aws.Client
	K8sClient         k8sclient.Client
	OcmClient         ocm.Client
	PdClient          pagerduty.Client
	Notes             *notewriter.NoteWriter
}

type ResourceBuilder interface {
	WithCluster() ResourceBuilder
	WithClusterDeployment() ResourceBuilder
	WithAwsClient() ResourceBuilder
	WithK8sClient() ResourceBuilder
	WithNotes() ResourceBuilder
	Build() (*Resources, error)
}

type ResourceBuilderT struct {
	buildCluster           bool
	buildClusterDeployment bool
	buildAwsClient         bool
	buildK8sClient         bool
	buildNotes             bool
	buildLogger            bool

	clusterId    string
	name         string
	logLevel     string
	pipelineName string

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

func (r *ResourceBuilderT) WithAwsClient() ResourceBuilder {
	r.WithCluster()
	r.buildAwsClient = true
	return r
}

func (r *ResourceBuilderT) WithK8sClient() ResourceBuilder {
	r.buildK8sClient = true
	return r
}

func (r *ResourceBuilderT) WithNotes() ResourceBuilder {
	r.buildNotes = true
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
			return nil, r.buildErr
		}
	}

	// Dependent resources can only be built if a cluster object exists.
	//nolint:nestif
	if r.builtResources.Cluster != nil {
		internalClusterId := r.builtResources.Cluster.ID()

		if r.buildAwsClient && r.builtResources.AwsClient == nil {
			r.builtResources.AwsClient, err = managedcloud.CreateCustomerAWSClient(r.builtResources.Cluster, r.ocmClient)
			if err != nil {
				r.buildErr = AWSClientError{ClusterID: r.clusterId, Err: err}
				return nil, r.buildErr
			}
		}

		if r.buildK8sClient && r.builtResources.K8sClient == nil {
			logging.Infof("creating k8s client for %s", r.name)
			r.builtResources.K8sClient, err = k8sclient.New(r.builtResources.Cluster.ID(), r.ocmClient, r.name)
			if err != nil {
				r.buildErr = K8SClientError{ClusterID: r.clusterId, Err: err}
				return nil, r.buildErr
			}
		}

		if r.buildClusterDeployment && r.builtResources.ClusterDeployment == nil {
			r.builtResources.ClusterDeployment, err = r.ocmClient.GetClusterDeployment(internalClusterId)
			if err != nil {
				r.buildErr = ClusterDeploymentNotFoundError{ClusterID: r.clusterId, Err: err}
				return nil, r.buildErr
			}
		}

		if r.buildLogger {
			// Re-initialize the logger with the cluster ID.
			logging.RawLogger = logging.InitLogger(r.logLevel, r.pipelineName, internalClusterId)
		}
	}

	if r.buildNotes && r.builtResources.Notes == nil {
		r.builtResources.Notes = notewriter.New(r.name, logging.RawLogger)
	}

	return r.builtResources, nil
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

func (r *ResourceBuilderMock) WithNotes() ResourceBuilder {
	return r
}

func (r *ResourceBuilderMock) WithK8sClient() ResourceBuilder {
	return r
}

func (r *ResourceBuilderMock) Build() (*Resources, error) {
	if r.BuildError != nil {
		return nil, r.BuildError
	}
	return r.Resources, nil
}

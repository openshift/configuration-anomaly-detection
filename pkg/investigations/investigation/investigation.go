package investigation

import (
	"errors"
	"fmt"

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
	// Uses a false-default so it must be set expclicitly by an investigation.
	StopInvestigations bool
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
	WithCluster(clusterId string) ResourceBuilder
	WithClusterDeployment() ResourceBuilder
	WithAwsClient() ResourceBuilder
	WithK8sClient() ResourceBuilder
	WithOcmClient(*ocm.SdkClient) ResourceBuilder
	WithPagerDutyClient(client *pagerduty.SdkClient) ResourceBuilder
	WithNotes() ResourceBuilder
	WithName(name string) ResourceBuilder
	WithLogger(logLevel string, pipelineName string) ResourceBuilder
	Build() (*Resources, error)
}

type ResourceBuilderT struct {
	buildCluster           bool
	buildClusterDeployment bool
	buildAwsClient         bool
	buildK8sClient         bool
	buildNotes             bool
	buildLogger            bool

	// These clients are required for all investigations and all clusters, so they are pre-filled.
	pdClient  *pagerduty.SdkClient
	ocmClient *ocm.SdkClient

	clusterId    string
	name         string
	logLevel     string
	pipelineName string

	// cache
	builtResources *Resources
	buildErr       error
}

func (r *ResourceBuilderT) WithCluster(clusterId string) ResourceBuilder {
	r.buildCluster = true
	r.clusterId = clusterId
	return r
}

func (r *ResourceBuilderT) WithClusterDeployment() ResourceBuilder {
	r.buildClusterDeployment = true
	return r
}

func (r *ResourceBuilderT) WithAwsClient() ResourceBuilder {
	r.buildAwsClient = true
	return r
}

func (r *ResourceBuilderT) WithK8sClient() ResourceBuilder {
	r.buildK8sClient = true
	return r
}

func (r *ResourceBuilderT) WithOcmClient(client *ocm.SdkClient) ResourceBuilder {
	r.ocmClient = client
	return r
}

func (r *ResourceBuilderT) WithPagerDutyClient(client *pagerduty.SdkClient) ResourceBuilder {
	r.pdClient = client
	return r
}

func (r *ResourceBuilderT) WithNotes() ResourceBuilder {
	r.buildNotes = true
	return r
}

func (r *ResourceBuilderT) WithName(name string) ResourceBuilder {
	r.name = name
	return r
}

func (r *ResourceBuilderT) WithLogger(logLevel string, pipelineName string) ResourceBuilder {
	r.buildLogger = true
	r.logLevel = logLevel
	r.pipelineName = pipelineName
	return r
}

func (r *ResourceBuilderT) Build() (*Resources, error) {
	if r.buildErr != nil {
		return nil, r.buildErr
	}

	if r.builtResources == nil {
		r.builtResources = &Resources{
			Name:      r.name,
			OcmClient: r.ocmClient,
			PdClient:  r.pdClient,
		}
	}

	var err error

	if r.buildClusterDeployment && !r.buildCluster {
		r.buildErr = errors.New("cannot build ClusterDeployment without Cluster")
		return nil, r.buildErr
	}
	if r.buildAwsClient && !r.buildCluster {
		r.buildErr = errors.New("cannot build AwsClient without Cluster")
		return nil, r.buildErr
	}
	if r.buildK8sClient && !r.buildCluster {
		r.buildErr = errors.New("cannot build K8sClient without Cluster")
		return nil, r.buildErr
	}

	if r.buildCluster && r.builtResources.Cluster == nil {
		r.builtResources.Cluster, err = r.ocmClient.GetClusterInfo(r.clusterId)
		if err != nil {
			// Let the caller handle how to respond to this error.
			err = fmt.Errorf("could not retrieve cluster info for %s: %w", r.clusterId, err)
			r.buildErr = err
			return nil, err
		}
	}

	// Dependent resources can only be built if a cluster object exists.
	//nolint:nestif
	if r.builtResources.Cluster != nil {
		internalClusterId := r.builtResources.Cluster.ID()

		if r.buildAwsClient && r.builtResources.AwsClient == nil {
			r.builtResources.AwsClient, err = managedcloud.CreateCustomerAWSClient(r.builtResources.Cluster, r.ocmClient)
			if err != nil {
				r.buildErr = err
				return nil, err
			}
		}

		if r.buildK8sClient && r.builtResources.K8sClient == nil {
			logging.Infof("creating k8s client for %s", r.name)
			r.builtResources.K8sClient, err = k8sclient.New(r.builtResources.Cluster.ID(), r.ocmClient, r.name)
			if err != nil {
				r.buildErr = err
				return nil, err
			}
		}

		if r.buildClusterDeployment && r.builtResources.ClusterDeployment == nil {
			r.builtResources.ClusterDeployment, err = r.ocmClient.GetClusterDeployment(internalClusterId)
			if err != nil {
				err = fmt.Errorf("could not retrieve Cluster Deployment for %s: %w", internalClusterId, err)
				r.buildErr = err
				return nil, err
			}
		}

		if r.buildLogger {
			// Re-initialize the logger with the cluster ID.
			logging.RawLogger = logging.InitLogger(r.logLevel, "", internalClusterId)
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

func (r *ResourceBuilderMock) WithCluster(clusterId string) ResourceBuilder {
	return r
}

func (r *ResourceBuilderMock) WithClusterDeployment() ResourceBuilder {
	return r
}

func (r *ResourceBuilderMock) WithAwsClient() ResourceBuilder {
	return r
}

func (r *ResourceBuilderMock) WithK8sClient() ResourceBuilder {
	return r
}

func (r *ResourceBuilderMock) WithOcmClient(client *ocm.SdkClient) ResourceBuilder {
	return r
}

func (r *ResourceBuilderMock) WithPagerDutyClient(client *pagerduty.SdkClient) ResourceBuilder {
	return r
}

func (r *ResourceBuilderMock) WithNotes() ResourceBuilder {
	return r
}

func (r *ResourceBuilderMock) WithName(name string) ResourceBuilder {
	return r
}

func (r *ResourceBuilderMock) WithLogger(logLevel string, pipelineName string) ResourceBuilder {
	return r
}

func (r *ResourceBuilderMock) Build() (*Resources, error) {
	if r.BuildError != nil {
		return nil, r.BuildError
	}
	return r.Resources, nil
}

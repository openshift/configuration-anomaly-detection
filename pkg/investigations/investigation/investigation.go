package investigation

import (
	"errors"
	"fmt"
	"strings"

	cmv1 "github.com/openshift-online/ocm-sdk-go/clustersmgmt/v1"
	"github.com/openshift-online/ocm-sdk-go/internal"
	"github.com/openshift/configuration-anomaly-detection/pkg/aws"
	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
	"github.com/openshift/configuration-anomaly-detection/pkg/managedcloud"
	"github.com/openshift/configuration-anomaly-detection/pkg/notewriter"
	"github.com/openshift/configuration-anomaly-detection/pkg/ocm"
	"github.com/openshift/configuration-anomaly-detection/pkg/pagerduty"
	hivev1 "github.com/openshift/hive/apis/hive/v1"
)

type InvestigationStep struct {
	Performed bool
	Labels    []string
}

type InvestigationResult struct {
	LimitedSupportSet  InvestigationStep
	ServiceLogPrepared InvestigationStep
	ServiceLogSent     InvestigationStep
}

type Investigation interface {
	Run(builder *ResourceBuilder) (InvestigationResult, error)
	// Please note that when adding an investigation the name and the directory currently need to be the same,
	// so that backplane-api can fetch the metadata.yaml
	Name() string
	Description() string
	IsExperimental() bool
	ShouldInvestigateAlert(string) bool
}

// Resources holds all resources/tools required for alert investigations
type Resources struct {
	Name              string
	Cluster           *cmv1.Cluster
	ClusterDeployment *hivev1.ClusterDeployment
	AwsClient         aws.Client
	OcmClient         ocm.Client
	PdClient          pagerduty.Client
	Notes             *notewriter.NoteWriter
}

type ResourceBuilder struct {
	buildCluster           bool
	buildClusterDeployment bool
	buildAwsClient         bool
	buildNotes             bool
	buildLogger            bool

	// These clients are required for all investigations and all clusters, so they are pre-filled.
	pdClient  *pagerduty.SdkClient
	ocmClient *ocm.SdkClient

	clusterId string
	name      string
	logLevel  string
}

func (r *ResourceBuilder) WithCluster(clusterId string) *ResourceBuilder {
	r.buildCluster = true
	r.clusterId = clusterId
	return r
}

func (r *ResourceBuilder) WithClusterDeployment() *ResourceBuilder {
	r.buildClusterDeployment = true
	return r
}

func (r *ResourceBuilder) WithAwsClient() *ResourceBuilder {
	r.buildAwsClient = true
	return r
}

func (r *ResourceBuilder) WithOcmClient(client *ocm.SdkClient) *ResourceBuilder {
	r.ocmClient = client
	return r
}

func (r *ResourceBuilder) WithPagerDutyClient(client *pagerduty.SdkClient) *ResourceBuilder {
	r.pdClient = client
	return r
}

func (r *ResourceBuilder) WithNotes() *ResourceBuilder {
	r.buildNotes = true
	return r
}

func (r *ResourceBuilder) WithName(name string) *ResourceBuilder {
	r.name = name
	return r
}

func (r *ResourceBuilder) WithLogger(logLevel string) *ResourceBuilder {
	r.buildLogger = true
	r.logLevel = logLevel
}

func (r *ResourceBuilder) Build() (*Resources, error) {
	var awsClient aws.Client
	var cluster *cmv1.Cluster
	var clusterDeployment *hivev1.ClusterDeployment
	var notes *notewriter.NoteWriter
	var internalClusterId string
	var err error

	if r.buildClusterDeployment && !r.buildCluster {
		return nil, errors.New("Can not build ClusterDeployment without Cluster")
	}

	if r.buildAwsClient {
		awsClient, err = managedcloud.CreateCustomerAWSClient(cluster, r.ocmClient)
		if err != nil {
			return nil, err
		}
	}

	if r.buildCluster {
		cluster, err = r.ocmClient.GetClusterInfo(r.clusterId)
		if err != nil {
			if strings.Contains(err.Error(), "no cluster found") {
				logging.Warnf("No cluster found with ID '%s'. Exiting.", r.clusterId)
				// TODO: Do this cleaner - error handling should be happening cleanly.
				err = r.pdClient.EscalateIncidentWithNote("CAD was unable to find the incident cluster in OCM. An alert for a non-existing cluster is unexpected. Please investigate manually.")
				return nil, errors.New("Unable to find incident cluster in OCM")
			}
			return nil, fmt.Errorf("could not retrieve cluster info for %s: %w", r.clusterId, err)
		}

		// From this point on, we normalize to internal ID, as this ID always exists.
		// For installing clusters, externalID can be empty.
		internalClusterId = cluster.ID()
	}

	if r.buildClusterDeployment {
		clusterDeployment, err = r.ocmClient.GetClusterDeployment(internalClusterId)
		if err != nil {
			return nil, fmt.Errorf("could not retrieve Cluster Deployment for %s: %w", internalClusterId, err)
		}
	}

	if r.buildLogger {
		logging.RawLogger = logging.InitLogger(r.logLevel, internalClusterId)
	}

	if r.buildNotes {
		// Initialize NoteWriter with sane defaults
		notes = notewriter.New(r.name, logging.RawLogger)
	}

	return &Resources{
		Name:              r.name,
		Cluster:           cluster,
		ClusterDeployment: clusterDeployment,
		AwsClient:         awsClient,
		OcmClient:         r.ocmClient,
		PdClient:          r.pdClient,
		Notes:             notes,
	}, nil
}

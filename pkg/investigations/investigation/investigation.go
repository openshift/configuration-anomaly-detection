// Package investigation contains base functions for investigations
package investigation

import (
	cmv1 "github.com/openshift-online/ocm-sdk-go/clustersmgmt/v1"
	"github.com/openshift/configuration-anomaly-detection/pkg/aws"
	"github.com/openshift/configuration-anomaly-detection/pkg/notewriter"
	"github.com/openshift/configuration-anomaly-detection/pkg/ocm"
	"github.com/openshift/configuration-anomaly-detection/pkg/pagerduty"
	hivev1 "github.com/openshift/hive/apis/hive/v1"
	"go.uber.org/dig"
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
	Run(resources *Resources) (InvestigationResult, error)
	// Please note that when adding an investigation the name and the directory currently need to be the same,
	// so that backplane-api can fetch the metadata.yaml
	Name() string
	Description() string
	IsExperimental() bool
	ShouldInvestigateAlert(string) bool
}

// Resources holds all resources/tools required for alert investigations
type Resources struct {
	Name                string
	Cluster             *cmv1.Cluster
	ClusterDeployment   *hivev1.ClusterDeployment
	AwsClient           aws.Client
	OcmClient           ocm.Client
	PdClient            pagerduty.Client
	Notes               *notewriter.NoteWriter
	AdditionalResources map[string]interface{}
}

type ResourceParameters struct {
	dig.In

	Name                string
	Cluster             *cmv1.Cluster
	ClusterDeployment   *hivev1.ClusterDeployment `optional:"true"`
	AwsClient           aws.Client                `optional:"true"`
	OcmClient           ocm.Client                `optional:"true"`
	PdClient            pagerduty.Client
	Notes               *notewriter.NoteWriter `optional:"true"`
	AdditionalResources map[string]interface{} `optional:"true"`
}

func NewResources(p ResourceParameters) *Resources {
	return &Resources{
		Name:                p.Name,
		Cluster:             p.Cluster,
		ClusterDeployment:   p.ClusterDeployment,
		AwsClient:           p.AwsClient,
		OcmClient:           p.OcmClient,
		PdClient:            p.PdClient,
		Notes:               p.Notes,
		AdditionalResources: p.AdditionalResources,
	}
}

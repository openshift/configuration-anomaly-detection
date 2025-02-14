// Package investigation contains base functions for investigations
package investigation

import (
	cmv1 "github.com/openshift-online/ocm-sdk-go/clustersmgmt/v1"
	"github.com/openshift/configuration-anomaly-detection/pkg/aws"
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
	Run(resources *Resources) (InvestigationResult, error)
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
	AdditionalResources map[string]interface{}
}

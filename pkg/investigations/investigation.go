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
	InvestigationName  string
	LimitedSupportSet  InvestigationStep
	ServiceLogPrepared InvestigationStep
	ServiceLogSent     InvestigationStep
}

// Investigation serves as a parent class
// This enables the structure of cmd/investigate.go
type Investigation struct {
	Run  func(resources *Resources) (InvestigationResult, error)
	Name string
}

// NewInvestigation creates a new investigation
func NewInvestigation(investigationFn func(resources *Resources) (InvestigationResult, error), name string) *Investigation {
	return &Investigation{investigationFn, name}
}

// Resources holds all resources/tools required for alert investigations
type Resources struct {
	Cluster             *cmv1.Cluster
	ClusterDeployment   *hivev1.ClusterDeployment
	AwsClient           aws.Client
	OcmClient           ocm.Client
	PdClient            pagerduty.Client
	AdditionalResources map[string]interface{}
}

// Package investigation contains base functions for investigations
package investigation

import (
	"errors"

	cmv1 "github.com/openshift-online/ocm-sdk-go/clustersmgmt/v1"
	"github.com/openshift/configuration-anomaly-detection/pkg/aws"
	"github.com/openshift/configuration-anomaly-detection/pkg/ocm"
	"github.com/openshift/configuration-anomaly-detection/pkg/pagerduty"
	hivev1 "github.com/openshift/hive/apis/hive/v1"
)

// Investigation wraps all possible event types and serves as a parent class
// This enables the structure of cmd/investigate.go
// Implement only functions for those event types that are desired
// and are set on the corresponding webhook
// add missing event types you want to implement from this list
// https://support.pagerduty.com/docs/webhooks#supported-resources-and-event-types
// Important: If you add an event type that can return a different data field type
// update the webhook parsing in the pagerduty service accordingly
// https://developer.pagerduty.com/docs/db0fa8c8984fc-overview#event-data-types
type Investigation struct {
	Triggered func(resources *Resources) error
	Resolved  func(resources *Resources) error
	Reopened  func(resources *Resources) error
	Escalated func(resources *Resources) error
}

// NewInvestigation creates a new investigation with default functions that return errors in case they are not overwritten
func NewInvestigation() *Investigation {
	unimplementedFunc := func(_ *Resources) error {
		return errors.New("Investigation not implemented for this alert state")
	}

	return &Investigation{unimplementedFunc, unimplementedFunc, unimplementedFunc, unimplementedFunc}
}

// Resources holds all resources/tools required for alert investigations
type Resources struct {
	AlertType         AlertType
	Cluster           *cmv1.Cluster
	ClusterDeployment *hivev1.ClusterDeployment
	AwsClient         aws.Client
	OcmClient         ocm.Client
	PdClient          pagerduty.Client
}

// AlertType is the struct representing all alerts handled by CAD
type AlertType int64

const (
	// Unsupported represents an alert not defined in CAD
	Unsupported AlertType = iota
	// ClusterHasGoneMissing represents the alert type ClusterHasGoneMissing
	ClusterHasGoneMissing
	// ClusterProvisioningDelay represents the alert type ClusterProvisioningDelay
	ClusterProvisioningDelay
)

func (a AlertType) String() string {
	switch a {
	case ClusterHasGoneMissing:
		return "ClusterHasGoneMissing"
	case ClusterProvisioningDelay:
		return "ClusterProvisioningDelay"
	default:
		return "Unsupported"
	}
}

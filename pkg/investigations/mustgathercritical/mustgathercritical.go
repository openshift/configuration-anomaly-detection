// Package mustgathercritical wraps the mustgather investigation to run on
// critical-severity alerts with a higher sampling rate configured via CAD filters.
package mustgathercritical

import (
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/investigation"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/mustgather"
)

type Investigation struct {
	delegate mustgather.Investigation
}

func (c *Investigation) Run(rb investigation.ResourceBuilder) (investigation.InvestigationResult, error) {
	return c.delegate.Run(rb)
}

func (c *Investigation) Name() string {
	return "mustgathercritical"
}

func (c *Investigation) AlertTitle() string {
	return "CreateMustGatherCritical"
}

func (c *Investigation) Description() string {
	return "creates a must gather for a cluster with a critical alert"
}

func (c *Investigation) IsExperimental() bool {
	return false
}

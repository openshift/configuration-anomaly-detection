package controller

import (
	"context"
	"fmt"
	"os"
	"strconv"

	"github.com/openshift/configuration-anomaly-detection/pkg/investigations"
)

type ManualController struct {
	config CommonConfig
	manual ManualConfig
	investigationRunner
}

func (c *ManualController) Investigate(ctx context.Context) error {
	experimentalEnabledVar := os.Getenv("CAD_EXPERIMENTAL_ENABLED")
	experimentalEnabled, _ := strconv.ParseBool(experimentalEnabledVar)
	alertInvestigation := investigations.GetInvestigationByName(c.manual.InvestigationName, experimentalEnabled)
	if alertInvestigation == nil {
		availableInvestigations := make([]string, 0)
		for _, title := range investigations.GetAvailableInvestigationsNames() {
			availableInvestigations = append(availableInvestigations, fmt.Sprintf("%s, ", title))
		}
		investigations.GetAvailableInvestigationsNames()
		return fmt.Errorf("unknown investigation: %s - must be one of: %v", c.manual.InvestigationName, availableInvestigations)
	}

	// No PD client for manual runs
	return c.runInvestigation(ctx, c.manual.ClusterId, alertInvestigation, nil)
}

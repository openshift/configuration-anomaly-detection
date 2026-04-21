package controller

import (
	"context"
	"fmt"
	"os"
	"strconv"

	"github.com/openshift/configuration-anomaly-detection/pkg/investigations"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/aiassisted"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/investigation"
	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
	"github.com/openshift/configuration-anomaly-detection/pkg/ocm"
	"github.com/openshift/configuration-anomaly-detection/pkg/pagerduty"
	"github.com/openshift/configuration-anomaly-detection/pkg/types"
)

type PagerDutyController struct {
	config   CommonConfig
	pd       PagerDutyConfig
	pdClient *pagerduty.SdkClient
	investigationRunner
}

func (c *PagerDutyController) Investigate(ctx context.Context) error {
	experimentalEnabledVar := os.Getenv("CAD_EXPERIMENTAL_ENABLED")
	experimentalEnabled, _ := strconv.ParseBool(experimentalEnabledVar)
	alertInvestigation := investigations.GetInvestigation(c.pdClient.GetTitle(), experimentalEnabled)

	clusterID, err := c.pdClient.RetrieveClusterID()
	if err != nil {
		return err
	}

	// Update logger with cluster ID now that we have it
	c.logger = logging.InitLogger(c.config.LogLevel, c.config.Identifier, clusterID)
	c.logger.Infof("Investigating incident '%s' for service '%s (%s)'", c.pdClient.GetIncidentRef(), c.pdClient.GetServiceID(), c.pdClient.GetServiceName())

	// If no formal investigation matches, fall back to AI investigation when enabled.
	// AI is considered enabled when experimental mode is on and the filter config
	// has an entry for "aiassisted". The actual cluster/org-level filtering happens
	// later in runInvestigation via the filter evaluation.
	if alertInvestigation == nil && experimentalEnabled {
		alertInvestigation = handleUnsupportedAlertWithAI(c.dependencies)
		if alertInvestigation == nil {
			err := c.pdClient.EscalateIncident()
			if err != nil {
				return fmt.Errorf("could not escalate unsupported alert: %w", err)
			}
			return nil
		}
	}

	// Build the filter context with PagerDuty fields available at this point.
	// OCM fields will be populated inside runInvestigation after precheck.
	filterCtx := &types.FilterContext{
		AlertName:   alertInvestigation.AlertTitle(),
		AlertTitle:  c.pdClient.GetTitle(),
		ServiceName: c.pdClient.GetServiceName(),
	}

	// Continue with investigation...
	return c.runInvestigation(ctx, clusterID, alertInvestigation, c.pdClient, filterCtx, nil)
}

func escalateDocumentationMismatch(docErr *ocm.DocumentationMismatchError, resources *investigation.Resources, pdClient *pagerduty.SdkClient) {
	message := docErr.EscalationMessage()

	if resources != nil && resources.Notes != nil {
		resources.Notes.AppendWarning("%s", message)
		message = resources.Notes.String()
	}

	if pdClient == nil {
		logging.Errorf("Failed to obtain PagerDuty client, unable to escalate documentation mismatch to PagerDuty notes.")
		return
	}

	if err := pdClient.EscalateIncidentWithNote(message); err != nil {
		logging.Errorf("Failed to escalate documentation mismatch notes to PagerDuty: %v", err)
		return
	}

	logging.Info("Escalated documentation mismatch to PagerDuty")
}

// handleUnsupportedAlertWithAI checks if AI investigation is enabled via the filter config.
// AI is considered enabled when the filter config has an entry for "aiassisted".
// Returns an AI investigation populated with the runtime config, or nil if disabled.
func handleUnsupportedAlertWithAI(deps *Dependencies) investigation.Investigation {
	if deps.FilterConfig == nil {
		return nil
	}

	// AI is enabled when the filter config has an entry for "aiassisted".
	// The actual cluster/org-level gating is handled by filter evaluation
	// in runInvestigation after OCM context is populated.
	if deps.FilterConfig.GetFilter("aiassisted") == nil {
		return nil
	}

	return &aiassisted.Investigation{
		AIConfig: deps.FilterConfig.GetAIAgentConfig(),
	}
}

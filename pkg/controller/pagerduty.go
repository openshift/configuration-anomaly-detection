package controller

import (
	"context"
	"fmt"
	"os"
	"strconv"

	"github.com/openshift/configuration-anomaly-detection/pkg/config"
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
	clusterID, err := c.pdClient.RetrieveClusterID()
	if err != nil {
		return err
	}

	// Update logger with cluster ID now that we have it
	c.logger = logging.InitLogger(c.config.LogLevel, c.config.Identifier, clusterID)
	c.logger.Infof("Investigating incident '%s' for service '%s (%s)'", c.pdClient.GetIncidentRef(), c.pdClient.GetServiceID(), c.pdClient.GetServiceName())

	experimentalEnabled, _ := strconv.ParseBool(os.Getenv("CAD_EXPERIMENTAL_ENABLED"))

	cfg := c.dependencies.FilterConfig
	alertTitle := c.pdClient.GetTitle()

	var alertConfig *config.AlertConfig

	// Look up alert config
	if cfg != nil {
		alertConfig = cfg.GetAlert(alertTitle, experimentalEnabled)
	}

	// AI fallback: if no alert matches and ai_agent is configured, build an ad-hoc config
	if alertConfig == nil {
		if experimentalEnabled && cfg != nil && cfg.AIAgent != nil {
			alertConfig = &config.AlertConfig{
				AlertTitle: "aiassisted-fallback",
				Investigations: []config.InvestigationEntry{
					{Name: "precheck"},
					{Name: "aiassisted"},
				},
			}
		} else {
			if escErr := c.pdClient.EscalateIncident(); escErr != nil {
				return fmt.Errorf("could not escalate unsupported alert: %w", escErr)
			}
			return nil
		}
	}

	filterCtx := &types.FilterContext{
		AlertName:   alertConfig.AlertTitle,
		AlertTitle:  alertTitle,
		ServiceName: c.pdClient.GetServiceName(),
	}

	return c.runChain(ctx, clusterID, alertConfig, filterCtx, nil)
}

func escalateDocumentationMismatch(docErr *ocm.DocumentationMismatchError, resources *investigation.Resources, notifier incidentNotifier) {
	message := docErr.EscalationMessage()

	if resources != nil && resources.Notes != nil {
		resources.Notes.AppendWarning("%s", message)
		message = resources.Notes.String()
	}

	if err := notifier.EscalateWithNote(message); err != nil {
		logging.Errorf("Failed to escalate documentation mismatch notes to PagerDuty: %v", err)
		return
	}

	logging.Info("Escalated documentation mismatch to PagerDuty")
}

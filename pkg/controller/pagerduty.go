package controller

import (
	"context"
	"errors"
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

	cfg := c.dependencies.Cfg
	alertTitle := c.pdClient.GetTitle()

	var alertConfig *config.AlertConfig

	// Look up alert config
	if cfg != nil {
		alertConfig = cfg.GetAlert(alertTitle, experimentalEnabled)
	}

	// If we matched a config, try running its chain. If the alert-level When
	// filter rejects, fall through to AI/escalation instead of stopping.
	if alertConfig != nil {
		filterCtx := &types.FilterContext{
			AlertName:   alertConfig.AlertTitle,
			AlertTitle:  alertTitle,
			ServiceName: c.pdClient.GetServiceName(),
		}
		err := c.runChain(ctx, clusterID, alertConfig, filterCtx, nil)
		if !errors.Is(err, errAlertFiltered) {
			return err
		}
		logging.Infof("Alert %q filtered out, falling through to AI/escalation", alertConfig.AlertTitle)
	}

	// AI fallback: no title match, or title matched but when-clause filtered
	if cfg != nil && cfg.AIAgent != nil {
		alertConfig = &config.AlertConfig{
			AlertTitle: "aiassisted-fallback",
			Investigations: []config.InvestigationEntry{
				{Name: "precheck"},
				{Name: "aiassisted"},
			},
		}
		filterCtx := &types.FilterContext{
			AlertName:   alertConfig.AlertTitle,
			AlertTitle:  alertTitle,
			ServiceName: c.pdClient.GetServiceName(),
		}
		return c.runChain(ctx, clusterID, alertConfig, filterCtx, nil)
	}

	if escErr := c.pdClient.EscalateIncident(); escErr != nil {
		return fmt.Errorf("could not escalate unsupported alert: %w", escErr)
	}
	return nil
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

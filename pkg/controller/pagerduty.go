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

	var chainConfig *config.InvestigationConfig

	// Look up chain from config
	if cfg != nil {
		chainConfig = cfg.GetChain(alertTitle, experimentalEnabled)
	}

	// AI fallback: if no chain matches and ai_agent is configured, build an ad-hoc chain
	if chainConfig == nil {
		if experimentalEnabled && cfg != nil && cfg.AIAgent != nil {
			chainConfig = &config.InvestigationConfig{
				AlertTitle: "aiassisted-fallback",
				Chain: []config.ChainEntry{
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
		AlertName:   chainConfig.AlertTitle,
		AlertTitle:  alertTitle,
		ServiceName: c.pdClient.GetServiceName(),
	}

	return c.runChain(ctx, clusterID, chainConfig, c.pdClient, filterCtx, nil)
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


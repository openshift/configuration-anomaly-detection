package controller

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/openshift/configuration-anomaly-detection/pkg/investigations"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/investigation"
	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
	"github.com/openshift/configuration-anomaly-detection/pkg/ocm"
	"github.com/openshift/configuration-anomaly-detection/pkg/pagerduty"
)

type PagerDutyController struct {
	config CommonConfig
	pd     PagerDutyConfig
	investigationRunner
}

func (c *PagerDutyController) Investigate(ctx context.Context) error {
	// Load payload, extract cluster ID and investigation from PD
	payload, err := os.ReadFile(c.pd.PayloadPath)
	if err != nil {
		return fmt.Errorf("failed to read webhook payload: %w", err)
	}

	pdClient, err := pagerduty.GetPDClient(payload)
	if err != nil {
		return fmt.Errorf("could not initialize pagerduty client: %w", err)
	}

	experimentalEnabledVar := os.Getenv("CAD_EXPERIMENTAL_ENABLED")
	experimentalEnabled, _ := strconv.ParseBool(experimentalEnabledVar)
	alertInvestigation := investigations.GetInvestigation(pdClient.GetTitle(), experimentalEnabled)
	clusterID, err := pdClient.RetrieveClusterID()
	if err != nil {
		return err
	}
	c.logger = logging.InitLogger(c.config.LogLevel, c.config.Identifier, clusterID)

	// Escalate all unsupported alerts
	if alertInvestigation == nil {
		err := pdClient.EscalateIncident()
		if err != nil {
			return fmt.Errorf("could not escalate unsupported alert: %w", err)
		}
		return nil
	}

	// Continue with investigation...
	return c.runInvestigation(ctx, clusterID, alertInvestigation, pdClient)
}

func updateIncidentTitle(pdClient *pagerduty.SdkClient) error {
	currentTitle := pdClient.GetTitle()
	if strings.Contains(currentTitle, pagerdutyTitlePrefix) {
		return nil
	}
	newTitle := fmt.Sprintf("%s %s", pagerdutyTitlePrefix, currentTitle)
	err := pdClient.UpdateIncidentTitle(newTitle)
	if err != nil {
		return fmt.Errorf("failed to update PagerDuty incident title: %w", err)
	}
	return nil
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

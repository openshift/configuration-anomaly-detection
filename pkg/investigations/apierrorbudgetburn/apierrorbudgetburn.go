// Package apierrorbudgetburn contains the investigation for api-ErrorBudgetBurn alerts
package apierrorbudgetburn

import (
	"errors"
	"fmt"
	"strings"

	"github.com/openshift/configuration-anomaly-detection/pkg/ai/k8sgpt"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/investigation"
	k8sclient "github.com/openshift/configuration-anomaly-detection/pkg/k8s"
	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
)

type Investigation struct{}

func (c *Investigation) Run(r *investigation.Resources) (investigation.InvestigationResult, error) {
	result := investigation.InvestigationResult{}

	k8sConfig, err := k8sclient.NewCfg(r.Cluster.ID(), r.OcmClient, r.Name)
	if err != nil {
		if errors.Is(err, k8sclient.ErrAPIServerUnavailable) {
			return result, r.PdClient.EscalateIncidentWithNote("CAD was unable to access cluster's kube-api. Please investigate manually.")
		}

		return result, fmt.Errorf("unable to initialize k8s cli config: %w", err)
	}
	defer func() {
		deferErr := k8sConfig.Clean()
		if deferErr != nil {
			logging.Error(deferErr)
			err = errors.Join(err, deferErr)
		}
	}()

	analysis, err := k8sgpt.K8sGptAnalysis(&k8sConfig.Config)
	if err != nil {
		return result, fmt.Errorf("failed to run K8sGptAnalysis: %w", err)
	}

	return result, r.PdClient.EscalateIncidentWithNote(analysis)
}

func (c *Investigation) Name() string {
	return "apierrorbudgetburn"
}

func (c *Investigation) Description() string {
	return "POC Api-ErrorBudgetBurn investigation using k8sgpt."
}

func (c *Investigation) ShouldInvestigateAlert(alert string) bool {
	return strings.Contains(alert, "api-ErrorBudgetBurn")
}

func (c *Investigation) IsExperimental() bool {
	// This is an experimental investigation leveraging k8sgpt.
	return true
}

func (c *Investigation) InformingMode() bool {
	return false
}

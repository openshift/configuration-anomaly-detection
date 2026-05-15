package controller

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/openshift/configuration-anomaly-detection/pkg/investigations"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/aiassisted"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/investigation"
	"github.com/openshift/configuration-anomaly-detection/pkg/metrics"
	"github.com/openshift/configuration-anomaly-detection/pkg/types"
)

// shortNameToInvestigation maps short flag names to their corresponding investigation names.
// This allows users to pass easier-to-type flags when running investigations manually.
var shortNameToInvestigation = map[string]string{
	"ai":                       "aiassisted",
	"can-not-retrieve-updates": "cannotretrieveupdatessre",
	"chgm":                     "Cluster Has Gone Missing (CHGM)",
	"cmbb":                     "clustermonitoringerrorbudgetburn",
	"cpd":                      "ClusterProvisioningDelay",
	"etcd-quota-low":           "etcddatabasequotalowspace",
	"insightsoperatordown":     "insightsoperatordown",
	"machine-health-check":     "machinehealthcheckunterminatedshortcircuitsre",
	"must-gather":              "mustgather",
	"ocmagentresponsefailure":  "ocmagentresponsefailure",
	"restart-controlplane":     "restartcontrolplane",
	"upgrade-config":           "upgradeconfigsyncfailureover4hr",
	"describe-nodes":           "describenodes",
	"cluster-health-check":     "clusterhealthcheck",
}

type ManualController struct {
	config CommonConfig
	manual ManualConfig
	investigationRunner
}

// getInvestigation looks up an investigation by short name first, then falls back to the registry lookup.
func getInvestigation(name string, experimental bool) investigation.Investigation {
	// Check if the name is a short name and map it to the full name
	if fullName, ok := shortNameToInvestigation[name]; ok {
		name = fullName
	}
	return investigations.GetInvestigationByName(name, experimental)
}

func (c *ManualController) Investigate(ctx context.Context) error {
	if c.manual.DryRun {
		c.logger.Info("🔍 DRY RUN MODE: Investigation will run without performing any external operations")
	}

	experimentalEnabledVar := os.Getenv("CAD_EXPERIMENTAL_ENABLED")
	experimentalEnabled, _ := strconv.ParseBool(experimentalEnabledVar)
	alertInvestigation := getInvestigation(c.manual.InvestigationName, experimentalEnabled)
	if alertInvestigation == nil {
		availableInvestigations := make([]string, 0, len(shortNameToInvestigation))
		for shortName, longName := range shortNameToInvestigation {
			format := fmt.Sprintf("- %s (%s)", shortName, longName)
			availableInvestigations = append(availableInvestigations, format)
		}
		investigationList := strings.Join(availableInvestigations, "\n")
		return fmt.Errorf("unknown investigation: %s - must be one of:\n%s", c.manual.InvestigationName, investigationList)
	}

	// Track manual investigation start
	dryRun := formatBool(c.dryRun)
	metrics.Inc(metrics.ManualInvestigationStarted, alertInvestigation.Name(), dryRun)

	// For AI investigations, create a new instance with the runtime config from the global config.
	if _, ok := alertInvestigation.(*aiassisted.Investigation); ok {
		alertInvestigation = &aiassisted.Investigation{
			AIConfig: c.dependencies.FilterConfig.GetAIAgentConfig(),
		}
	}

	// When --with-filtering is set, create a filter context so filters are evaluated.
	// Otherwise pass nil to bypass filtering (default manual behavior).
	var filterCtx *types.FilterContext
	if c.manual.WithFiltering {
		filterCtx = &types.FilterContext{
			AlertName: alertInvestigation.Name(),
		}
	}

	// No PD client for manual runs.
	return c.runInvestigation(ctx, c.manual.ClusterId, alertInvestigation, nil, filterCtx, c.manual.Params)
}

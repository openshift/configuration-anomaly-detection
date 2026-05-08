package controller

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/openshift/configuration-anomaly-detection/pkg/config"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/aiassisted"
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

// resolveInvestigationName maps a short name to the full investigation name.
func resolveInvestigationName(name string) string {
	if fullName, ok := shortNameToInvestigation[name]; ok {
		return fullName
	}
	return name
}

func (c *ManualController) Investigate(ctx context.Context) error {
	if c.manual.DryRun {
		c.logger.Info("🔍 DRY RUN MODE: Investigation will run without performing any external operations")
	}

	name := resolveInvestigationName(c.manual.InvestigationName)
	inv := investigations.GetInvestigationByName(name)
	if inv == nil {
		availableInvestigations := make([]string, 0, len(shortNameToInvestigation))
		for shortName, longName := range shortNameToInvestigation {
			format := fmt.Sprintf("- %s (%s)", shortName, longName)
			availableInvestigations = append(availableInvestigations, format)
		}
		investigationList := strings.Join(availableInvestigations, "\n")
		return fmt.Errorf("unknown investigation: %s - must be one of:\n%s", c.manual.InvestigationName, investigationList)
	}

	// Track manual investigation start
	dryRun := strconv.FormatBool(c.dryRun)
	metrics.Inc(metrics.ManualInvestigationStarted, inv.Name(), dryRun)

	// For AI investigations, create a new instance with the runtime config from the global config.
	if _, ok := inv.(*aiassisted.Investigation); ok {
		inv = &aiassisted.Investigation{
			AIConfig: c.dependencies.FilterConfig.GetAIAgentConfig(),
		}
	}

	chain := []config.ChainEntry{}
	if inv.Name() != "precheck" {
		chain = append(chain, config.ChainEntry{Name: "precheck"})
	}
	if inv.Name() != "ccam" && inv.Name() != "precheck" {
		chain = append(chain, config.ChainEntry{Name: "ccam"})
	}
	chain = append(chain, config.ChainEntry{Name: inv.Name()})

	chainConfig := &config.InvestigationConfig{
		AlertTitle: inv.Name(),
		Chain:      chain,
	}

	// When --with-filtering is set, create a filter context so filters are evaluated.
	// Otherwise pass nil to bypass filtering (default manual behavior).
	var filterCtx *types.FilterContext
	if c.manual.WithFiltering {
		filterCtx = &types.FilterContext{
			AlertName: inv.Name(),
		}
	}

	// No PD client for manual runs.
	return c.runChain(ctx, c.manual.ClusterId, chainConfig, nil, filterCtx, c.manual.Params)
}

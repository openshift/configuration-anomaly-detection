package analyzers

import (
	"fmt"
	"time"

	configv1 "github.com/openshift/api/config/v1"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/diagnosticcollection/findings"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/diagnosticcollection/parsers"
)

const (
	// UpgradeStuckThreshold is how long an upgrade can run before being considered stuck
	UpgradeStuckThreshold = 4 * time.Hour
)

// ClusterVersionAnalyzer analyzes ClusterVersion resources for upgrade issues
type ClusterVersionAnalyzer struct{}

// NewClusterVersionAnalyzer creates a new ClusterVersion analyzer
func NewClusterVersionAnalyzer() *ClusterVersionAnalyzer {
	return &ClusterVersionAnalyzer{}
}

// Name returns the analyzer name
func (a *ClusterVersionAnalyzer) Name() string {
	return "ClusterVersion"
}

// Analyze examines ClusterVersion data and returns findings
func (a *ClusterVersionAnalyzer) Analyze(inspectDir string) (*findings.Findings, error) {
	f := findings.New()

	// Parse ClusterVersion
	cvInfo, err := parsers.ParseClusterVersion(inspectDir)
	if err != nil {
		return nil, fmt.Errorf("failed to parse clusterversion: %w", err)
	}

	// Add basic version info
	f.AddInfo(
		"Cluster Version Information",
		fmt.Sprintf("Current: %s\nDesired: %s\nUpgrading: %v",
			cvInfo.CurrentVersion, cvInfo.DesiredVersion, cvInfo.IsUpgrading),
	)

	// Check if upgrade is stuck
	if cvInfo.IsUpgradeStuck(UpgradeStuckThreshold) {
		duration := cvInfo.GetUpgradeDuration()
		f.AddCritical(
			"Upgrade Stuck",
			fmt.Sprintf("Upgrade from %s to %s has been running for %v (threshold: %v)",
				cvInfo.CurrentVersion, cvInfo.DesiredVersion,
				duration.Round(time.Minute), UpgradeStuckThreshold),
			"Check degraded cluster operators and machine config pools",
		)
	} else if cvInfo.IsUpgrading {
		duration := cvInfo.GetUpgradeDuration()
		f.AddInfo(
			"Upgrade In Progress",
			fmt.Sprintf("Upgrade to %s started %v ago",
				cvInfo.DesiredVersion, duration.Round(time.Minute)),
		)
	}

	// Check for Progressing=False when upgrade is expected
	if cvInfo.DesiredVersion != "" && cvInfo.DesiredVersion != cvInfo.CurrentVersion {
		if progressingCond := cvInfo.GetCondition(configv1.OperatorProgressing); progressingCond != nil && progressingCond.Status == configv1.ConditionFalse {
			f.AddWarning(
				"Upgrade Not Progressing",
				fmt.Sprintf("Desired version %s but Progressing=False\nReason: %s\nMessage: %s",
					cvInfo.DesiredVersion, progressingCond.Reason, progressingCond.Message),
				"Check if there are blockers preventing the upgrade from starting",
			)
		}
	}

	// Check Available condition
	if availableCond := cvInfo.GetCondition(configv1.OperatorAvailable); availableCond != nil && availableCond.Status == configv1.ConditionFalse {
		f.AddCritical(
			"Cluster Not Available",
			fmt.Sprintf("Reason: %s\nMessage: %s", availableCond.Reason, availableCond.Message),
			"Cluster is not available - investigate immediately",
		)
	}

	return f, nil
}

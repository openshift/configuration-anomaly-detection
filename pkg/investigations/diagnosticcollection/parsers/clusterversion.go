package parsers

import (
	"fmt"
	"time"

	configv1 "github.com/openshift/api/config/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ClusterVersionInfo contains parsed information from ClusterVersion resource
type ClusterVersionInfo struct {
	// Name of the ClusterVersion resource (usually "version")
	Name string
	// CurrentVersion is the current cluster version
	CurrentVersion string
	// DesiredVersion is the target version for upgrade
	DesiredVersion string
	// Conditions contains the status conditions
	Conditions []configv1.ClusterOperatorStatusCondition
	// History contains the update history
	History []configv1.UpdateHistory
	// IsUpgrading indicates if an upgrade is in progress
	IsUpgrading bool
	// UpgradeStartTime is when the current upgrade started (if applicable)
	UpgradeStartTime *metav1.Time
}

// ParseClusterVersion parses ClusterVersion YAML files from inspect output
func ParseClusterVersion(inspectDir string) (*ClusterVersionInfo, error) {
	// Find ClusterVersion YAML files
	files, err := FindYAMLFilesByPattern(inspectDir, "clusterversions")
	if err != nil {
		return nil, fmt.Errorf("failed to find clusterversion files: %w", err)
	}

	if len(files) == 0 {
		return nil, fmt.Errorf("no clusterversion files found in %s", inspectDir)
	}

	// Usually there's only one ClusterVersion resource named "version"
	// Parse the first one found
	var cv configv1.ClusterVersion
	if err := ReadYAMLFile(files[0], &cv); err != nil {
		return nil, fmt.Errorf("failed to parse clusterversion: %w", err)
	}

	info := &ClusterVersionInfo{
		Name:       cv.Name,
		Conditions: cv.Status.Conditions,
		History:    cv.Status.History,
	}

	// Extract current version from history (most recent completed update)
	if len(cv.Status.History) > 0 {
		info.CurrentVersion = cv.Status.History[0].Version
	}

	// Extract desired version from desired update
	if cv.Spec.DesiredUpdate != nil {
		info.DesiredVersion = cv.Spec.DesiredUpdate.Version
	}

	// Determine if upgrade is in progress
	info.IsUpgrading = isUpgrading(&cv)

	// Get upgrade start time if upgrading
	if info.IsUpgrading && len(cv.Status.History) > 0 {
		info.UpgradeStartTime = &cv.Status.History[0].StartedTime
	}

	return info, nil
}

// isUpgrading checks if the cluster is currently upgrading
func isUpgrading(cv *configv1.ClusterVersion) bool {
	for _, condition := range cv.Status.Conditions {
		if condition.Type == configv1.OperatorProgressing {
			return condition.Status == configv1.ConditionTrue
		}
	}
	return false
}

// GetCondition returns a specific condition by type
func (c *ClusterVersionInfo) GetCondition(conditionType configv1.ClusterStatusConditionType) *configv1.ClusterOperatorStatusCondition {
	for i := range c.Conditions {
		if c.Conditions[i].Type == conditionType {
			return &c.Conditions[i]
		}
	}
	return nil
}

// GetUpgradeDuration returns how long the upgrade has been running
func (c *ClusterVersionInfo) GetUpgradeDuration() time.Duration {
	if !c.IsUpgrading || c.UpgradeStartTime == nil {
		return 0
	}
	return time.Since(c.UpgradeStartTime.Time)
}

// IsUpgradeStuck returns true if upgrade has been running for more than the threshold
func (c *ClusterVersionInfo) IsUpgradeStuck(threshold time.Duration) bool {
	return c.IsUpgrading && c.GetUpgradeDuration() > threshold
}

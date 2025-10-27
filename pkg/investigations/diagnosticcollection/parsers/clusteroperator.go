package parsers

import (
	"fmt"

	configv1 "github.com/openshift/api/config/v1"
)

// ClusterOperatorInfo contains parsed information from a single ClusterOperator
type ClusterOperatorInfo struct {
	// Name of the operator (e.g., "authentication", "ingress", "kube-apiserver")
	Name string
	// Conditions contains the status conditions
	Conditions []configv1.ClusterOperatorStatusCondition
	// IsDegraded indicates if the operator is degraded
	IsDegraded bool
	// IsAvailable indicates if the operator is available
	IsAvailable bool
	// IsProgressing indicates if the operator is progressing
	IsProgressing bool
	// DegradedMessage contains the degraded condition message if degraded
	DegradedMessage string
	// DegradedReason contains the degraded condition reason if degraded
	DegradedReason string
}

// ParseClusterOperators parses all ClusterOperator YAML files from inspect output
func ParseClusterOperators(inspectDir string) ([]ClusterOperatorInfo, error) {
	// Find ClusterOperator YAML files
	files, err := FindYAMLFilesByPattern(inspectDir, "clusteroperators")
	if err != nil {
		return nil, fmt.Errorf("failed to find clusteroperator files: %w", err)
	}

	if len(files) == 0 {
		return nil, fmt.Errorf("no clusteroperator files found in %s", inspectDir)
	}

	var operators []ClusterOperatorInfo

	for _, file := range files {
		var co configv1.ClusterOperator
		if err := ReadYAMLFile(file, &co); err != nil {
			// Log warning but continue with other files
			fmt.Printf("Warning: failed to parse %s: %v\n", file, err)
			continue
		}

		info := parseClusterOperatorInfo(&co)
		operators = append(operators, info)
	}

	return operators, nil
}

// parseClusterOperatorInfo extracts information from a ClusterOperator resource
func parseClusterOperatorInfo(co *configv1.ClusterOperator) ClusterOperatorInfo {
	info := ClusterOperatorInfo{
		Name:       co.Name,
		Conditions: co.Status.Conditions,
	}

	// Check conditions
	for _, condition := range co.Status.Conditions {
		switch condition.Type {
		case configv1.OperatorDegraded:
			info.IsDegraded = condition.Status == configv1.ConditionTrue
			if info.IsDegraded {
				info.DegradedMessage = condition.Message
				info.DegradedReason = condition.Reason
			}
		case configv1.OperatorAvailable:
			info.IsAvailable = condition.Status == configv1.ConditionTrue
		case configv1.OperatorProgressing:
			info.IsProgressing = condition.Status == configv1.ConditionTrue
		}
	}

	return info
}

// GetCondition returns a specific condition by type
func (c *ClusterOperatorInfo) GetCondition(conditionType configv1.ClusterStatusConditionType) *configv1.ClusterOperatorStatusCondition {
	for i := range c.Conditions {
		if c.Conditions[i].Type == conditionType {
			return &c.Conditions[i]
		}
	}
	return nil
}

// HasIssues returns true if the operator has any issues (degraded or not available)
func (c *ClusterOperatorInfo) HasIssues() bool {
	return c.IsDegraded || !c.IsAvailable
}

// GetDegradedOperators filters a list of operators to return only degraded ones
func GetDegradedOperators(operators []ClusterOperatorInfo) []ClusterOperatorInfo {
	var degraded []ClusterOperatorInfo
	for _, op := range operators {
		if op.IsDegraded {
			degraded = append(degraded, op)
		}
	}
	return degraded
}

// GetUnavailableOperators filters a list of operators to return only unavailable ones
func GetUnavailableOperators(operators []ClusterOperatorInfo) []ClusterOperatorInfo {
	var unavailable []ClusterOperatorInfo
	for _, op := range operators {
		if !op.IsAvailable {
			unavailable = append(unavailable, op)
		}
	}
	return unavailable
}

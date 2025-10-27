package analyzers

import "github.com/openshift/configuration-anomaly-detection/pkg/investigations/diagnosticcollection/findings"

// ResourceAnalyzer is the interface that all resource analyzers must implement
// Each analyzer examines a specific type of resource (ClusterVersion, ClusterOperator, etc.)
// and produces findings based on the resource state
type ResourceAnalyzer interface {
	// Analyze examines the resource data and returns findings
	// The input is the directory path containing the collected resource YAML files
	Analyze(inspectDir string) (*findings.Findings, error)

	// Name returns the name of this analyzer (for logging/debugging)
	Name() string
}

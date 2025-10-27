package diagnosticcollection

// DiagnosticMapping defines which resources to inspect for a given alert type
type DiagnosticMapping struct {
	// AlertPattern is the string pattern to match in the alert name
	AlertPattern string
	// Resources is the list of resources to pass to `oc adm inspect`
	// Examples: "clusterversion", "clusteroperators", "ns/openshift-monitoring"
	Resources []string
	// Description explains what this mapping collects
	Description string
}

// diagnosticMappings contains all alert-to-resource mappings
// To add a new alert type, simply add a new entry here
var diagnosticMappings = []DiagnosticMapping{
	{
		AlertPattern: "UpgradeConfigSyncFailure",
		Resources:    []string{"clusterversion", "clusteroperators"},
		Description:  "Collects upgrade status and operator health for stuck upgrades",
	},
	// Easy to add more mappings:
	// {
	// 	AlertPattern: "InsightsOperatorDown",
	// 	Resources:    []string{"clusteroperator/insights", "ns/openshift-insights"},
	// 	Description:  "Collects insights operator status and namespace resources",
	// },
}

// GetMappingForAlert returns the diagnostic mapping for a given alert name
// Returns nil if no mapping is found
func GetMappingForAlert(alertName string) *DiagnosticMapping {
	for i := range diagnosticMappings {
		mapping := &diagnosticMappings[i]
		if containsPattern(alertName, mapping.AlertPattern) {
			return mapping
		}
	}
	return nil
}

// containsPattern checks if the alert name contains the pattern
// This is a simple string contains check, but can be enhanced with regex if needed
func containsPattern(alertName, pattern string) bool {
	return len(alertName) > 0 && len(pattern) > 0 &&
		   (alertName == pattern || contains(alertName, pattern))
}

// contains is a simple helper to avoid importing strings just for this
func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

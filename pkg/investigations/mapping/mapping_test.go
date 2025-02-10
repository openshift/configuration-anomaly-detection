package investigation_mapping

import (
	"os"
	"testing"
)

// Helper function to set up environment variable for tests.
func setExperimentalEnv(enabled bool) {
	if enabled {
		_ = os.Setenv("CAD_EXPERIMENTAL_ENABLED", "TRUE")
	} else {
		_ = os.Unsetenv("CAD_EXPERIMENTAL_ENABLED")
	}
}

func TestGetInvestigation(t *testing.T) {
	tests := []struct {
		name            string
		alertTitle      string
		experimentalEnv bool
		expectedType    string
	}{
		{
			name:            "Standard investigation - Cluster has gone missing",
			alertTitle:      "testingcluster cluster has gone missing",
			experimentalEnv: false,
			expectedType:    "ClusterHasGoneMissing",
		},
		{
			name:            "Standard investigation - Cluster provisioning delay",
			alertTitle:      "ClusterProvisioningDelay - production",
			experimentalEnv: false,
			expectedType:    "ClusterProvisioningDelay",
		},
		{
			name:            "Experimental feature enabled - ClusterMonitoringErrorBudgetBurnSRE",
			alertTitle:      "ClusterMonitoringErrorBudgetBurnSRE ",
			experimentalEnv: true,
			expectedType:    "clustermonitoringerrorbudgetburn",
		},
		{
			name:            "Experimental feature disabled - ClusterMonitoringErrorBudgetBurnSRE",
			alertTitle:      "ClusterMonitoringErrorBudgetBurnSRE detected",
			experimentalEnv: false,
			expectedType:    "",
		},
		{
			name:            "No matching investigation",
			alertTitle:      "Unrelated alert title",
			experimentalEnv: false,
			expectedType:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setExperimentalEnv(tt.experimentalEnv)
			result := GetInvestigation(tt.alertTitle)

			if tt.expectedType == "" {
				if result != nil {
					t.Errorf("Expected nil, but got %v", result.Name)
				}
			} else {
				if result == nil || result.Name != tt.expectedType {
					t.Errorf("Expected %v, but got %v", tt.expectedType, result)
				}
			}
		})
	}
}

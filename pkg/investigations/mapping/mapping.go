package investigation_mapping

import (
	"os"
	"strings"

	investigation "github.com/openshift/configuration-anomaly-detection/pkg/investigations"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/chgm"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/clustermonitoringerrorbudgetburn"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/cpd"
	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
)

// GetInvestigation will return the investigation function for the identified alert
func GetInvestigation(alertTitle string) *investigation.Investigation {
	// We currently map to the alert by using the title, we should use the name in the alert note in the future.
	// This currently isn't feasible yet, as CPD's alertmanager doesn't allow for the field to exist.

	// We can't switch case here as it's strings.Contains.
	if strings.Contains(alertTitle, "has gone missing") {
		return investigation.NewInvestigation(chgm.Investigate, "ClusterHasGoneMissing")
	} else if strings.Contains(alertTitle, "ClusterProvisioningDelay -") {
		return investigation.NewInvestigation(cpd.Investigate, "ClusterProvisioningDelay")
	}

	// Return early if experimental features are not enabled
	if strings.ToUpper(os.Getenv("CAD_EXPERIMENTAL_ENABLED")) != "TRUE" {
		return nil
	}

	logging.Warn("Flag CAD_EXPERIMENTAL_ENABLED is set, experimental CAD investigations are enabled!")

	// Experimental investigations go here
	if strings.Contains(alertTitle, "ClusterMonitoringErrorBudgetBurnSRE") {
		return investigation.NewInvestigation(clustermonitoringerrorbudgetburn.Investigate, "ClusterMonitoringErrorBudgetBurnSRE")
	}

	return nil
}

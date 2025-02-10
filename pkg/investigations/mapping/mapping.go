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
//
// Please note that when adding an investigation the name and the directory need to be the same,
// so that backplane-api can fetch the metadata.yaml
func GetInvestigation(alertTitle string) *investigation.Investigation {
	// We currently map to the alert by using the title, we should use the name in the alert note in the future.
	// This currently isn't feasible yet, as CPD's alertmanager doesn't allow for the field to exist.
	switch {
	case strings.Contains(alertTitle, "has gone missing"):
		return investigation.NewInvestigation(chgm.Investigate, "ClusterHasGoneMissing")
	case strings.Contains(alertTitle, "ClusterProvisioningDelay -"):
		return investigation.NewInvestigation(cpd.Investigate, "ClusterProvisioningDelay")
	}

	if experimentalFeaturesEnabled() {
		logging.Warn("Flag CAD_EXPERIMENTAL_ENABLED is set, experimental CAD investigations are enabled!")

		// We don't care this is a single case switch (gocritic), this should just be extensible
		switch { //nolint:gocritic
		case strings.Contains(alertTitle, "ClusterMonitoringErrorBudgetBurnSRE"):
			return investigation.NewInvestigation(clustermonitoringerrorbudgetburn.Investigate, "clustermonitoringerrorbudgetburn")
		}
	}

	logging.Infof("No investigation exists for %s", alertTitle)
	return nil
}

func experimentalFeaturesEnabled() bool {
	return strings.ToUpper(os.Getenv("CAD_EXPERIMENTAL_ENABLED")) == "TRUE"
}

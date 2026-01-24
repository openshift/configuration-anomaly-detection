package investigations

import (
	"strings"

	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/cannotretrieveupdatessre"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/chgm"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/clustermonitoringerrorbudgetburn"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/cpd"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/etcddatabasequotalowspace"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/insightsoperatordown"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/investigation"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/machinehealthcheckunterminatedshortcircuitsre"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/mustgather"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/upgradeconfigsyncfailureover4hr"
)

// availableInvestigations holds all Investigation implementations.
var availableInvestigations = []investigation.Investigation{
	&chgm.Investigation{},
	&clustermonitoringerrorbudgetburn.Investigation{},
	&cpd.Investigation{},
	&etcddatabasequotalowspace.Investigation{},
	&insightsoperatordown.Investigation{},
	&upgradeconfigsyncfailureover4hr.Investigation{},
	&machinehealthcheckunterminatedshortcircuitsre.Investigation{},
	&cannotretrieveupdatessre.Investigation{},
	&mustgather.Investigation{},
}

// GetInvestigation returns the first Investigation that applies to the given alert title.
// Returns nil if no formal investigation matches.
func GetInvestigation(title string, experimental bool) investigation.Investigation {
	for _, inv := range availableInvestigations {
		if strings.Contains(title, inv.AlertTitle()) && (experimental || !inv.IsExperimental()) {
			return inv
		}
	}
	return nil
}

// GetAvailableInvestigationsTitles returns a string array with the alert titles of all available investigations.
func GetAvailableInvestigationsTitles() []string {
	alertTitles := make([]string, 0, len(availableInvestigations))

	for _, inv := range availableInvestigations {
		alertTitles = append(alertTitles, inv.AlertTitle())
	}
	return alertTitles
}

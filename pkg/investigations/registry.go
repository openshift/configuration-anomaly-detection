package investigations

import (
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/aiassisted"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/cannotretrieveupdatessre"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/ccam"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/chgm"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/clusterhealthcheck"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/clustermonitoringerrorbudgetburn"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/consoleerrorbudgetburn"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/cpd"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/describenodes"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/etcddatabasequotalowspace"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/expiredcertificates"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/insightsoperatordown"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/investigation"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/machinehealthcheckunterminatedshortcircuitsre"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/mustgather"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/ocmagentresponsefailure"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/pdbblockingnodedrain"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/precheck"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/restartcontrolplane"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/upgradeconfigsyncfailureover4hr"
)

// availableInvestigations holds all Investigation implementations.
var availableInvestigations = []investigation.Investigation{
	&precheck.ClusterStatePrecheck{},
	&ccam.CloudCredentialsCheck{},
	&aiassisted.Investigation{},
	&chgm.Investigation{},
	&clustermonitoringerrorbudgetburn.Investigation{},
	&cpd.Investigation{},
	&etcddatabasequotalowspace.Investigation{},
	&insightsoperatordown.Investigation{},
	&upgradeconfigsyncfailureover4hr.Investigation{},
	&machinehealthcheckunterminatedshortcircuitsre.Investigation{},
	&ocmagentresponsefailure.Investigation{},
	&restartcontrolplane.Investigation{},
	&cannotretrieveupdatessre.Investigation{},
	&mustgather.Investigation{},
	&describenodes.Investigation{},
	&clusterhealthcheck.Investigation{},
	&consoleerrorbudgetburn.Investigation{},
	&expiredcertificates.Investigation{},
	&pdbblockingnodedrain.Investigation{},
}

// GetInvestigationByName returns the Investigation with the given name, or nil if not found.
func GetInvestigationByName(name string) investigation.Investigation {
	for _, inv := range availableInvestigations {
		if inv.Name() == name {
			return inv
		}
	}
	return nil
}

// GetAvailableInvestigationsNames returns a string array with the names of all available investigations.
func GetAvailableInvestigationsNames() []string {
	alertNames := make([]string, 0, len(availableInvestigations))

	for _, inv := range availableInvestigations {
		alertNames = append(alertNames, inv.Name())
	}
	return alertNames
}

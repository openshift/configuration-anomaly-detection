package investigations

import (
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/ccam"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/chgm"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/clustermonitoringerrorbudgetburn"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/cpd"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/investigation"
)

// availableInvestigations holds all Investigation implementations.
var availableInvestigations = []investigation.Investigation{
	&ccam.Investigation{},
	&chgm.Investiation{},
	&clustermonitoringerrorbudgetburn.Investigation{},
	&cpd.Investigation{},
}

// GetInvestigation returns the first Investigation that applies to the given alert title.
// This is a naive version that only returns the first matching investigation and ignores the rest.
// Future improvement is to use the proper mapping that can return multiple investigations
// linked to single alert type.
func GetInvestigation(title string, experimental bool) investigation.Investigation {
	for _, inv := range availableInvestigations {
		if inv.ShouldInvestigateAlert(title) && (experimental || !inv.IsExperimental()) {
			return inv
		}
	}
	return nil
}

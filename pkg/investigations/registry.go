package investigations

import (
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/ccam"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/chgm"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/clustermonitoringerrorbudgetburn"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/cpd"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/insightsoperatordown"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/investigation"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/upgradeconfigsyncfailureover4hr"
)

// investigationInstances holds all Investigation implementations by name.
var investigationInstances = map[string]investigation.Investigation{
	(&ccam.Investigation{}).Name():                             &ccam.Investigation{},
	(&chgm.Investiation{}).Name():                              &chgm.Investiation{},
	(&clustermonitoringerrorbudgetburn.Investigation{}).Name(): &clustermonitoringerrorbudgetburn.Investigation{},
	(&cpd.Investigation{}).Name():                              &cpd.Investigation{},
	(&insightsoperatordown.Investigation{}).Name():             &insightsoperatordown.Investigation{},
	(&upgradeconfigsyncfailureover4hr.Investigation{}).Name():  &upgradeconfigsyncfailureover4hr.Investigation{},
}

// availableInvestigations maps investigation name to its description.
var availableInvestigations = func() map[string]string {
	m := make(map[string]string)
	for name, inv := range investigationInstances {
		m[name] = inv.Description()
	}
	return m
}()

// GetInvestigation returns the first Investigation that applies to the given alert title.
// This is a naive version that only returns the first matching investigation and ignores the rest.
// Future improvement is to use the proper mapping that can return multiple investigations
// linked to single alert type.
func GetInvestigation(title string, experimental bool) investigation.Investigation {
	for _, inv := range investigationInstances {
		if inv.ShouldInvestigateAlert(title) && (experimental || !inv.IsExperimental()) {
			return inv
		}
	}
	return nil
}

// GetInvestigationByName returns the Investigation instance by its name.
func GetInvestigationByName(name string) investigation.Investigation {
	return investigationInstances[name]
}

// GetAllInvestigations returns a map of investigation name to description.
func GetAllInvestigations() map[string]string {
	return availableInvestigations
}

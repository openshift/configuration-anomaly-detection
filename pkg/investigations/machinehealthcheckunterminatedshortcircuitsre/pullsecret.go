/*
machinehealthcheckunterminatedshortcircuitsre defines the investigation logic for the MachineHealthCheckUnterminatedShortCircuitSRE alert
*/
package machinehealthcheckunterminatedshortcircuitsre

import (
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/investigation"
	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
	"github.com/openshift/configuration-anomaly-detection/pkg/pullsecret"
)

// validatePullSecret compares the cluster's pull secret against the owning account in OCM.
//
// A pull secret whose registry credentials no longer match OCM stops the kubelet from pulling
// images, which is one of the ways a group of worker nodes goes NotReady at once and short-circuits
// the machinehealthcheck. The check only runs once the investigation has already found a NotReady
// node, since that is the only state in which it is diagnostically relevant.
//
// This is note-only: CAD never rewrites a cluster's pull secret. Remediation steps live in
// https://github.com/openshift/ops-sop/blob/master/v4/alerts/UpgradeConfigSyncFailureOver4HrSRE.md
func (i *Investigation) validatePullSecret(r *investigation.Resources) {
	// Not every caller builds an OCM client (the unit tests do not), and the pull secret cannot be
	// compared against anything without one.
	if r.OcmClient == nil {
		return
	}

	user, err := r.OcmClient.GetCreatorFromCluster(r.Cluster)
	if err != nil {
		i.notes.AppendWarning("could not retrieve the cluster creator from OCM, so the pull secret was not validated: %v", err)
		return
	}

	emailValidation := pullsecret.ValidateEmail(r.K8sClient, user.Email())
	registryValidation, registryResults := pullsecret.ValidateRegistryCredentials(r.K8sClient, r.OcmClient.GetConnection(), user.ID(), user.Email())

	warnings := make([]string, 0, len(emailValidation.Warnings)+len(registryValidation.Warnings))
	warnings = append(warnings, emailValidation.Warnings...)
	warnings = append(warnings, registryValidation.Warnings...)

	// Per-registry detail is noise in a PagerDuty note, but useful when debugging the check itself.
	for _, registryResult := range registryResults {
		if registryResult.Error != nil {
			logging.Debugf("Registry %q: error=%v", registryResult.Registry, registryResult.Error)
			continue
		}
		logging.Debugf("Registry %q: emailMatch=%v, tokenMatch=%v", registryResult.Registry, registryResult.EmailMatch, registryResult.TokenMatch)
	}

	if len(warnings) == 0 {
		i.notes.AppendSuccess("pull secret matches on cluster and in OCM, so image pulls are not the reason these nodes are NotReady")
		return
	}

	for _, warning := range warnings {
		i.notes.AppendWarning("pull secret: %s", warning)
	}
}

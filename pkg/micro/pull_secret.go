package micro

import (
	"fmt"

	sdk "github.com/openshift-online/ocm-sdk-go"
	"github.com/openshift/configuration-anomaly-detection/pkg/executor"
	k8sclient "github.com/openshift/configuration-anomaly-detection/pkg/k8s"
	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
	"github.com/openshift/configuration-anomaly-detection/pkg/notewriter"
	"github.com/openshift/configuration-anomaly-detection/pkg/pullsecret"
	"github.com/openshift/configuration-anomaly-detection/pkg/types"
)

// PullSecret validates the cluster's pull secret against OCM.
// Always returns Done: true — both valid and invalid pull secrets are
// terminal findings (valid → silence, invalid → escalate).
func PullSecret(k8sClient k8sclient.Client, ocmConn *sdk.Connection, userID, ocmEmail string, notes *notewriter.NoteWriter) (Result, error) {
	if _, err := pullsecret.GetPullSecret(k8sClient); err != nil {
		return Result{}, fmt.Errorf("failed to get pull secret: %w", err)
	}

	emailValidation := pullsecret.ValidateEmail(k8sClient, ocmEmail)

	for _, warning := range emailValidation.Warnings {
		notes.AppendWarning("%s", warning)
	}

	if emailValidation.IsValid && len(emailValidation.Warnings) == 0 {
		notes.AppendSuccess("Pull secret email matches on cluster and in OCM.")
	}

	registryValidation, registryResults := pullsecret.ValidateRegistryCredentials(k8sClient, ocmConn, userID, ocmEmail)

	for _, regResult := range registryResults {
		if regResult.Error != nil {
			logging.Debugf("Registry '%s': error=%v", regResult.Registry, regResult.Error)
		} else {
			logging.Debugf("Registry '%s': emailMatch=%v, tokenMatch=%v", regResult.Registry, regResult.EmailMatch, regResult.TokenMatch)
		}
	}

	for _, warning := range registryValidation.Warnings {
		notes.AppendWarning("%s", warning)
	}

	if emailValidation.IsValid && registryValidation.IsValid {
		return Result{
			Done: true,
			Actions: []types.Action{
				executor.Silence("Pull secret is valid - no customer-side issue detected"),
			},
		}, nil
	}

	return Result{
		Done: true,
		Actions: []types.Action{
			executor.Escalate("Pull secret issue detected - review notes for details"),
		},
	}, nil
}

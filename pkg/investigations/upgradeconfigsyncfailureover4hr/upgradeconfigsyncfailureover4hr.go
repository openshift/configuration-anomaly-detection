// Package upgradeconfigsyncfailureover4hr contains functionality for the UpgradeConfigSyncFailureOver4HrSRE investigation
package upgradeconfigsyncfailureover4hr

import (
	"errors"

	"github.com/openshift/configuration-anomaly-detection/pkg/executor"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/investigation"
	k8sclient "github.com/openshift/configuration-anomaly-detection/pkg/k8s"
	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
	"github.com/openshift/configuration-anomaly-detection/pkg/notewriter"
	"github.com/openshift/configuration-anomaly-detection/pkg/ocm"
	"github.com/openshift/configuration-anomaly-detection/pkg/pullsecret"
	"github.com/openshift/configuration-anomaly-detection/pkg/types"
)

type Investigation struct{}

func (c *Investigation) Run(rb investigation.ResourceBuilder) (investigation.InvestigationResult, error) {
	result := investigation.InvestigationResult{}
	r, err := rb.Build()
	if err != nil {
		return result, err
	}
	notes := notewriter.New("UpgradeConfigSyncFailureOver4Hr", logging.RawLogger)

	logging.Infof("Checking if user is Banned.")
	userBannedStatus, userBannedNotes, err := ocm.CheckIfUserBanned(r.OcmClient, r.Cluster)
	if err != nil {
		notes.AppendWarning("encountered an issue when checking if the cluster owner is banned: %s\nPlease investigate.", err)
		result.Actions = append(
			executor.NoteAndReportFrom(notes, r.Cluster.ID(), c.Name()),
			executor.Escalate("Failed to check if user is banned"),
		)
		return result, nil
	}
	if userBannedStatus {
		notes.AppendWarning("%s", userBannedNotes)
	} else {
		notes.AppendSuccess("User is not banned.")
	}
	user, err := ocm.GetCreatorFromCluster(r.OcmClient.GetConnection(), r.Cluster)
	logging.Infof("User ID is: %v", user.ID())
	if err != nil {
		notes.AppendWarning("Failed getting cluster creator from ocm: %s", err)
		result.Actions = append(
			executor.NoteAndReportFrom(notes, r.Cluster.ID(), c.Name()),
			executor.Escalate("Failed to get cluster creator from OCM"),
		)
		return result, nil
	}

	r, err = rb.WithK8sClient().Build()
	if err != nil {
		k8sErr := &investigation.K8SClientError{}
		if errors.As(err, k8sErr) {
			if errors.Is(k8sErr.Err, k8sclient.ErrAPIServerUnavailable) {
				result.Actions = []types.Action{
					executor.Note("CAD was unable to access cluster's kube-api. Please investigate manually."),
					executor.Escalate("Cluster API unavailable"),
				}
				return result, nil
			}
			if errors.Is(k8sErr.Err, k8sclient.ErrCannotAccessInfra) {
				result.Actions = []types.Action{
					executor.Note("CAD is not allowed to access hive, management or service cluster's kube-api. Please investigate manually."),
					executor.Escalate("Cannot access infrastructure"),
				}
				return result, nil
			}
			return result, investigation.WrapInfrastructure(k8sErr.Err, "K8s client error")
		}
		return result, investigation.WrapInfrastructure(err, "Resource build error")
	}

	// Pullsecret validation done via pullsecret package
	ocmEmail := user.Email()
	emailValidation := pullsecret.ValidateEmail(r.K8sClient, ocmEmail)

	for _, warning := range emailValidation.Warnings {
		notes.AppendWarning("%s", warning)
	}

	if emailValidation.IsValid && len(emailValidation.Warnings) == 0 {
		notes.AppendSuccess("Pull Secret matches on cluster and in OCM. Please continue investigation.")
	}

	// Registry credentials validation
	registryValidation, registryResults := pullsecret.ValidateRegistryCredentials(r.K8sClient, r.OcmClient.GetConnection(), user.ID(), ocmEmail)

	// INFO: per-registry validation results at debug level for troubleshooting
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

	result.Actions = append(
		executor.NoteAndReportFrom(notes, r.Cluster.ID(), c.Name()),
		executor.Escalate("UpgradeConfigSyncFailure investigation complete"),
	)
	return result, nil
}

func (c *Investigation) Name() string {
	return "upgradeconfigsyncfailureover4hr"
}

func (c *Investigation) AlertTitle() string {
	return "UpgradeConfigSyncFailureOver4HrSRE"
}

func (c *Investigation) Description() string {
	return "Investigates the UpgradeConfigSyncFailureOver4hr alert"
}

func (c *Investigation) IsExperimental() bool {
	return false
}

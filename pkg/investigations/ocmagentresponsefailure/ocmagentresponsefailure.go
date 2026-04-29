// Package ocmagentresponsefailure implements the investigation logic
// for the "OCMAgentResponseFailureServiceLogsSRE" alert.
package ocmagentresponsefailure

import (
	"errors"
	"os"
	"strconv"

	"github.com/openshift/configuration-anomaly-detection/pkg/executor"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/investigation"
	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
	"github.com/openshift/configuration-anomaly-detection/pkg/networkverifier"
	"github.com/openshift/configuration-anomaly-detection/pkg/ocm"
	"github.com/openshift/configuration-anomaly-detection/pkg/pullsecret"
	"github.com/openshift/configuration-anomaly-detection/pkg/types"
)

type Investigation struct{}

type check func(*investigation.Resources) (checkResult, error)

// checkResult is returned by individual checks. It contains the set of actions
// as determined by the check, as well as a boolean indicating whether the
// investigation should stop.
type checkResult struct {
	actions []types.Action
	stop    bool
}

func (i *Investigation) Run(rb investigation.ResourceBuilder) (investigation.InvestigationResult, error) {
	investigationResult := investigation.InvestigationResult{}
	r, err := rb.WithNotes().WithAwsClient().WithK8sClient().WithClusterDeployment().Build()
	if err != nil {
		if msg, ok := investigation.ClusterAccessErrorMessage(err); ok {
			investigationResult.Actions = []types.Action{
				executor.Note(msg),
				executor.Escalate(msg),
			}
			return investigationResult, nil
		}
		return investigationResult, investigation.WrapInfrastructure(err, "Resource build error")
	}

	if r.IsHCP {
		msg := "HCP detected, please manually investigate."
		investigationResult.Actions = []types.Action{
			executor.Note(msg),
			executor.Escalate(msg),
		}

		return investigationResult, nil
	}

	checks := []check{
		validateEgress,
		checkUserBanStatus,
		validatePullSecret,
	}

	// Run all checks and merge their resulting actions together into the investigation result.
	// Continue until all checks are run or a check signals the investigation should stop.
	for _, c := range checks {
		result, err := c(r)
		if err != nil {
			return investigationResult, err
		}

		investigationResult.Actions = append(investigationResult.Actions, result.actions...)

		if result.stop {
			return investigationResult, nil
		}
	}

	investigationResult.Actions = append(
		investigationResult.Actions,
		executor.NoteAndReportFrom(r.Notes, r.Cluster.ID(), i.Name())...,
	)

	investigationResult.Actions = append(
		investigationResult.Actions,
		executor.Escalate("OCMAgentResponseFailureServiceLogsSRE investigation complete"),
	)

	return investigationResult, nil
}

func (i *Investigation) Name() string {
	return "ocmagentresponsefailure"
}

func (i *Investigation) Description() string {
	return "Investigates the OCMAgentResponseFailureServiceLogsSRE alert"
}

func (i *Investigation) IsExperimental() bool {
	// TODO: Update to false when graduating to production.
	return true
}

func (i *Investigation) AlertTitle() string {
	return "OCMAgentResponseFailureServiceLogsSRE"
}

// checkUserBanStatus checks if the cluster owner is banned.
// It returns a set of actions, and a boolean indicating whether the investigation should halt
func checkUserBanStatus(r *investigation.Resources) (checkResult, error) {
	experimentalEnabled, _ := strconv.ParseBool(os.Getenv("CAD_EXPERIMENTAL_ENABLED"))
	userBannedErr := ocm.UserBannedError{}
	err := r.OcmClient.CheckIfUserBanned(r.Cluster)
	actions := []types.Action{}

	switch {
	case errors.As(err, &userBannedErr) && userBannedErr.Code == "export_control_compliance":
		// User is banned due to Export Control Compliance; escalate to SRE
		r.Notes.AppendWarning("%v", err)
		actions = append(
			actions,
			executor.NoteAndReportFrom(r.Notes, r.Cluster.ID(), r.Name)...,
		)
		actions = append(
			actions,
			executor.Escalate("Export Control Compliance ban detected, please refer to the SOP."),
		)
		return checkResult{actions: actions, stop: true}, nil
	case errors.As(err, &userBannedErr):
		// User is banned, but not due to Export Control Compliance; Send a SL

		r.Notes.AppendWarning("%v", err)
		actions = append(
			actions,
			executor.NoteAndReportFrom(r.Notes, r.Cluster.ID(), r.Name)...,
		)

		// Remove this check once informing phase tests are concluded
		if experimentalEnabled {
			sl := ocm.NewOCMBannedUserServiceLog()
			actions = append(
				actions,
				executor.NewServiceLogAction(sl.Severity, sl.Summary).
					WithDescription(sl.Description).
					WithServiceName(sl.ServiceName).
					Build(),
			)
		}

		actions = append(
			actions,
			executor.Escalate("User is banned, please refer to the SOP."),
		)
		return checkResult{actions: actions, stop: true}, nil
	case err != nil:
		// Unhandled error; escalate to SRE
		r.Notes.AppendWarning("encountered an issue when checking if the cluster owner is banned: %s\nPlease investigate.", err)
		actions = append(
			actions,
			executor.NoteAndReportFrom(r.Notes, r.Cluster.ID(), r.Name)...,
		)
		actions = append(
			actions,
			executor.Escalate("Failed to check if user is banned"),
		)
		return checkResult{actions: actions, stop: true}, nil
	}

	r.Notes.AppendSuccess("User is not banned.")

	return checkResult{actions: actions, stop: false}, nil
}

// validateEgress checks the cluster can reach the required endpoints.
// It returns a set of actions, and a boolean indicating whether the investigation should halt
func validateEgress(r *investigation.Resources) (checkResult, error) {
	actions := []types.Action{}
	verifierResult, failureReason, err := networkverifier.Run(r.Cluster, r.ClusterDeployment, r.AwsClient)
	if err != nil {
		logging.Errorf("Network verifier ran into an error: %s", err.Error())
		r.Notes.AppendWarning("NetworkVerifier failed to run:\n %s", err.Error())
		return checkResult{actions: actions, stop: false}, nil
	}

	switch verifierResult {
	case networkverifier.Failure:
		// Once the informing phase tests are over, this path will send out a SL as per SOP.
		r.Notes.AppendWarning("Network verifier reported failure: %s", failureReason)
		actions = append(
			actions,
			executor.NoteAndReportFrom(r.Notes, r.Cluster.ID(), r.Name)...,
		)
		actions = append(
			actions,
			executor.Escalate("Egress network verifier failed. Please investigate."),
		)
		return checkResult{actions: actions, stop: true}, nil
	case networkverifier.Success:
		r.Notes.AppendSuccess("Network verifier passed")
		logging.Info("Network verifier passed.")
	}

	return checkResult{actions: actions, stop: false}, nil
}

// validatePullSecret checks the cluster pull secret is valid.
// It returns a set of actions, and a boolean indicating whether the investigation should halt
func validatePullSecret(r *investigation.Resources) (checkResult, error) {
	actions := []types.Action{}
	user, err := r.OcmClient.GetCreatorFromCluster(r.Cluster)
	if err != nil {
		r.Notes.AppendWarning("Failed getting cluster creator from ocm: %s", err)
		actions = append(
			actions,
			executor.NoteAndReportFrom(r.Notes, r.Cluster.ID(), r.Name)...,
		)
		actions = append(
			actions,
			executor.Escalate("Failed to get cluster creator from OCM"),
		)
		return checkResult{actions: actions, stop: true}, nil
	}

	logging.Infof("User ID is: %v", user.ID())

	// Pullsecret validation done via pullsecret package
	ocmEmail := user.Email()
	emailValidation := pullsecret.ValidateEmail(r.K8sClient, ocmEmail)

	for _, warning := range emailValidation.Warnings {
		r.Notes.AppendWarning("%s", warning)
	}

	if emailValidation.IsValid && len(emailValidation.Warnings) == 0 {
		r.Notes.AppendSuccess("Pull Secret matches on cluster and in OCM. Please continue investigation.")
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
		r.Notes.AppendWarning("%s", warning)
	}

	return checkResult{actions: actions, stop: false}, nil
}

// Package upgradeconfigsyncfailureover4hr contains functionality for the UpgradeConfigSyncFailureOver4HrSRE investigation
package upgradeconfigsyncfailureover4hr

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"gopkg.in/yaml.v3"
	corev1 "k8s.io/api/core/v1"
	k8stypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/openshift/configuration-anomaly-detection/pkg/executor"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/investigation"
	k8sclient "github.com/openshift/configuration-anomaly-detection/pkg/k8s"
	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
	"github.com/openshift/configuration-anomaly-detection/pkg/notewriter"
	"github.com/openshift/configuration-anomaly-detection/pkg/ocm"
	"github.com/openshift/configuration-anomaly-detection/pkg/pullsecret"
	"github.com/openshift/configuration-anomaly-detection/pkg/types"
)

const (
	muoNamespace      = "openshift-managed-upgrade-operator"
	muoConfigMapName  = "managed-upgrade-operator-config"
	muoDeploymentName = "managed-upgrade-operator"
	expectedOCMBase   = "https://api.openshift.com"
)

type muoConfig struct {
	ConfigManager struct {
		Source     string `yaml:"source"`
		OcmBaseUrl string `yaml:"ocmBaseUrl"`
	} `yaml:"configManager"`
}

type Investigation struct{}

func (c *Investigation) Run(rb investigation.ResourceBuilder) (investigation.InvestigationResult, error) {
	result := investigation.InvestigationResult{}
	r, err := rb.WithCluster().Build()
	if err != nil {
		return result, err
	}
	notes := notewriter.New("UpgradeConfigSyncFailureOver4Hr", logging.RawLogger)

	logging.Infof("Checking if user is Banned.")
	userBannedErr := ocm.UserBannedError{}
	err = r.OcmClient.CheckIfUserBanned(r.Cluster)

	switch {
	case errors.As(err, &userBannedErr) && userBannedErr.Code == "export_control_compliance":
		// User is banned due to Export Control Compliance; escalate to SRE
		notes.AppendWarning("%v", err)
		result.Actions = append(
			result.Actions,
			executor.NoteAndReportFrom(notes, r.Cluster.ID(), c.Name())...,
		)

		result.Actions = append(
			result.Actions,
			executor.Escalate("Export Control Compliance ban detected, please refer to the SOP."),
		)

		return result, nil
	case errors.As(err, &userBannedErr):
		// User is banned, but not due to Export Control Compliance; Send a SL

		sl := ocm.NewOCMBannedUserServiceLog()

		notes.AppendWarning("%v", err)
		notes.AppendWarning("Sending out Service Log (%s)", sl.Summary)
		result.Actions = append(
			result.Actions,
			executor.NoteAndReportFrom(notes, r.Cluster.ID(), c.Name())...,
		)

		result.Actions = append(
			result.Actions,
			executor.NewServiceLogAction(sl.Severity, sl.Summary).
				WithDescription(sl.Description).
				WithServiceName(sl.ServiceName).
				Build(),
		)

		result.Actions = append(
			result.Actions,
			executor.Silence("Banned OCM user - service log sent to customer"),
		)

		return result, nil
	case err != nil:
		// Unhandled error; escalate to SRE
		notes.AppendWarning("encountered an issue when checking if the cluster owner is banned: %s\nPlease investigate.", err)
		result.Actions = append(
			result.Actions,
			executor.NoteAndReportFrom(notes, r.Cluster.ID(), c.Name())...,
		)

		result.Actions = append(
			result.Actions,
			executor.Escalate("Failed to check if user is banned"),
		)
		return result, nil
	}

	notes.AppendSuccess("User is not banned.")

	user, err := r.OcmClient.GetCreatorFromCluster(r.Cluster)
	if err != nil {
		notes.AppendWarning("Failed getting cluster creator from ocm: %s", err)
		result.Actions = append(
			executor.NoteAndReportFrom(notes, r.Cluster.ID(), c.Name()),
			executor.Escalate("Failed to get cluster creator from OCM"),
		)
		return result, nil
	}
	logging.Infof("User ID is: %v", user.ID())

	r, err = rb.WithK8sClient().Build()
	if err != nil {
		if msg, ok := investigation.ClusterAccessErrorMessage(err); ok {
			result.Actions = []types.Action{
				executor.Note(msg),
				executor.Escalate(msg),
			}
			return result, nil
		}
		return result, investigation.WrapInfrastructure(err, "Resource build error")
	}

	// MUO configmap validation
	logging.Info("Checking MUO configmap for ocmBaseUrl.")
	muoConfigErr := checkMUOConfig(r.K8sClient, notes)
	if muoConfigErr != nil {
		logging.Warnf("Failed to validate MUO config: %v", muoConfigErr)
	}

	// MUO log analysis
	logging.Info("Checking MUO deployment logs for known error patterns.")
	muoLogErr := checkMUOLogs(r.K8sClient, notes)
	if muoLogErr != nil {
		logging.Warnf("Failed to read MUO logs: %v", muoLogErr)
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

	result.Actions = append(result.Actions, executor.NoteAndReportFrom(notes, r.Cluster.ID(), c.Name())...)

	pullSecretValid := emailValidation.IsValid && registryValidation.IsValid
	if pullSecretValid {
		result.Actions = append(result.Actions,
			executor.Silence("Pull secret is valid - no customer-side issue detected"),
		)
	} else {
		result.Actions = append(result.Actions,
			executor.Escalate("Pull secret issue detected - review notes for details"),
		)
	}
	return result, nil
}

func (c *Investigation) Name() string {
	return "upgradeconfigsyncfailureover4hr"
}

func checkMUOConfig(k8sClient k8sclient.Client, notes *notewriter.NoteWriter) error {
	cm := &corev1.ConfigMap{}
	err := k8sClient.Get(context.TODO(), k8stypes.NamespacedName{
		Namespace: muoNamespace,
		Name:      muoConfigMapName,
	}, cm)
	if err != nil {
		notes.AppendWarning("Failed to read MUO configmap: %v", err)
		return err
	}

	rawConfig, ok := cm.Data["config.yaml"]
	if !ok {
		notes.AppendWarning("MUO configmap missing 'config.yaml' key")
		return fmt.Errorf("configmap missing config.yaml key")
	}

	var cfg muoConfig
	if err := yaml.Unmarshal([]byte(rawConfig), &cfg); err != nil {
		notes.AppendWarning("Failed to parse MUO config: %v", err)
		return err
	}

	if cfg.ConfigManager.OcmBaseUrl != expectedOCMBase {
		notes.AppendWarning("MUO ocmBaseUrl is '%s', expected '%s'", cfg.ConfigManager.OcmBaseUrl, expectedOCMBase)
		return nil
	}

	notes.AppendSuccess("MUO ocmBaseUrl is correct (%s)", expectedOCMBase)
	return nil
}

func checkMUOLogs(k8sClient k8sclient.Client, notes *notewriter.NoteWriter) error {
	ctx := context.TODO()

	podList := &corev1.PodList{}
	if err := k8sClient.List(ctx, podList,
		client.InNamespace(muoNamespace),
		client.MatchingLabels{"name": muoDeploymentName},
	); err != nil {
		notes.AppendWarning("Failed to list MUO pods: %v", err)
		return err
	}

	if len(podList.Items) == 0 {
		notes.AppendWarning("No MUO pods found in %s", muoNamespace)
		return fmt.Errorf("no MUO pods found")
	}

	restConfig, err := k8sclient.GetRestConfig(k8sClient)
	if err != nil {
		return fmt.Errorf("failed to get REST config: %w", err)
	}

	clientset, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		return fmt.Errorf("failed to create kubernetes clientset: %w", err)
	}

	pod := &podList.Items[0]
	tailLines := int64(200)
	logOptions := &corev1.PodLogOptions{
		TailLines: &tailLines,
	}

	req := clientset.CoreV1().Pods(muoNamespace).GetLogs(pod.Name, logOptions)
	logStream, err := req.Stream(ctx)
	if err != nil {
		notes.AppendWarning("Failed to read MUO pod logs: %v", err)
		return err
	}
	defer logStream.Close()

	buf := new(strings.Builder)
	if _, err := io.Copy(buf, logStream); err != nil {
		return fmt.Errorf("failed to read log stream: %w", err)
	}

	logs := buf.String()
	parseMUOLogs(logs, notes)
	return nil
}

func parseMUOLogs(logs string, notes *notewriter.NoteWriter) {
	knownPatterns := []struct {
		pattern string
		message string
	}{
		{"Leader pod has been deleted, waiting for garbage collection", "MUO deadlock detected (leader election): scale down/up MUO deployment to recover"},
		{"net/http: TLS handshake timeout", "TLS handshake timeout detected (possible ML-KEM incompatibility): check SOP for OHSS escalation"},
		{"ocm-config-getter", "MUO ocm-config-getter errors found: check OCM connectivity and MUO config"},
	}

	found := false
	for _, p := range knownPatterns {
		if strings.Contains(logs, p.pattern) {
			notes.AppendWarning("MUO logs: %s", p.message)
			found = true
		}
	}

	if !found {
		notes.AppendSuccess("No known error patterns found in MUO logs")
	}
}

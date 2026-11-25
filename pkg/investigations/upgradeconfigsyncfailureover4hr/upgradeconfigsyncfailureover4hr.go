// Package upgradeconfigsyncfailureover4hr contains functionality for the UpgradeConfigSyncFailureOver4HrSRE investigation
package upgradeconfigsyncfailureover4hr

import (
	"context"
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
	"github.com/openshift/configuration-anomaly-detection/pkg/micro"
	"github.com/openshift/configuration-anomaly-detection/pkg/notewriter"
)

const (
	muoNamespace      = "openshift-managed-upgrade-operator"
	muoConfigMapName  = "managed-upgrade-operator-config"
	muoConfigKey      = "config.yaml"
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
	r, err := rb.WithCluster().Build()
	if err != nil {
		return investigation.InvestigationResult{}, err
	}
	notes := notewriter.New(c.Name(), logging.RawLogger)
	result := func(actions ...executor.Action) investigation.InvestigationResult {
		return investigation.InvestigationResult{
			Actions: executor.FinalizeResult(notes, r.Cluster.ID(), c.Name(), actions...),
		}
	}

	banResult, err := micro.BannedUser(r.OcmClient, r.Cluster, notes)
	if err != nil {
		logging.Errorf("Failed to check if user is banned: %v", err)
		return result(executor.Escalate("Failed to check if user is banned")), nil //nolint:nilerr // failure is reported through the escalation action
	}
	if banResult.Done {
		return result(banResult.Actions...), nil
	}

	creatorResult, err := micro.ClusterCreator(r.OcmClient, r.Cluster, notes)
	if err != nil {
		logging.Errorf("Failed to get cluster creator from OCM: %v", err)
		return result(executor.Escalate("Failed to get cluster creator from OCM")), nil //nolint:nilerr // failure is reported through the escalation action
	}
	user := creatorResult.Value

	r, err = rb.WithK8sClient().Build()
	if err != nil {
		if cr := micro.ClusterAccessError(err, notes); cr.Done {
			return result(cr.Actions...), nil
		}
		return investigation.InvestigationResult{}, investigation.WrapInfrastructure(err, "Resource build error")
	}

	muoFinding := false
	if found, err := checkMUOConfig(r.K8sClient, notes); err != nil {
		logging.Warnf("Failed to validate MUO config: %v", err)
	} else if found {
		muoFinding = true
	}

	if found, err := checkMUOLogs(r.K8sClient, notes); err != nil {
		logging.Warnf("Failed to read MUO logs: %v", err)
	} else if found {
		muoFinding = true
	}

	psResult, err := micro.PullSecret(r.K8sClient, r.OcmClient.GetConnection(), user.ID(), user.Email(), notes)
	if err != nil {
		return investigation.InvestigationResult{}, investigation.WrapInfrastructure(err, "Pull secret validation failure")
	}

	if muoFinding {
		return result(executor.Escalate("MUO diagnostics found an issue - review notes for details")), nil
	}

	return result(psResult.Actions...), nil
}

func (c *Investigation) Name() string {
	return "upgradeconfigsyncfailureover4hr"
}

func checkMUOConfig(k8sClient k8sclient.Client, notes *notewriter.NoteWriter) (bool, error) {
	cm := &corev1.ConfigMap{}
	err := k8sClient.Get(context.TODO(), k8stypes.NamespacedName{
		Namespace: muoNamespace,
		Name:      muoConfigMapName,
	}, cm)
	if err != nil {
		notes.AppendWarning("Failed to read MUO configmap: %v", err)
		return false, err
	}

	rawConfig, ok := cm.Data[muoConfigKey]
	if !ok {
		notes.AppendWarning("MUO configmap missing '%s' key", muoConfigKey)
		return true, nil
	}

	var cfg muoConfig
	if err := yaml.Unmarshal([]byte(rawConfig), &cfg); err != nil {
		notes.AppendWarning("Failed to parse MUO config: %v", err)
		return false, err
	}

	finding := false
	source := strings.ToUpper(cfg.ConfigManager.Source)
	switch source {
	case "OCM":
		if cfg.ConfigManager.OcmBaseUrl != expectedOCMBase {
			notes.AppendWarning("MUO ocmBaseUrl is '%s', expected '%s'", cfg.ConfigManager.OcmBaseUrl, expectedOCMBase)
			finding = true
		} else {
			notes.AppendSuccess("MUO ocmBaseUrl is correct (%s)", expectedOCMBase)
		}
	case "LOCAL":
		notes.AppendSuccess("MUO configManager source is LOCAL (ocmBaseUrl check not applicable)")
	default:
		notes.AppendWarning("MUO configManager source is '%s', expected 'OCM' or 'LOCAL'", cfg.ConfigManager.Source)
		finding = true
	}

	return finding, nil
}

func selectRunningPod(pods []corev1.Pod) *corev1.Pod {
	for i := range pods {
		if pods[i].Status.Phase == corev1.PodRunning {
			return &pods[i]
		}
	}
	return nil
}

func checkMUOLogs(k8sClient k8sclient.Client, notes *notewriter.NoteWriter) (bool, error) {
	ctx := context.TODO()

	podList := &corev1.PodList{}
	if err := k8sClient.List(ctx, podList,
		client.InNamespace(muoNamespace),
		client.MatchingLabels{"name": muoDeploymentName},
	); err != nil {
		notes.AppendWarning("Failed to list MUO pods: %v", err)
		return false, err
	}

	pod := selectRunningPod(podList.Items)
	if pod == nil {
		notes.AppendWarning("No running MUO pods found in %s", muoNamespace)
		return false, fmt.Errorf("no running MUO pods found")
	}

	restConfig, err := k8sclient.GetRestConfig(k8sClient)
	if err != nil {
		notes.AppendWarning("Failed to get REST config for MUO log analysis")
		return false, fmt.Errorf("failed to get REST config: %w", err)
	}

	clientset, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		notes.AppendWarning("Failed to create kubernetes clientset for MUO log analysis")
		return false, fmt.Errorf("failed to create kubernetes clientset: %w", err)
	}

	tailLines := int64(200)
	logOptions := &corev1.PodLogOptions{
		TailLines: &tailLines,
	}

	req := clientset.CoreV1().Pods(muoNamespace).GetLogs(pod.Name, logOptions)
	logStream, err := req.Stream(ctx)
	if err != nil {
		notes.AppendWarning("Failed to read MUO pod logs: %v", err)
		return false, err
	}
	defer func() {
		if cerr := logStream.Close(); cerr != nil {
			logging.Debugf("Failed to close MUO log stream: %v", cerr)
		}
	}()

	buf := new(strings.Builder)
	if _, err := io.Copy(buf, logStream); err != nil {
		notes.AppendWarning("Failed to read MUO log stream")
		return false, fmt.Errorf("failed to read log stream: %w", err)
	}

	logs := buf.String()
	return parseMUOLogs(logs, notes), nil
}

func parseMUOLogs(logs string, notes *notewriter.NoteWriter) bool {
	knownPatterns := []struct {
		pattern string
		message string
	}{
		{"Leader pod has been deleted, waiting for garbage collection", "MUO deadlock detected (leader election): scale down/up MUO deployment to recover"},
		{"net/http: TLS handshake timeout", "TLS handshake timeout detected (possible ML-KEM incompatibility): check SOP for OHSS escalation"},
	}

	found := false
	for _, p := range knownPatterns {
		if strings.Contains(logs, p.pattern) {
			notes.AppendWarning("MUO logs: %s", p.message)
			found = true
		}
	}

	for _, line := range strings.Split(logs, "\n") {
		if strings.Contains(line, "ERROR") && strings.Contains(line, "ocm-config-getter") {
			notes.AppendWarning("MUO logs: ocm-config-getter errors found: check OCM connectivity and MUO config")
			found = true
			break
		}
	}

	if !found {
		notes.AppendSuccess("No known error patterns found in MUO logs")
	}

	return found
}

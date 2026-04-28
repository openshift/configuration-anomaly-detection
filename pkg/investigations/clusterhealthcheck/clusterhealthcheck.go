// Package clusterhealthcheck implements a CAD investigation that runs
// comprehensive health checks against an OpenShift cluster, replicating the
// functionality of the managed-scripts health/cluster-health-check action.
package clusterhealthcheck

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	configv1 "github.com/openshift/api/config/v1"
	mcfgv1 "github.com/openshift/api/machineconfiguration/v1"

	"github.com/openshift/configuration-anomaly-detection/pkg/executor"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/investigation"
	k8sclient "github.com/openshift/configuration-anomaly-detection/pkg/k8s"
	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
	"github.com/openshift/configuration-anomaly-detection/pkg/notewriter"
	"github.com/openshift/configuration-anomaly-detection/pkg/types"

	certsv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type alertsFetcher interface {
	fetchFiringAlerts(ctx context.Context, k8sClient k8sclient.Client, restConfig *rest.Config) ([]firingAlert, error)
}

type etcdHealthChecker interface {
	checkEtcdHealth(ctx context.Context, k8sClient k8sclient.Client, restConfig *rest.Config, namespace string) (string, error)
}

type apiHealthChecker interface {
	checkHealth(ctx context.Context, restConfig *rest.Config) (apiHealthResult, error)
}

type apiHealthResult struct {
	healthz string
	livez   string
	readyz  string
}

type firingAlert struct {
	Name     string
	Severity string
	State    string
	Summary  string
}

type Investigation struct {
	alertsFetcher    alertsFetcher
	etcdChecker      etcdHealthChecker
	apiHealthChecker apiHealthChecker
}

func (i *Investigation) Run(rb investigation.ResourceBuilder) (investigation.InvestigationResult, error) {
	ctx := context.Background()
	result := investigation.InvestigationResult{}

	r, err := rb.WithCluster().WithK8sClient().Build()
	if err != nil {
		if msg, ok := investigation.ClusterAccessErrorMessage(err); ok {
			logging.Warnf("Cluster access error for cluster-health-check: %v", err)
			result.Actions = []types.Action{
				executor.Note(msg),
			}
			return result, nil
		}
		return result, investigation.WrapInfrastructure(err, "failed to build resources for cluster-health-check")
	}

	notes := notewriter.New(i.Name(), logging.RawLogger)

	if r.IsHCP {
		notes.AppendWarning("This is an HCP cluster - some checks may differ (control plane runs on management cluster)")
	}

	// run all 12 health checks, collecting results.
	i.checkClusterOperators(ctx, r.K8sClient, notes)
	i.checkAPIServerHealth(ctx, r, notes)
	i.checkEtcdStatus(ctx, r, notes)
	i.checkMachineConfigPools(ctx, r.K8sClient, r.IsHCP, notes)
	i.checkPendingCSRs(ctx, r.K8sClient, notes)
	i.checkNodeStatus(ctx, r.K8sClient, notes)
	i.checkCapacity(ctx, r, notes)
	i.checkFiringAlerts(ctx, r, notes)
	i.checkClusterVersion(ctx, r.K8sClient, notes)
	i.checkFailingPods(ctx, r.K8sClient, notes)
	i.checkRestrictivePDBs(ctx, r.K8sClient, notes)
	i.checkNonNormalEvents(ctx, r.K8sClient, notes)

	result.Actions = executor.NoteAndReportFrom(notes, r.Cluster.ID(), i.Name())
	return result, nil
}

// checkClusterOperators lists all ClusterOperators and reports any that are degraded, unavailable, or progressing.
func (i *Investigation) checkClusterOperators(ctx context.Context, k8sClient k8sclient.Client, notes *notewriter.NoteWriter) {
	coList := &configv1.ClusterOperatorList{}
	if err := k8sClient.List(ctx, coList); err != nil {
		notes.AppendWarning("Cluster Operators: failed to list - %v", err)
		return
	}

	if len(coList.Items) == 0 {
		notes.AppendWarning("Cluster Operators: none found")
		return
	}

	var degraded, unavailable, progressing []string

	for _, co := range coList.Items {
		for _, cond := range co.Status.Conditions {
			switch {
			case cond.Type == configv1.OperatorDegraded && cond.Status == configv1.ConditionTrue:
				degraded = append(degraded, fmt.Sprintf("%s (reason: %s)", co.Name, cond.Reason))
			case cond.Type == configv1.OperatorAvailable && cond.Status == configv1.ConditionFalse:
				unavailable = append(unavailable, fmt.Sprintf("%s (reason: %s)", co.Name, cond.Reason))
			case cond.Type == configv1.OperatorProgressing && cond.Status == configv1.ConditionTrue:
				progressing = append(progressing, fmt.Sprintf("%s (reason: %s)", co.Name, cond.Reason))
			}
		}
	}

	if len(degraded) == 0 && len(unavailable) == 0 && len(progressing) == 0 {
		notes.AppendSuccess("Cluster Operators: all %d operators are healthy", len(coList.Items))
	} else {
		if len(unavailable) > 0 {
			notes.AppendWarning("Cluster Operators: %d unavailable - %s", len(unavailable), strings.Join(unavailable, ", "))
		}
		if len(degraded) > 0 {
			notes.AppendWarning("Cluster Operators: %d degraded - %s", len(degraded), strings.Join(degraded, ", "))
		}
		if len(progressing) > 0 {
			notes.AppendWarning("Cluster Operators: %d progressing - %s", len(progressing), strings.Join(progressing, ", "))
		}
	}
}

// checkAPIServerHealth queries the API server /healthz, /livez, and /readyz endpoints.
func (i *Investigation) checkAPIServerHealth(ctx context.Context, r *investigation.Resources, notes *notewriter.NoteWriter) {
	restConfig, err := getRestConfig(r)
	if err != nil {
		notes.AppendWarning("API Server Health: unable to get REST config - %v", err)
		return
	}

	checker := i.apiHealthChecker
	if checker == nil {
		checker = &defaultAPIHealthChecker{}
	}

	healthResult, err := checker.checkHealth(ctx, restConfig)
	if err != nil {
		notes.AppendWarning("API Server Health: check failed - %v", err)
		return
	}

	allOk := healthResult.healthz == "ok" && healthResult.livez == "ok" && healthResult.readyz == "ok"
	if allOk {
		notes.AppendSuccess("API Server Health: all endpoints healthy (healthz=ok, livez=ok, readyz=ok)")
	} else {
		notes.AppendWarning("API Server Health: healthz=%s, livez=%s, readyz=%s", healthResult.healthz, healthResult.livez, healthResult.readyz)
	}
}

type defaultAPIHealthChecker struct{}

func (d *defaultAPIHealthChecker) checkHealth(ctx context.Context, restConfig *rest.Config) (apiHealthResult, error) {
	clientset, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		return apiHealthResult{}, fmt.Errorf("failed to create clientset: %w", err)
	}

	result := apiHealthResult{}

	body, err := clientset.Discovery().RESTClient().Get().AbsPath("/healthz").DoRaw(ctx)
	if err != nil {
		result.healthz = fmt.Sprintf("error: %v", err)
	} else {
		result.healthz = string(body)
	}

	body, err = clientset.Discovery().RESTClient().Get().AbsPath("/livez").DoRaw(ctx)
	if err != nil {
		result.livez = fmt.Sprintf("error: %v", err)
	} else {
		result.livez = string(body)
	}

	body, err = clientset.Discovery().RESTClient().Get().AbsPath("/readyz").DoRaw(ctx)
	if err != nil {
		result.readyz = fmt.Sprintf("error: %v", err)
	} else {
		result.readyz = string(body)
	}

	return result, nil
}

// checkEtcdStatus execs etcdctl in an etcd pod to verify cluster health. Skipped on HCP clusters.
func (i *Investigation) checkEtcdStatus(ctx context.Context, r *investigation.Resources, notes *notewriter.NoteWriter) {
	if r.IsHCP {
		notes.AppendWarning("ETCD Status: skipped - etcd runs on the management cluster for HCP clusters")
		return
	}

	checker := i.etcdChecker
	if checker == nil {
		checker = &defaultEtcdHealthChecker{}
	}

	restConfig, err := getRestConfig(r)
	if err != nil {
		notes.AppendWarning("ETCD Status: unable to get REST config - %v", err)
		return
	}

	output, err := checker.checkEtcdHealth(ctx, r.K8sClient, restConfig, "openshift-etcd")
	if err != nil {
		notes.AppendWarning("ETCD Status: check failed - %v", err)
		return
	}

	notes.AppendSuccess("ETCD Status:\n%s", output)
}

type defaultEtcdHealthChecker struct{}

func (d *defaultEtcdHealthChecker) checkEtcdHealth(ctx context.Context, k8sClient k8sclient.Client, restConfig *rest.Config, namespace string) (string, error) {
	podList := &corev1.PodList{}
	err := k8sClient.List(ctx, podList,
		client.InNamespace(namespace),
		client.MatchingLabels{"app": "etcd"},
	)
	if err != nil {
		return "", fmt.Errorf("failed to list etcd pods: %w", err)
	}

	if len(podList.Items) == 0 {
		err = k8sClient.List(ctx, podList,
			client.InNamespace(namespace),
			client.MatchingLabels{"k8s-app": "etcd"},
		)
		if err != nil {
			return "", fmt.Errorf("failed to list etcd pods: %w", err)
		}
	}

	if len(podList.Items) == 0 {
		return "", fmt.Errorf("no etcd pods found in namespace %s", namespace)
	}

	var etcdPod *corev1.Pod
	for idx := range podList.Items {
		if podList.Items[idx].Status.Phase == corev1.PodRunning {
			etcdPod = &podList.Items[idx]
			break
		}
	}

	if etcdPod == nil {
		return "", fmt.Errorf("no running etcd pods found in namespace %s", namespace)
	}

	containerName := "etcd"
	for _, c := range etcdPod.Spec.Containers {
		if c.Name == "etcdctl" || c.Name == "etcd" {
			containerName = c.Name
			break
		}
	}

	output, err := k8sclient.ExecInPod(ctx, restConfig, etcdPod, containerName, []string{
		"etcdctl", "endpoint", "health", "--cluster",
	})
	if err != nil {
		return "", fmt.Errorf("failed to exec etcdctl health check: %w", err)
	}

	return strings.TrimSpace(output), nil
}

// checkMachineConfigPools lists MCPs and reports any that are degraded or updating. Skipped on HCP clusters.
func (i *Investigation) checkMachineConfigPools(ctx context.Context, k8sClient k8sclient.Client, isHCP bool, notes *notewriter.NoteWriter) {
	if isHCP {
		notes.AppendWarning("MachineConfigPools: skipped - MCPs are not used on HCP clusters")
		return
	}

	mcpList := &mcfgv1.MachineConfigPoolList{}
	if err := k8sClient.List(ctx, mcpList); err != nil {
		notes.AppendWarning("MachineConfigPools: failed to list - %v", err)
		return
	}

	if len(mcpList.Items) == 0 {
		notes.AppendWarning("MachineConfigPools: none found")
		return
	}

	var degraded, updating []string

	for _, mcp := range mcpList.Items {
		for _, cond := range mcp.Status.Conditions {
			switch {
			case cond.Type == mcfgv1.MachineConfigPoolDegraded && cond.Status == corev1.ConditionTrue:
				degraded = append(degraded, fmt.Sprintf("%s (reason: %s, message: %s)", mcp.Name, cond.Reason, cond.Message))
			case cond.Type == mcfgv1.MachineConfigPoolUpdating && cond.Status == corev1.ConditionTrue:
				updating = append(updating, fmt.Sprintf("%s (%d/%d updated)", mcp.Name, mcp.Status.UpdatedMachineCount, mcp.Status.MachineCount))
			}
		}
	}

	if len(degraded) == 0 && len(updating) == 0 {
		notes.AppendSuccess("MachineConfigPools: all %d pools are healthy", len(mcpList.Items))
	} else {
		if len(degraded) > 0 {
			notes.AppendWarning("MachineConfigPools: %d degraded - %s", len(degraded), strings.Join(degraded, "; "))
		}
		if len(updating) > 0 {
			notes.AppendWarning("MachineConfigPools: %d updating - %s", len(updating), strings.Join(updating, "; "))
		}
	}
}

// checkPendingCSRs lists CertificateSigningRequests and reports any that are neither approved nor denied.
func (i *Investigation) checkPendingCSRs(ctx context.Context, k8sClient k8sclient.Client, notes *notewriter.NoteWriter) {
	csrList := &certsv1.CertificateSigningRequestList{}
	if err := k8sClient.List(ctx, csrList); err != nil {
		notes.AppendWarning("Pending CSRs: failed to list - %v", err)
		return
	}

	var pending []string
	for _, csr := range csrList.Items {
		approved := false
		denied := false
		for _, cond := range csr.Status.Conditions {
			if cond.Type == certsv1.CertificateApproved {
				approved = true
			}
			if cond.Type == certsv1.CertificateDenied {
				denied = true
			}
		}
		if !approved && !denied {
			age := time.Since(csr.CreationTimestamp.Time).Truncate(time.Second)
			pending = append(pending, fmt.Sprintf("%s (requester: %s, age: %s)", csr.Name, csr.Spec.Username, age))
		}
	}

	if len(pending) == 0 {
		notes.AppendSuccess("Pending CSRs: none")
	} else {
		notes.AppendWarning("Pending CSRs: %d pending - %s", len(pending), strings.Join(pending, "; "))
	}
}

// checkNodeStatus reports nodes that are not ready, unschedulable, under pressure, or tainted.
func (i *Investigation) checkNodeStatus(ctx context.Context, k8sClient k8sclient.Client, notes *notewriter.NoteWriter) {
	nodeList := &corev1.NodeList{}
	if err := k8sClient.List(ctx, nodeList); err != nil {
		notes.AppendWarning("Nodes: failed to list - %v", err)
		return
	}

	if len(nodeList.Items) == 0 {
		notes.AppendWarning("Nodes: none found")
		return
	}

	var notReady, schedulingDisabled, tainted []string
	var conditionIssues []string

	for _, node := range nodeList.Items {
		for _, cond := range node.Status.Conditions {
			switch cond.Type {
			case corev1.NodeReady:
				if cond.Status != corev1.ConditionTrue {
					notReady = append(notReady, fmt.Sprintf("%s (status: %s, reason: %s)", node.Name, cond.Status, cond.Reason))
				}
			case corev1.NodeMemoryPressure:
				if cond.Status == corev1.ConditionTrue {
					conditionIssues = append(conditionIssues, fmt.Sprintf("%s: MemoryPressure", node.Name))
				}
			case corev1.NodeDiskPressure:
				if cond.Status == corev1.ConditionTrue {
					conditionIssues = append(conditionIssues, fmt.Sprintf("%s: DiskPressure", node.Name))
				}
			case corev1.NodePIDPressure:
				if cond.Status == corev1.ConditionTrue {
					conditionIssues = append(conditionIssues, fmt.Sprintf("%s: PIDPressure", node.Name))
				}
			}
		}

		if node.Spec.Unschedulable {
			schedulingDisabled = append(schedulingDisabled, node.Name)
		}

		for _, taint := range node.Spec.Taints {
			tainted = append(tainted, fmt.Sprintf("%s: %s: %s", node.Name, taint.Key, taint.Effect))
		}
	}

	if len(notReady) == 0 && len(schedulingDisabled) == 0 && len(conditionIssues) == 0 {
		notes.AppendSuccess("Nodes: all %d nodes are Ready and healthy", len(nodeList.Items))
	} else {
		if len(notReady) > 0 {
			notes.AppendWarning("Nodes: %d not ready - %s", len(notReady), strings.Join(notReady, "; "))
		}
		if len(schedulingDisabled) > 0 {
			notes.AppendWarning("Nodes: %d scheduling disabled - %s", len(schedulingDisabled), strings.Join(schedulingDisabled, ", "))
		}
		if len(conditionIssues) > 0 {
			notes.AppendWarning("Node Conditions: %d issue(s) - %s", len(conditionIssues), strings.Join(conditionIssues, "; "))
		}
	}

	if len(tainted) > 0 {
		notes.AppendWarning("Node Taints: %d taint(s) found:\n  %s", len(tainted), strings.Join(tainted, "\n  "))
	}
}

// checkCapacity reports per-node resource pre-allocation and current utilization via the metrics API.
func (i *Investigation) checkCapacity(ctx context.Context, r *investigation.Resources, notes *notewriter.NoteWriter) {
	nodeList := &corev1.NodeList{}
	if err := r.K8sClient.List(ctx, nodeList); err != nil {
		notes.AppendWarning("Capacity: failed to list nodes - %v", err)
		return
	}

	if len(nodeList.Items) == 0 {
		notes.AppendWarning("Capacity: no nodes found")
		return
	}

	const capacityThreshold = 80

	nodeCapacity := make(map[string]corev1.ResourceList, len(nodeList.Items))
	perNode := make([]string, 0, len(nodeList.Items))
	var overThreshold []string

	for _, node := range nodeList.Items {
		cpuCap := node.Status.Capacity[corev1.ResourceCPU]
		cpuAlloc := node.Status.Allocatable[corev1.ResourceCPU]
		memCap := node.Status.Capacity[corev1.ResourceMemory]
		memAlloc := node.Status.Allocatable[corev1.ResourceMemory]

		nodeCapacity[node.Name] = node.Status.Capacity

		// calculate pre-allocation percentage (reserved = capacity - allocatable)
		cpuPct := 0
		if cpuCap.MilliValue() > 0 {
			cpuPct = int(math.Round(float64(cpuCap.MilliValue()-cpuAlloc.MilliValue()) * 100 / float64(cpuCap.MilliValue())))
		}
		memPct := 0
		if memCap.Value() > 0 {
			memPct = int(math.Round(float64(memCap.Value()-memAlloc.Value()) * 100 / float64(memCap.Value())))
		}

		perNode = append(perNode, fmt.Sprintf("%s: CPU %d%%, Memory %d%%", node.Name, cpuPct, memPct))

		if cpuPct >= capacityThreshold || memPct >= capacityThreshold {
			overThreshold = append(overThreshold, fmt.Sprintf("%s (CPU: %d%%, Memory: %d%%)", node.Name, cpuPct, memPct))
		}
	}

	if len(overThreshold) > 0 {
		notes.AppendWarning("Capacity: %d node(s) with >=80%% pre-allocation - %s", len(overThreshold), strings.Join(overThreshold, "; "))
	} else {
		notes.AppendSuccess("Capacity: all %d nodes have less than 80%% CPU and Memory pre-allocation", len(nodeList.Items))
	}
	notes.AppendAutomation("Capacity per-node pre-allocation:\n  %s", strings.Join(perNode, "\n  "))

	i.checkCurrentUtilization(ctx, r, nodeCapacity, notes)
}

type nodeMetricsList struct {
	Items []nodeMetrics `json:"items"`
}

type nodeMetrics struct {
	Metadata struct {
		Name string `json:"name"`
	} `json:"metadata"`
	Usage map[string]string `json:"usage"`
}

func (i *Investigation) checkCurrentUtilization(ctx context.Context, r *investigation.Resources, nodeCapacity map[string]corev1.ResourceList, notes *notewriter.NoteWriter) {
	restConfig, err := getRestConfig(r)
	if err != nil {
		notes.AppendWarning("Capacity Utilization: unable to get REST config - %v", err)
		return
	}

	clientset, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		notes.AppendWarning("Capacity Utilization: failed to create clientset - %v", err)
		return
	}

	body, err := clientset.Discovery().RESTClient().Get().AbsPath("/apis/metrics.k8s.io/v1beta1/nodes").DoRaw(ctx)
	if err != nil {
		notes.AppendWarning("Capacity Utilization: unable to query metrics API - %v", err)
		return
	}

	var metricsList nodeMetricsList
	if err := json.Unmarshal(body, &metricsList); err != nil {
		notes.AppendWarning("Capacity Utilization: failed to parse metrics response - %v", err)
		return
	}

	const utilizationThreshold = 80

	perNodeUtil := make([]string, 0, len(metricsList.Items))
	var overThreshold []string

	for _, nm := range metricsList.Items {
		nodeCap, ok := nodeCapacity[nm.Metadata.Name]
		if !ok {
			continue
		}

		cpuUsage, err := resource.ParseQuantity(nm.Usage["cpu"])
		if err != nil {
			continue
		}
		memUsage, err := resource.ParseQuantity(nm.Usage["memory"])
		if err != nil {
			continue
		}
		cpuCap := nodeCap[corev1.ResourceCPU]
		memCap := nodeCap[corev1.ResourceMemory]

		cpuPct := 0
		if cpuCap.MilliValue() > 0 {
			cpuPct = int(math.Round(float64(cpuUsage.MilliValue()) * 100 / float64(cpuCap.MilliValue())))
		}
		memPct := 0
		if memCap.Value() > 0 {
			memPct = int(math.Round(float64(memUsage.Value()) * 100 / float64(memCap.Value())))
		}

		perNodeUtil = append(perNodeUtil, fmt.Sprintf("%s: CPU %d%%, Memory %d%%", nm.Metadata.Name, cpuPct, memPct))

		if cpuPct >= utilizationThreshold || memPct >= utilizationThreshold {
			overThreshold = append(overThreshold, fmt.Sprintf("%s (CPU: %d%%, Memory: %d%%)", nm.Metadata.Name, cpuPct, memPct))
		}
	}

	if len(perNodeUtil) == 0 {
		notes.AppendWarning("Capacity Utilization: no node metrics available")
		return
	}

	if len(overThreshold) > 0 {
		notes.AppendWarning("Capacity Utilization: %d node(s) with >=80%% utilization - %s", len(overThreshold), strings.Join(overThreshold, "; "))
	} else {
		notes.AppendSuccess("Capacity Utilization: all nodes have less than 80%% CPU and Memory utilization")
	}
	notes.AppendAutomation("Capacity per-node utilization:\n  %s", strings.Join(perNodeUtil, "\n  "))
}

func formatBytes(bytes int64) string {
	const (
		gi = 1024 * 1024 * 1024
		mi = 1024 * 1024
	)
	switch {
	case bytes >= gi:
		return fmt.Sprintf("%dGi", bytes/gi)
	case bytes >= mi:
		return fmt.Sprintf("%dMi", bytes/mi)
	default:
		return fmt.Sprintf("%dKi", bytes/1024)
	}
}

// checkFiringAlerts queries the Alertmanager API via pod exec and reports any firing alerts.
func (i *Investigation) checkFiringAlerts(ctx context.Context, r *investigation.Resources, notes *notewriter.NoteWriter) {
	restConfig, err := getRestConfig(r)
	if err != nil {
		notes.AppendWarning("Firing Alerts: unable to get REST config - %v", err)
		return
	}

	fetcher := i.alertsFetcher
	if fetcher == nil {
		fetcher = &defaultAlertsFetcher{}
	}

	alerts, err := fetcher.fetchFiringAlerts(ctx, r.K8sClient, restConfig)
	if err != nil {
		notes.AppendWarning("Firing Alerts: failed to fetch - %v", err)
		return
	}

	if len(alerts) == 0 {
		notes.AppendSuccess("Firing Alerts: none")
		return
	}

	bySeverity := map[string][]firingAlert{}
	for _, a := range alerts {
		bySeverity[a.Severity] = append(bySeverity[a.Severity], a)
	}

	var summary strings.Builder
	summary.WriteString(fmt.Sprintf("%d firing alert(s):\n", len(alerts)))
	for _, sev := range []string{"critical", "warning", "info", "none"} {
		alertsForSev, ok := bySeverity[sev]
		if !ok {
			continue
		}
		for _, a := range alertsForSev {
			summary.WriteString(fmt.Sprintf("  [%s] %s", sev, a.Name))
			if a.Summary != "" {
				summary.WriteString(fmt.Sprintf(" - %s", a.Summary))
			}
			summary.WriteString("\n")
		}
		delete(bySeverity, sev)
	}
	for sev, alertsForSev := range bySeverity {
		for _, a := range alertsForSev {
			summary.WriteString(fmt.Sprintf("  [%s] %s", sev, a.Name))
			if a.Summary != "" {
				summary.WriteString(fmt.Sprintf(" - %s", a.Summary))
			}
			summary.WriteString("\n")
		}
	}

	notes.AppendWarning("Firing Alerts: %s", summary.String())
}

type alertmanagerAlert struct {
	Labels      map[string]string       `json:"labels"`
	Annotations map[string]string       `json:"annotations"`
	Status      alertmanagerAlertStatus `json:"status"`
}

type alertmanagerAlertStatus struct {
	State string `json:"state"`
}

type defaultAlertsFetcher struct{}

func (d *defaultAlertsFetcher) fetchFiringAlerts(ctx context.Context, k8sClient k8sclient.Client, restConfig *rest.Config) ([]firingAlert, error) {
	podList := &corev1.PodList{}
	err := k8sClient.List(ctx, podList,
		client.InNamespace("openshift-monitoring"),
		client.MatchingLabels{"app.kubernetes.io/name": "alertmanager"},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to list alertmanager pods: %w", err)
	}

	var amPod *corev1.Pod
	for idx := range podList.Items {
		if podList.Items[idx].Status.Phase == corev1.PodRunning {
			amPod = &podList.Items[idx]
			break
		}
	}
	if amPod == nil {
		return nil, fmt.Errorf("no running alertmanager pods found in openshift-monitoring")
	}

	output, err := k8sclient.ExecInPod(ctx, restConfig, amPod, "alertmanager", []string{
		"wget", "-qO-", "http://localhost:9093/api/v2/alerts?active=true",
	})
	if err != nil {
		return nil, fmt.Errorf("failed to exec in alertmanager pod: %w", err)
	}

	var amAlerts []alertmanagerAlert
	if err := json.Unmarshal([]byte(output), &amAlerts); err != nil {
		return nil, fmt.Errorf("failed to decode alertmanager response: %w", err)
	}

	var firing []firingAlert
	for _, a := range amAlerts {
		if a.Status.State == "active" || a.Status.State == "firing" {
			alert := firingAlert{
				Name:     a.Labels["alertname"],
				Severity: a.Labels["severity"],
				State:    a.Status.State,
				Summary:  a.Annotations["summary"],
			}
			firing = append(firing, alert)
		}
	}

	return firing, nil
}

// checkClusterVersion reports the current cluster version, any update conditions, and EOL status.
func (i *Investigation) checkClusterVersion(ctx context.Context, k8sClient k8sclient.Client, notes *notewriter.NoteWriter) {
	cv := &configv1.ClusterVersion{}
	if err := k8sClient.Get(ctx, client.ObjectKey{Name: "version"}, cv); err != nil {
		notes.AppendWarning("Cluster Version: failed to get - %v", err)
		return
	}

	version := "unknown"
	for _, h := range cv.Status.History {
		if h.State == configv1.CompletedUpdate {
			version = h.Version
			break
		}
	}

	var issues []string
	for _, cond := range cv.Status.Conditions {
		switch {
		case cond.Type == "Failing" && cond.Status == configv1.ConditionTrue:
			issues = append(issues, fmt.Sprintf("Failing: %s", cond.Message))
		case cond.Type == "Progressing" && cond.Status == configv1.ConditionTrue:
			issues = append(issues, fmt.Sprintf("Progressing: %s", cond.Message))
		case cond.Type == "RetrievedUpdates" && cond.Status == configv1.ConditionFalse:
			issues = append(issues, fmt.Sprintf("Cannot retrieve updates: %s", cond.Message))
		}
	}

	eolWarning := checkEOL(cv)
	if eolWarning != "" {
		issues = append(issues, eolWarning)
	}

	if len(issues) == 0 {
		notes.AppendSuccess("Cluster Version: %s", version)
	} else {
		notes.AppendWarning("Cluster Version: %s - %s", version, strings.Join(issues, "; "))
	}
}

func checkEOL(cv *configv1.ClusterVersion) string {
	desired := cv.Status.Desired.Version
	if desired == "" {
		return ""
	}

	current := ""
	for _, h := range cv.Status.History {
		if h.State == configv1.CompletedUpdate {
			current = h.Version
			break
		}
	}
	if current == "" {
		return ""
	}

	currentMinor := parseMinorVersion(current)
	desiredMinor := parseMinorVersion(desired)
	if currentMinor < 0 || desiredMinor < 0 {
		return ""
	}

	if desiredMinor-currentMinor > 2 {
		return fmt.Sprintf("EOL: cluster version %s is more than 2 minor versions behind desired %s", current, desired)
	}
	return ""
}

func parseMinorVersion(version string) int {
	parts := strings.SplitN(version, ".", 3)
	if len(parts) < 2 {
		return -1
	}
	minor := 0
	for _, c := range parts[1] {
		if c < '0' || c > '9' {
			return -1
		}
		minor = minor*10 + int(c-'0')
	}
	return minor
}

// checkFailingPods reports pods in a failed state, with excessive restarts, or in error waiting states.
func (i *Investigation) checkFailingPods(ctx context.Context, k8sClient k8sclient.Client, notes *notewriter.NoteWriter) {
	podList := &corev1.PodList{}
	if err := k8sClient.List(ctx, podList); err != nil {
		notes.AppendWarning("Failing Pods: failed to list - %v", err)
		return
	}

	type podIssue struct {
		name      string
		namespace string
		reason    string
	}

	var issues []podIssue

	for _, pod := range podList.Items {
		if pod.Status.Phase == corev1.PodSucceeded {
			continue
		}

		if pod.Status.Phase == corev1.PodFailed {
			reason := pod.Status.Reason
			if reason == "" {
				reason = "Failed"
			}
			issues = append(issues, podIssue{
				name:      pod.Name,
				namespace: pod.Namespace,
				reason:    reason,
			})
			continue
		}

		for _, cs := range pod.Status.ContainerStatuses {
			if cs.RestartCount > 10 {
				issues = append(issues, podIssue{
					name:      pod.Name,
					namespace: pod.Namespace,
					reason:    fmt.Sprintf("container %s has %d restarts", cs.Name, cs.RestartCount),
				})
			}
			if cs.State.Waiting != nil && (cs.State.Waiting.Reason == "CrashLoopBackOff" ||
				cs.State.Waiting.Reason == "Error" ||
				cs.State.Waiting.Reason == "ImagePullBackOff" ||
				cs.State.Waiting.Reason == "ErrImagePull") {
				issues = append(issues, podIssue{
					name:      pod.Name,
					namespace: pod.Namespace,
					reason:    fmt.Sprintf("container %s: %s", cs.Name, cs.State.Waiting.Reason),
				})
			}
		}
	}

	if len(issues) == 0 {
		notes.AppendSuccess("Failing Pods: none")
	} else {
		maxDisplay := 50
		var sb strings.Builder
		sb.WriteString(fmt.Sprintf("%d pod(s) with issues:\n", len(issues)))

		sort.Slice(issues, func(a, b int) bool {
			if issues[a].namespace != issues[b].namespace {
				return issues[a].namespace < issues[b].namespace
			}
			return issues[a].name < issues[b].name
		})

		displayed := 0
		for _, issue := range issues {
			if displayed >= maxDisplay {
				sb.WriteString(fmt.Sprintf("  ... and %d more\n", len(issues)-maxDisplay))
				break
			}
			sb.WriteString(fmt.Sprintf("  %s/%s: %s\n", issue.namespace, issue.name, issue.reason))
			displayed++
		}

		notes.AppendWarning("Failing Pods: %s", sb.String())
	}
}

// checkRestrictivePDBs reports PodDisruptionBudgets that are actively blocking disruptions.
func (i *Investigation) checkRestrictivePDBs(ctx context.Context, k8sClient k8sclient.Client, notes *notewriter.NoteWriter) {
	pdbList := &policyv1.PodDisruptionBudgetList{}
	if err := k8sClient.List(ctx, pdbList); err != nil {
		notes.AppendWarning("Restrictive PDBs: failed to list - %v", err)
		return
	}

	var restrictive []string

	for _, pdb := range pdbList.Items {
		// (disruptionsAllowed == 0)
		if pdb.Status.DisruptionsAllowed > 0 {
			continue
		}

		isRestrictive := false
		reason := ""

		if pdb.Spec.MaxUnavailable != nil && pdb.Spec.MaxUnavailable.IntValue() == 0 {
			isRestrictive = true
			reason = "maxUnavailable=0"
		}

		// Check minAvailable = 100% or equal to total expected pods
		if pdb.Spec.MinAvailable != nil {
			if pdb.Spec.MinAvailable.Type == 1 {
				if pdb.Spec.MinAvailable.StrVal == "100%" {
					isRestrictive = true
					reason = "minAvailable=100%"
				}
			} else if pdb.Status.ExpectedPods > 0 && pdb.Spec.MinAvailable.IntValue() >= int(pdb.Status.ExpectedPods) {
				isRestrictive = true
				reason = fmt.Sprintf("minAvailable=%d (expectedPods=%d)", pdb.Spec.MinAvailable.IntValue(), pdb.Status.ExpectedPods)
			}
		}

		if isRestrictive {
			restrictive = append(restrictive, fmt.Sprintf("%s/%s (%s)",
				pdb.Namespace, pdb.Name, reason))
		}
	}

	if len(restrictive) == 0 {
		notes.AppendSuccess("Restrictive PDBs: none")
	} else {
		notes.AppendWarning("Restrictive PDBs: %d found - %s", len(restrictive), strings.Join(restrictive, "; "))
	}
}

// checkNonNormalEvents reports cluster events with a type other than Normal.
func (i *Investigation) checkNonNormalEvents(ctx context.Context, k8sClient k8sclient.Client, notes *notewriter.NoteWriter) {
	eventList := &corev1.EventList{}
	if err := k8sClient.List(ctx, eventList); err != nil {
		notes.AppendWarning("Events: failed to list - %v", err)
		return
	}

	type eventSummary struct {
		reason    string
		object    string
		message   string
		count     int32
		namespace string
	}

	var nonNormal []eventSummary
	for _, event := range eventList.Items {
		if event.Type != corev1.EventTypeNormal {
			nonNormal = append(nonNormal, eventSummary{
				reason:    event.Reason,
				object:    fmt.Sprintf("%s/%s", event.InvolvedObject.Kind, event.InvolvedObject.Name),
				message:   event.Message,
				count:     event.Count,
				namespace: event.Namespace,
			})
		}
	}

	if len(nonNormal) == 0 {
		notes.AppendSuccess("Events: no non-normal events")
	} else {
		maxDisplay := 50
		var sb strings.Builder
		sb.WriteString(fmt.Sprintf("%d non-normal event(s):\n", len(nonNormal)))

		sort.Slice(nonNormal, func(a, b int) bool {
			if nonNormal[a].namespace != nonNormal[b].namespace {
				return nonNormal[a].namespace < nonNormal[b].namespace
			}
			return nonNormal[a].reason < nonNormal[b].reason
		})

		displayed := 0
		for _, e := range nonNormal {
			if displayed >= maxDisplay {
				sb.WriteString(fmt.Sprintf("  ... and %d more\n", len(nonNormal)-maxDisplay))
				break
			}
			countStr := ""
			if e.count > 1 {
				countStr = fmt.Sprintf(" (x%d)", e.count)
			}
			msg := e.message
			if len(msg) > 120 {
				msg = msg[:120] + "..."
			}
			sb.WriteString(fmt.Sprintf("  %s/%s: %s%s - %s\n", e.namespace, e.object, e.reason, countStr, msg))
			displayed++
		}

		notes.AppendWarning("Events: %s", sb.String())
	}
}

func getRestConfig(r *investigation.Resources) (*rest.Config, error) {
	if r.RestConfig != nil {
		return &r.RestConfig.Config, nil
	}
	return k8sclient.GetRestConfig(r.K8sClient)
}

func (i *Investigation) Name() string {
	return "clusterhealthcheck"
}

func (i *Investigation) AlertTitle() string {
	return ""
}

func (i *Investigation) Description() string {
	return "Run comprehensive health checks against the cluster (cluster operators, API, etcd, nodes, pods, events, etc.)"
}

func (i *Investigation) IsExperimental() bool {
	return true
}

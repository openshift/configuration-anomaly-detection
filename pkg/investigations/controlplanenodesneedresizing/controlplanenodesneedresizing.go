// Package controlplanenodesneedresizing ranks the workloads using CPU and memory
// on the control-plane node the alert is about. The resize stays manual.
package controlplanenodesneedresizing

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/openshift/configuration-anomaly-detection/pkg/executor"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/investigation"
	k8sclient "github.com/openshift/configuration-anomaly-detection/pkg/k8s"
	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
	"github.com/openshift/configuration-anomaly-detection/pkg/types"
)

const (
	masterRoleLabel = "node-role.kubernetes.io/master"
	// sopUsageThreshold is the SOP's "over 66%" control-plane utilization.
	sopUsageThreshold = 66
)

var (
	nodeLabel     = regexp.MustCompile(`(?:^|[\s,])node=([A-Za-z0-9_.-]+)`)
	instanceLabel = regexp.MustCompile(`(?:^|[\s,])instance=([A-Za-z0-9_.-]+)`)
)

// Investigation writes a PagerDuty note for ControlPlaneNodesNeedResizingSRE.
type Investigation struct{}

func (i *Investigation) Name() string {
	return "controlplanenodesneedresizing"
}

func (i *Investigation) Run(rb investigation.ResourceBuilder) (investigation.InvestigationResult, error) {
	ctx := context.Background()
	result := investigation.InvestigationResult{}

	r, err := rb.WithCluster().WithNotes().WithK8sClient().Build()
	if err != nil {
		if msg, ok := investigation.ClusterAccessErrorMessage(err); ok {
			result.Actions = []types.Action{executor.Escalate(msg)}
			return result, nil
		}
		return result, err
	}

	if r.IsHCP {
		r.Notes.AppendWarning("ControlPlaneNodesNeedResizingSRE applies to classic ROSA. This cluster is HCP, so no workload ranking was taken.")
		result.Actions = append(
			executor.NoteAndReportFrom(r.Notes, r.Cluster.ID(), i.Name()),
			executor.Escalate("HCP cluster - control plane resize alert is not handled here"),
		)
		return result, nil
	}

	title := ""
	if r.PdClient != nil {
		title = r.PdClient.GetTitle()
	}
	summary, err := summarizeAlertNode(ctx, r.K8sClient, title)
	if err != nil {
		if investigation.IsInfrastructureError(err) {
			return result, err
		}
		logging.Errorf("control plane workload ranking failed: %v", err)
		r.Notes.AppendWarning("Failed to rank control plane workloads: %v", err)
		result.Actions = append(
			executor.NoteAndReportFrom(r.Notes, r.Cluster.ID(), i.Name()),
			executor.Escalate("Failed to rank control plane workloads - manual investigation required"),
		)
		return result, nil
	}

	r.Notes.AppendSuccess("%s", summary)
	r.Notes.AppendWarning("CAD does not resize control plane nodes. Use the resize SOP after reading this note.")
	result.Actions = append(
		executor.NoteAndReportFrom(r.Notes, r.Cluster.ID(), i.Name()),
		executor.Escalate("Control plane resize stays manual. Workload ranking is in the note."),
	)
	return result, nil
}

type podUsage struct {
	namespace string
	name      string
	cpuMilli  int64
	memBytes  int64
}

func summarizeAlertNode(ctx context.Context, k8sClient k8sclient.Client, alertText string) (string, error) {
	nodes, err := listMasterNodes(ctx, k8sClient)
	if err != nil {
		return "", err
	}
	if named := nodeFromAlert(alertText); named != "" {
		if _, ok := nodes[named]; !ok {
			return fmt.Sprintf("The incident names node %s, which is not a control-plane node. No other masters were inspected.", named), nil
		}
		return rankNode(ctx, k8sClient, named, nodes[named])
	}

	hot, err := hotMasterNodes(ctx, k8sClient, nodes)
	if err != nil {
		return "", err
	}
	if len(hot) == 0 {
		return "The incident does not name a node, and no control-plane node is currently at or above 66% CPU or memory. No pod ranking was taken.", nil
	}
	var b strings.Builder
	b.WriteString("The incident does not name a node. Ranking workloads only on control-plane nodes at or above 66% CPU or memory.\n")
	for _, name := range hot {
		text, err := rankNode(ctx, k8sClient, name, nodes[name])
		if err != nil {
			return "", err
		}
		b.WriteString("\n")
		b.WriteString(text)
	}
	return b.String(), nil
}

func listMasterNodes(ctx context.Context, k8sClient k8sclient.Client) (map[string]corev1.Node, error) {
	var nodes corev1.NodeList
	if err := k8sClient.List(ctx, &nodes, client.HasLabels{masterRoleLabel}); err != nil {
		return nil, investigation.WrapInfrastructure(err, "listing control plane nodes")
	}
	out := make(map[string]corev1.Node, len(nodes.Items))
	for _, node := range nodes.Items {
		out[node.Name] = node
	}
	return out, nil
}

// node= is preferred. instance= is often ip:port and must not hide a real node name.
func nodeFromAlert(text string) string {
	if m := nodeLabel.FindStringSubmatch(text); len(m) >= 2 {
		return m[1]
	}
	if m := instanceLabel.FindStringSubmatch(text); len(m) >= 2 {
		return m[1]
	}
	return ""
}

func hotMasterNodes(ctx context.Context, k8sClient k8sclient.Client, nodes map[string]corev1.Node) ([]string, error) {
	body, err := metricsBody(ctx, k8sClient, "/apis/metrics.k8s.io/v1beta1/nodes")
	if err != nil {
		return nil, err
	}
	var list nodeMetricsList
	if err := json.Unmarshal(body, &list); err != nil {
		return nil, fmt.Errorf("parsing node metrics: %w", err)
	}
	var hot []string
	for _, item := range list.Items {
		node, ok := nodes[item.Metadata.Name]
		if !ok {
			continue
		}
		cpuPct, memPct := usagePercents(item.Usage, node.Status.Allocatable)
		if cpuPct >= sopUsageThreshold || memPct >= sopUsageThreshold {
			hot = append(hot, node.Name)
		}
	}
	sort.Strings(hot)
	return hot, nil
}

func rankNode(ctx context.Context, k8sClient k8sclient.Client, nodeName string, node corev1.Node) (string, error) {
	var pods corev1.PodList
	if err := k8sClient.List(ctx, &pods, client.MatchingFields{"spec.nodeName": nodeName}); err != nil {
		return "", investigation.WrapInfrastructure(err, "listing pods on "+nodeName)
	}
	onNode := map[string]corev1.Pod{}
	for _, pod := range pods.Items {
		onNode[pod.Namespace+"/"+pod.Name] = pod
	}
	body, err := metricsBody(ctx, k8sClient, "/apis/metrics.k8s.io/v1beta1/pods")
	if err != nil {
		return "", err
	}
	var list podMetricsList
	if err := json.Unmarshal(body, &list); err != nil {
		return "", fmt.Errorf("parsing pod metrics: %w", err)
	}
	usages := make([]podUsage, 0)
	for _, item := range list.Items {
		key := item.Metadata.Namespace + "/" + item.Metadata.Name
		if _, ok := onNode[key]; !ok {
			continue
		}
		var cpu, mem resource.Quantity
		for _, c := range item.Containers {
			if q, err := resource.ParseQuantity(c.Usage["cpu"]); err == nil {
				cpu.Add(q)
			}
			if q, err := resource.ParseQuantity(c.Usage["memory"]); err == nil {
				mem.Add(q)
			}
		}
		usages = append(usages, podUsage{
			namespace: item.Metadata.Namespace,
			name:      item.Metadata.Name,
			cpuMilli:  cpu.MilliValue(),
			memBytes:  mem.Value(),
		})
	}
	// A failed lookup must not be reported as 0%.
	nodeBody, err := metricsBody(ctx, k8sClient, "/apis/metrics.k8s.io/v1beta1/nodes/"+nodeName)
	if err != nil {
		return formatRanking(nodeName, 0, 0, false, usages), nil
	}
	var nm nodeMetrics
	if err := json.Unmarshal(nodeBody, &nm); err != nil {
		return formatRanking(nodeName, 0, 0, false, usages), nil
	}
	cpuPct, memPct := usagePercents(nm.Usage, node.Status.Allocatable)
	return formatRanking(nodeName, cpuPct, memPct, true, usages), nil
}

func formatRanking(nodeName string, cpuPct, memPct int, haveNodeUsage bool, usages []podUsage) string {
	sort.Slice(usages, func(i, j int) bool {
		if usages[i].memBytes == usages[j].memBytes {
			return usages[i].cpuMilli > usages[j].cpuMilli
		}
		return usages[i].memBytes > usages[j].memBytes
	})
	var b strings.Builder
	if haveNodeUsage {
		fmt.Fprintf(&b, "Node %s: CPU %d%%, memory %d%%\n", nodeName, cpuPct, memPct)
	} else {
		fmt.Fprintf(&b, "Node %s: CPU and memory percentages unavailable\n", nodeName)
	}
	if len(usages) == 0 {
		b.WriteString("No pod metrics were found on this node.\n")
		return b.String()
	}
	b.WriteString("Workloads by memory, then CPU:\n")
	for i, u := range usages {
		kind := "customer"
		if isPlatformNamespace(u.namespace) {
			kind = "platform"
		}
		fmt.Fprintf(&b, "%d. %s/%s memory %dMi CPU %dm (%s)\n", i+1, u.namespace, u.name, u.memBytes/(1024*1024), u.cpuMilli, kind)
	}
	return b.String()
}

// openshift, openshift-*, and kube-* are platform namespaces.
func isPlatformNamespace(ns string) bool {
	return ns == "openshift" || strings.HasPrefix(ns, "openshift-") || strings.HasPrefix(ns, "kube-")
}

func usagePercents(usage map[string]string, allocatable corev1.ResourceList) (int, int) {
	cpuPct, memPct := 0, 0
	if q, err := resource.ParseQuantity(usage["cpu"]); err == nil {
		cap := allocatable[corev1.ResourceCPU]
		if cap.MilliValue() > 0 {
			cpuPct = int(q.MilliValue() * 100 / cap.MilliValue())
		}
	}
	if q, err := resource.ParseQuantity(usage["memory"]); err == nil {
		cap := allocatable[corev1.ResourceMemory]
		if cap.Value() > 0 {
			memPct = int(q.Value() * 100 / cap.Value())
		}
	}
	return cpuPct, memPct
}

func metricsBody(ctx context.Context, k8sClient k8sclient.Client, path string) ([]byte, error) {
	cfg, err := k8sclient.GetRestConfig(k8sClient)
	if err != nil {
		return nil, err
	}
	clientset, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("creating metrics client: %w", err)
	}
	body, err := clientset.Discovery().RESTClient().Get().AbsPath(path).DoRaw(ctx)
	if err != nil {
		return nil, investigation.WrapInfrastructure(err, "querying metrics API "+path)
	}
	return body, nil
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

type podMetricsList struct {
	Items []podMetrics `json:"items"`
}

type podMetrics struct {
	Metadata struct {
		Name      string `json:"name"`
		Namespace string `json:"namespace"`
	} `json:"metadata"`
	Containers []struct {
		Usage map[string]string `json:"usage"`
	} `json:"containers"`
}

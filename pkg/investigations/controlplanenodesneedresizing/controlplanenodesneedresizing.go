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
	kindCustomer    = "customer"
	kindPlatform    = "platform"
)

// alertThresholdPercent is (n-1)/n for three control-plane nodes, which is the
// comparison in the recording rule. It is applied per node because the alert
// series drops the node label. These figures are current metrics, not the
// eight-hour average the alert computed, and "the node that fired" cannot be
// read from the incident.
const alertThresholdPercent = 66

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
	masters, err := masterSamples(ctx, r.K8sClient)
	if err != nil {
		if investigation.IsInfrastructureError(err) {
			return result, err
		}
		logging.Errorf("control plane workload identification failed: %v", err)
		r.Notes.AppendWarning("Failed to identify the control plane workload: %v", err)
		result.Actions = append(
			executor.NoteAndReportFrom(r.Notes, r.Cluster.ID(), i.Name()),
			executor.Escalate("Failed to identify the control plane workload - manual investigation required"),
		)
		return result, nil
	}
	cause := identifyCause(title, masters)
	r.Notes.AppendSuccess("%s", cause.note())
	result.Actions = append(
		executor.NoteAndReportFrom(r.Notes, r.Cluster.ID(), i.Name()),
		executor.Escalate("Control plane resize stays manual."),
	)
	return result, nil
}

// WorkloadCause is the single workload CAD would act on if resize were automated.
type WorkloadCause struct {
	Found     bool
	Node      string
	Namespace string
	Name      string
	Kind      string
	CPUMilli  int64
	MemBytes  int64
}

func (c WorkloadCause) note() string {
	if !c.Found {
		return "No control-plane node is at or above the alert threshold on current usage, so no workload was identified. Current usage is not the eight-hour average. The alert rule drops the node label."
	}
	return fmt.Sprintf("Identified workload: %s/%s on %s (%s), memory %dMi, CPU %dm. Current usage, not the eight-hour average. The alert rule drops the node, so this node was selected because it is at or above the threshold.",
		c.Namespace, c.Name, c.Node, c.Kind, c.MemBytes/(1024*1024), c.CPUMilli)
}

type podUsage struct {
	namespace string
	name      string
	node      string
	cpuMilli  int64
	memBytes  int64
}

type masterSample struct {
	name       string
	cpuPercent int
	memPercent int
	pods       []podUsage
}

// identifyCause selects the workload from current node and pod usage.
// title is the incident title. A missing node= is the normal page: the alert
// rule drops the node, so identification must not stop there. cpu and memory
// percents are current metrics, not the eight-hour average.
func identifyCause(title string, masters []masterSample) WorkloadCause {
	// A node= in the title is ignored. The firing alert does not have one, and
	// a present one must not hide a hotter master.
	_ = nodeFromAlert(title)
	var candidates []podUsage
	for _, master := range masters {
		if master.cpuPercent < alertThresholdPercent && master.memPercent < alertThresholdPercent {
			continue
		}
		candidates = append(candidates, master.pods...)
	}
	return topWorkload(candidates)
}

func masterSamples(ctx context.Context, k8sClient k8sclient.Client) ([]masterSample, error) {
	var nodes corev1.NodeList
	if err := k8sClient.List(ctx, &nodes, client.HasLabels{masterRoleLabel}); err != nil {
		return nil, investigation.WrapInfrastructure(err, "listing control plane nodes")
	}
	nodeBody, err := metricsBody(ctx, k8sClient, "/apis/metrics.k8s.io/v1beta1/nodes")
	if err != nil {
		return nil, err
	}
	var nodeList nodeMetricsList
	if err := json.Unmarshal(nodeBody, &nodeList); err != nil {
		return nil, fmt.Errorf("parsing node metrics: %w", err)
	}
	usageByNode := map[string]nodeMetrics{}
	for _, item := range nodeList.Items {
		usageByNode[item.Metadata.Name] = item
	}
	podBody, err := metricsBody(ctx, k8sClient, "/apis/metrics.k8s.io/v1beta1/pods")
	if err != nil {
		return nil, err
	}
	var podList podMetricsList
	if err := json.Unmarshal(podBody, &podList); err != nil {
		return nil, fmt.Errorf("parsing pod metrics: %w", err)
	}
	samples := make([]masterSample, 0, len(nodes.Items))
	for _, node := range nodes.Items {
		var pods corev1.PodList
		if err := k8sClient.List(ctx, &pods, client.MatchingFields{"spec.nodeName": node.Name}); err != nil {
			return nil, investigation.WrapInfrastructure(err, "listing pods on "+node.Name)
		}
		onNode := map[string]struct{}{}
		for _, pod := range pods.Items {
			onNode[pod.Namespace+"/"+pod.Name] = struct{}{}
		}
		sample := masterSample{name: node.Name}
		if nm, ok := usageByNode[node.Name]; ok {
			sample.cpuPercent, sample.memPercent = usagePercents(nm.Usage, node.Status.Allocatable)
		}
		for _, item := range podList.Items {
			if _, ok := onNode[item.Metadata.Namespace+"/"+item.Metadata.Name]; !ok {
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
			sample.pods = append(sample.pods, podUsage{
				namespace: item.Metadata.Namespace,
				name:      item.Metadata.Name,
				node:      node.Name,
				cpuMilli:  cpu.MilliValue(),
				memBytes:  mem.Value(),
			})
		}
		samples = append(samples, sample)
	}
	return samples, nil
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

func topWorkload(usages []podUsage) WorkloadCause {
	if len(usages) == 0 {
		return WorkloadCause{}
	}
	sorted := append([]podUsage(nil), usages...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].memBytes == sorted[j].memBytes {
			return sorted[i].cpuMilli > sorted[j].cpuMilli
		}
		return sorted[i].memBytes > sorted[j].memBytes
	})
	top := sorted[0]
	kind := kindCustomer
	if isPlatformNamespace(top.namespace) {
		kind = kindPlatform
	}
	return WorkloadCause{
		Found:     true,
		Node:      top.node,
		Namespace: top.namespace,
		Name:      top.name,
		Kind:      kind,
		CPUMilli:  top.cpuMilli,
		MemBytes:  top.memBytes,
	}
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
		kind := kindCustomer
		if isPlatformNamespace(u.namespace) {
			kind = kindPlatform
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
		cpuAlloc := allocatable[corev1.ResourceCPU]
		if cpuAlloc.MilliValue() > 0 {
			cpuPct = int(q.MilliValue() * 100 / cpuAlloc.MilliValue())
		}
	}
	if q, err := resource.ParseQuantity(usage["memory"]); err == nil {
		memAlloc := allocatable[corev1.ResourceMemory]
		if memAlloc.Value() > 0 {
			memPct = int(q.Value() * 100 / memAlloc.Value())
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

// Package infranodesneedresizingsre contains the investigation for the
// InfraNodesNeedResizingSRE alert.
//
// The alert fires when the dedicated infra nodes of a cluster are under resource
// pressure and SRE has to resize the infra machine pool. The investigation
// summarises, read-only, how heavily the infra nodes are loaded and which
// platform components are the largest resource requesters on them, so on-call
// has the context to size the change.
//
// Informing stage: the investigation never resizes anything and never sends a
// service log. It records its findings in the PD note and escalates, so the
// verdicts can be compared with on-call resolutions before any action is taken.
package infranodesneedresizingsre

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"

	"github.com/openshift/configuration-anomaly-detection/pkg/executor"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/investigation"
	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
	"github.com/openshift/configuration-anomaly-detection/pkg/types"
)

const (
	investigationName = "infranodesneedresizingsre"

	// checksTimeout bounds all cluster reads so a hung API call cannot block the
	// PD note and escalation.
	checksTimeout = 2 * time.Minute

	// infraRoleLabel marks a dedicated infra node.
	infraRoleLabel = "node-role.kubernetes.io/infra"

	// topConsumers is how many namespaces to list as the largest requesters.
	topConsumers = 5

	// highRequestRatio is the fraction of a node's allocatable at or above which
	// scheduled requests are treated as resource pressure worth a resize.
	highRequestRatio = 0.85
)

// componentUsage is the summed pod resource requests for one namespace on the
// infra nodes. Namespace is used as the platform-component key because platform
// workloads live in distinct openshift-* namespaces.
type componentUsage struct {
	Namespace string
	CPUMilli  int64
	MemBytes  int64
	Pods      int
}

// nodePressure is the summed scheduled requests on a single infra node against
// its allocatable capacity.
type nodePressure struct {
	Name          string
	CPUMilli      int64
	CPUAllocMilli int64
	MemBytes      int64
	MemAllocBytes int64
}

func (p nodePressure) cpuRatio() float64 {
	if p.CPUAllocMilli == 0 {
		return 0
	}
	return float64(p.CPUMilli) / float64(p.CPUAllocMilli)
}

func (p nodePressure) memRatio() float64 {
	if p.MemAllocBytes == 0 {
		return 0
	}
	return float64(p.MemBytes) / float64(p.MemAllocBytes)
}

// Investigation implements the InfraNodesNeedResizingSRE investigation.
type Investigation struct{}

// Run summarises the scheduled load on the infra nodes and the top-requesting
// platform components, records them in the PD note, and escalates. It never
// mutates the cluster.
func (i *Investigation) Run(rb investigation.ResourceBuilder) (investigation.InvestigationResult, error) {
	result := investigation.InvestigationResult{}

	r, err := rb.WithCluster().WithK8sClient().WithNotes().Build()
	if err != nil {
		if msg, ok := investigation.ClusterAccessErrorMessage(err); ok {
			logging.Warnf("Cluster access error for %s: %v", i.Name(), err)
			result.Actions = []types.Action{
				executor.Note(msg),
				executor.Escalate(msg),
			}
			return result, nil
		}
		return result, investigation.WrapInfrastructure(err, "failed to build resources for "+i.Name())
	}

	escalate := func(reason string) (investigation.InvestigationResult, error) {
		result.Actions = append(
			executor.NoteAndReportFrom(r.Notes, r.Cluster.ID(), i.Name()),
			executor.Escalate(reason),
		)
		return result, nil
	}

	// Management / service clusters have their own SOP for infra-node pressure.
	if r.IsInfrastructureCluster {
		r.Notes.AppendWarning("Cluster is a management/service cluster: treat as an incident and follow the infrastructure-cluster SOP.")
		result.StopInvestigations = errors.New("infrastructure cluster: manual incident handling")
		return escalate("InfraNodesNeedResizingSRE on an infrastructure cluster")
	}

	if r.IsHCP {
		r.Notes.AppendWarning("Cluster is HCP: dedicated infra nodes are not expected; verify the alert source.")
	}

	ctx, cancel := context.WithTimeout(context.Background(), checksTimeout)
	defer cancel()

	nodes := &corev1.NodeList{}
	if err := r.K8sClient.List(ctx, nodes); err != nil {
		r.Notes.AppendWarning("Nodes: failed to list: %v", err)
		return escalate("Could not list nodes")
	}

	infra := map[string]corev1.Node{}
	for _, n := range nodes.Items {
		if _, ok := n.Labels[infraRoleLabel]; ok {
			infra[n.Name] = n
		}
	}
	if len(infra) == 0 {
		r.Notes.AppendWarning("No infra nodes found (%s); nothing to summarise.", infraRoleLabel)
		return escalate("InfraNodesNeedResizingSRE: no infra nodes found")
	}

	pods := &corev1.PodList{}
	if err := r.K8sClient.List(ctx, pods); err != nil {
		r.Notes.AppendWarning("Pods: failed to list: %v", err)
		return escalate("Could not list pods")
	}

	pressure, byNamespace := summarise(infra, pods.Items)
	top := rankNamespaces(byNamespace)
	if len(top) > topConsumers {
		top = top[:topConsumers]
	}

	saturated := false
	lines := []string{"Infra node scheduled requests vs allocatable:"}
	for _, p := range pressure {
		lines = append(lines, fmt.Sprintf("  - %s: CPU %s/%s (%.0f%%), memory %s/%s (%.0f%%)",
			p.Name,
			formatCPU(p.CPUMilli), formatCPU(p.CPUAllocMilli), p.cpuRatio()*100,
			formatMem(p.MemBytes), formatMem(p.MemAllocBytes), p.memRatio()*100))
		if p.cpuRatio() >= highRequestRatio || p.memRatio() >= highRequestRatio {
			saturated = true
		}
	}
	lines = append(lines, "", "Top requesters by namespace (platform components):")
	if len(top) == 0 {
		lines = append(lines, "  - none (no running pods with requests on the infra nodes)")
	}
	for _, c := range top {
		lines = append(lines, fmt.Sprintf("  - %s: CPU %s, memory %s (%d pods)",
			c.Namespace, formatCPU(c.CPUMilli), formatMem(c.MemBytes), c.Pods))
	}

	r.Notes.AppendSuccess("Found %d infra node(s); summarising scheduled resource requests.", len(pressure))
	r.Notes.AppendAutomation("%s", strings.Join(lines, "\n"))

	if saturated {
		r.Notes.AppendWarning("At least one infra node is at or above %.0f%% of allocatable on scheduled requests. "+
			"Recommend resizing the infra machine pool to a larger instance type (or adding an infra node), "+
			"and rebalancing the top consumers listed above.", highRequestRatio*100)
	} else {
		r.Notes.AppendWarning("Scheduled requests are below %.0f%% of allocatable on every infra node. "+
			"The alert may be driven by live usage (not read in informing mode) rather than requests; "+
			"on-call should confirm against metrics before resizing.", highRequestRatio*100)
	}

	return escalate("InfraNodesNeedResizingSRE: infra-node resource summary recorded (informing mode)")
}

// summarise returns the per-node scheduled pressure (sorted by node name) and the
// per-namespace request totals for pods scheduled on the infra nodes. Completed
// pods (finished Jobs) are ignored: they still appear in the API but hold no
// resources.
func summarise(infra map[string]corev1.Node, pods []corev1.Pod) ([]nodePressure, map[string]*componentUsage) {
	byNode := make(map[string]*nodePressure, len(infra))
	for name, n := range infra {
		byNode[name] = &nodePressure{
			Name:          name,
			CPUAllocMilli: n.Status.Allocatable.Cpu().MilliValue(),
			MemAllocBytes: n.Status.Allocatable.Memory().Value(),
		}
	}

	byNamespace := map[string]*componentUsage{}
	for _, p := range pods {
		np, onInfra := byNode[p.Spec.NodeName]
		if !onInfra {
			continue
		}
		if p.Status.Phase == corev1.PodSucceeded || p.Status.Phase == corev1.PodFailed {
			continue
		}
		cpu, mem := podRequests(p)
		np.CPUMilli += cpu
		np.MemBytes += mem

		c := byNamespace[p.Namespace]
		if c == nil {
			c = &componentUsage{Namespace: p.Namespace}
			byNamespace[p.Namespace] = c
		}
		c.CPUMilli += cpu
		c.MemBytes += mem
		c.Pods++
	}

	pressures := make([]nodePressure, 0, len(byNode))
	for _, np := range byNode {
		pressures = append(pressures, *np)
	}
	sort.Slice(pressures, func(a, b int) bool { return pressures[a].Name < pressures[b].Name })
	return pressures, byNamespace
}

// podRequests sums the CPU (millicores) and memory (bytes) requests across a
// pod's regular containers.
func podRequests(p corev1.Pod) (cpuMilli, memBytes int64) {
	for i := range p.Spec.Containers {
		reqs := p.Spec.Containers[i].Resources.Requests
		cpuMilli += reqs.Cpu().MilliValue()
		memBytes += reqs.Memory().Value()
	}
	return cpuMilli, memBytes
}

// rankNamespaces orders the per-namespace totals by CPU request descending, then
// memory, then name, so the output is deterministic.
func rankNamespaces(byNamespace map[string]*componentUsage) []componentUsage {
	out := make([]componentUsage, 0, len(byNamespace))
	for _, c := range byNamespace {
		out = append(out, *c)
	}
	sort.Slice(out, func(a, b int) bool {
		if out[a].CPUMilli != out[b].CPUMilli {
			return out[a].CPUMilli > out[b].CPUMilli
		}
		if out[a].MemBytes != out[b].MemBytes {
			return out[a].MemBytes > out[b].MemBytes
		}
		return out[a].Namespace < out[b].Namespace
	})
	return out
}

// formatCPU renders millicores as cores with two decimals.
func formatCPU(milli int64) string {
	return fmt.Sprintf("%.2f cores", float64(milli)/1000.0)
}

// formatMem renders bytes as Gi (or Mi below 1Gi).
func formatMem(bytes int64) string {
	const (
		mi = 1 << 20
		gi = 1 << 30
	)
	if bytes >= gi {
		return fmt.Sprintf("%.2f Gi", float64(bytes)/float64(gi))
	}
	return fmt.Sprintf("%.0f Mi", float64(bytes)/float64(mi))
}

// Name returns the investigation name, which must match the package directory.
func (i *Investigation) Name() string {
	return investigationName
}

// AlertTitle returns the PagerDuty alert title this investigation handles.
func (i *Investigation) AlertTitle() string {
	return "InfraNodesNeedResizingSRE"
}

// Description returns a one-line summary of the investigation.
func (i *Investigation) Description() string {
	return "Summarises infra-node scheduled load and the top-requesting platform components (informing)"
}

// IsExperimental reports whether the investigation is gated behind CAD_EXPERIMENTAL_ENABLED.
func (i *Investigation) IsExperimental() bool {
	return false
}

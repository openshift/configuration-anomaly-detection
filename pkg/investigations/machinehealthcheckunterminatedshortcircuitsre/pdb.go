/*
machinehealthcheckunterminatedshortcircuitsre defines the investigation logic for the MachineHealthCheckUnterminatedShortCircuitSRE alert
*/
package machinehealthcheckunterminatedshortcircuitsre

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	servicelogsv1 "github.com/openshift-online/ocm-sdk-go/servicelogs/v1"
	"github.com/openshift/configuration-anomaly-detection/pkg/ocm"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	ktypes "k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	// drainStallThreshold is how long a node must carry the unschedulable taint before its drain is
	// treated as stalled rather than merely in progress.
	//
	// NOTE: pkg/investigations/pdbblockingnodedrain carries an equivalent constant and an equivalent
	// (cluster-wide) implementation of the PDB correlation below, and
	// clusterhealthcheck.checkRestrictivePDBs carries a third, node-agnostic variant. The three are
	// deliberately kept separate for now; consolidating them behind a shared helper is tracked as
	// follow-up work. Until then, keep this threshold and the taint semantics in sync with
	// pdbblockingnodedrain.
	drainStallThreshold = 10 * time.Minute

	// ownerNone is reported for pods that have no owner reference at all (bare pods), which cannot
	// be rescheduled by a controller and therefore always require manual handling.
	ownerNone = "none"
)

// drainBlocker describes a single PodDisruptionBudget that is preventing a specific node from
// completing its drain.
type drainBlocker struct {
	// Node is the name of the stalled node whose pods this PDB protects
	Node string
	// Namespace and Name identify the PodDisruptionBudget
	Namespace string
	Name      string
	// Constraint is the human-readable spec field that is doing the blocking,
	// e.g. "minAvailable: 3" or "maxUnavailable: 0"
	Constraint string
	// CurrentHealthy and ExpectedPods mirror the PDB's .status
	CurrentHealthy int32
	ExpectedPods   int32
	// Pods are the names of the PDB-selected pods running on Node
	Pods []string
	// OwnerWorkloads are the deduplicated "Kind/name" owners of Pods
	OwnerWorkloads []string
	// IsPlatformManaged is true when the PDB lives in a Red Hat-managed namespace, which changes who
	// is expected to remediate it
	IsPlatformManaged bool
}

// summarize renders the blocker as a recommendation note, including how long the drain has been
// stalled.
func (b drainBlocker) summarize(drainDuration time.Duration) string {
	owners := strings.Join(b.OwnerWorkloads, ", ")
	if owners == "" {
		owners = ownerNone
	}
	return fmt.Sprintf(
		"drain stalled for %s, blocked by PodDisruptionBudget %s/%s (%s, disruptionsAllowed: 0, healthy: %d/%d). Pods held on this node: %s. Owning workload(s): %s",
		drainDuration.Truncate(time.Second),
		b.Namespace, b.Name, b.Constraint,
		b.CurrentHealthy, b.ExpectedPods,
		strings.Join(b.Pods, ", "),
		owners,
	)
}

// stalledDrainDuration reports how long the node has been draining, and whether that exceeds
// drainStallThreshold.
//
// "Draining" is identified by the node.kubernetes.io/unschedulable NoSchedule taint specifically,
// rather than by any NoSchedule taint: a node can legitimately carry unrelated NoSchedule taints
// (dedicated workloads, custom taints set by the customer) without being drained at all, and
// treating those as a drain produces false positives.
func stalledDrainDuration(node corev1.Node) (time.Duration, bool) {
	taint, found := findUnschedulableTaint(node)
	if !found {
		return 0, false
	}
	// Without a TimeAdded we cannot tell how long the drain has been running, so we cannot claim it
	// is stalled. See SREP-1975.
	if taint.TimeAdded == nil {
		return 0, false
	}
	duration := time.Since(taint.TimeAdded.Time)
	if duration <= drainStallThreshold {
		return duration, false
	}
	return duration, true
}

// findUnschedulableTaint returns the node's cordon taint, if present
func findUnschedulableTaint(node corev1.Node) (corev1.Taint, bool) {
	for _, taint := range node.Spec.Taints {
		if taint.Key == corev1.TaintNodeUnschedulable && taint.Effect == corev1.TaintEffectNoSchedule {
			return taint, true
		}
	}
	return corev1.Taint{}, false
}

// findDrainBlockingPDBs correlates PodDisruptionBudgets that permit no disruptions with the pods
// running on the provided stalled nodes.
//
// A PDB is reported as a blocker when both of the following hold:
//   - its .status.disruptionsAllowed is 0, so the eviction API rejects every eviction it governs, and
//   - at least one pod it selects is running on a node whose drain has stalled.
//
// Those two conditions together are what actually holds the drain open, so identifying the blocker
// needs no correlation against eviction events.
func findDrainBlockingPDBs(ctx context.Context, k8scli client.Client, stalledNodes []corev1.Node) ([]drainBlocker, error) {
	if len(stalledNodes) == 0 {
		return nil, nil
	}

	stalledNodeNames := make(map[string]bool, len(stalledNodes))
	for _, node := range stalledNodes {
		stalledNodeNames[node.Name] = true
	}

	pdbList := &policyv1.PodDisruptionBudgetList{}
	if err := k8scli.List(ctx, pdbList); err != nil {
		return nil, fmt.Errorf("failed to list poddisruptionbudgets: %w", err)
	}

	// Pods are listed once and indexed by namespace. Only pods on a stalled node can contribute to a
	// blocked drain, so everything else is discarded immediately.
	podList := &corev1.PodList{}
	if err := k8scli.List(ctx, podList); err != nil {
		return nil, fmt.Errorf("failed to list pods: %w", err)
	}
	podsByNamespace := map[string][]corev1.Pod{}
	for _, pod := range podList.Items {
		if !stalledNodeNames[pod.Spec.NodeName] {
			continue
		}
		podsByNamespace[pod.Namespace] = append(podsByNamespace[pod.Namespace], pod)
	}

	blockers := []drainBlocker{}
	for _, pdb := range pdbList.Items {
		if pdb.Status.DisruptionsAllowed != 0 {
			continue
		}

		selector, err := metav1.LabelSelectorAsSelector(pdb.Spec.Selector)
		if err != nil {
			// A PDB with an unparseable selector cannot be attributed to a node, but it is worth
			// surfacing rather than silently dropping.
			return blockers, fmt.Errorf("failed to parse selector for poddisruptionbudget %s/%s: %w", pdb.Namespace, pdb.Name, err)
		}

		// A PDB can hold several nodes open at once, so group the matching pods per node and emit one
		// blocker per (PDB, node) pair.
		podsByNode := map[string][]corev1.Pod{}
		for _, pod := range podsByNamespace[pdb.Namespace] {
			if !selector.Matches(labels.Set(pod.Labels)) {
				continue
			}
			podsByNode[pod.Spec.NodeName] = append(podsByNode[pod.Spec.NodeName], pod)
		}

		for nodeName, pods := range podsByNode {
			podNames := make([]string, 0, len(pods))
			ownerSet := map[string]bool{}
			for _, pod := range pods {
				podNames = append(podNames, pod.Name)
				ownerSet[resolveWorkloadOwner(ctx, k8scli, pod)] = true
			}
			sort.Strings(podNames)

			owners := make([]string, 0, len(ownerSet))
			for owner := range ownerSet {
				owners = append(owners, owner)
			}
			sort.Strings(owners)

			blockers = append(blockers, drainBlocker{
				Node:              nodeName,
				Namespace:         pdb.Namespace,
				Name:              pdb.Name,
				Constraint:        describeConstraint(pdb),
				CurrentHealthy:    pdb.Status.CurrentHealthy,
				ExpectedPods:      pdb.Status.ExpectedPods,
				Pods:              podNames,
				OwnerWorkloads:    owners,
				IsPlatformManaged: isPlatformNamespace(pdb.Namespace),
			})
		}
	}

	// Map iteration above makes the ordering non-deterministic; sort so PagerDuty notes are stable
	// across runs and diffable by the responder.
	sort.Slice(blockers, func(a, b int) bool {
		if blockers[a].Node != blockers[b].Node {
			return blockers[a].Node < blockers[b].Node
		}
		if blockers[a].Namespace != blockers[b].Namespace {
			return blockers[a].Namespace < blockers[b].Namespace
		}
		return blockers[a].Name < blockers[b].Name
	})

	return blockers, nil
}

// describeConstraint renders whichever of the mutually exclusive PDB spec fields is set
func describeConstraint(pdb policyv1.PodDisruptionBudget) string {
	switch {
	case pdb.Spec.MinAvailable != nil:
		return fmt.Sprintf("minAvailable: %s", pdb.Spec.MinAvailable.String())
	case pdb.Spec.MaxUnavailable != nil:
		return fmt.Sprintf("maxUnavailable: %s", pdb.Spec.MaxUnavailable.String())
	default:
		return "no minAvailable or maxUnavailable set"
	}
}

// resolveWorkloadOwner walks a pod's owner reference chain to the top-level workload
// (Deployment, StatefulSet, DaemonSet, ...), so the note names something the responder or customer
// can actually act on rather than a generated ReplicaSet.
func resolveWorkloadOwner(ctx context.Context, k8scli client.Client, pod corev1.Pod) string {
	if len(pod.OwnerReferences) == 0 {
		return ownerNone
	}

	owner := pod.OwnerReferences[0]
	if owner.Kind != "ReplicaSet" {
		return fmt.Sprintf("%s/%s", owner.Kind, owner.Name)
	}

	rs := &appsv1.ReplicaSet{}
	if err := k8scli.Get(ctx, ktypes.NamespacedName{Namespace: pod.Namespace, Name: owner.Name}, rs); err != nil {
		return fmt.Sprintf("ReplicaSet/%s", owner.Name)
	}
	for _, rsOwner := range rs.OwnerReferences {
		if rsOwner.Kind == "Deployment" {
			return fmt.Sprintf("Deployment/%s", rsOwner.Name)
		}
	}
	return fmt.Sprintf("ReplicaSet/%s", owner.Name)
}

// isPlatformNamespace reports whether the namespace is Red Hat-managed. Customer-managed PDBs are
// the customer's to relax (SRE does not delete customer workloads); platform PDBs are SRE's.
func isPlatformNamespace(namespace string) bool {
	return strings.HasPrefix(namespace, "openshift-") ||
		strings.HasPrefix(namespace, "kube-") ||
		namespace == "openshift"
}

// customerPDBServiceLog renders the managed-notifications customer_pdb_preventing_drain template for
// a blocker caused by a customer-managed PDB.
//
// Template: https://github.com/openshift/managed-notifications/blob/master/osd/customer_pdb_preventing_drain.json
// The template declares severity Major; Important is used here instead, matching the OSL
// HCC-alignment already applied to scpSL (ROSAENG-59901). Note also that Major was dropped from the
// servicelog severity enum in ocm-api-model v0.0.471.
func customerPDBServiceLog(b drainBlocker) ocm.ServiceLog {
	return ocm.ServiceLog{
		Severity:    servicelogsv1.SeverityImportant,
		ServiceName: "SREManualAction",
		Summary:     "Action required: Pod Disruption Budget preventing Node Drain",
		Description: fmt.Sprintf(
			"Your cluster is attempting to drain node `%s` but there is a pod disruption budget set that is preventing the drain. The OSD SRE team has identified the pod as `%s` running in the namespace: `%s`. Please re-schedule this pod so that the node can drain. For more information on pod disruption budgets, see https://access.redhat.com/documentation/en-us/red_hat_openshift_service_on_aws/4/html/nodes/working-with-pods#nodes-pods-pod-distruption-about_nodes-pods-configuring#.",
			b.Node,
			strings.Join(b.Pods, ", "),
			b.Namespace,
		),
		InternalOnly: false,
	}
}

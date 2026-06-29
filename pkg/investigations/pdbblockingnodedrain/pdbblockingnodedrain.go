package pdbblockingnodedrain

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/openshift/configuration-anomaly-detection/pkg/executor"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/investigation"
	k8sclient "github.com/openshift/configuration-anomaly-detection/pkg/k8s"
	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
	"github.com/openshift/configuration-anomaly-detection/pkg/notewriter"
	"github.com/openshift/configuration-anomaly-detection/pkg/types"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	ktypes "k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	drainStallThreshold = 10 * time.Minute
	ownerNone           = "none"
)

type stalledNode struct {
	Node               corev1.Node
	UnschedulableSince time.Time
	DrainDuration      time.Duration
}

type blockingPDB struct {
	Namespace          string
	Name               string
	MinAvailable       string
	MaxUnavailable     string
	DisruptionsAllowed int32
	CurrentHealthy     int32
	ExpectedPods       int32
	MatchingPods       []string // pod names on draining nodes
	OwnerWorkloads     []string // deduplicated "Kind/name" strings
	IsPlatformManaged  bool
}

type Investigation struct{}

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

	ctx := context.Background()

	stalledNodes := i.checkDrainingNodes(ctx, r.K8sClient, r.Notes)

	if len(stalledNodes) == 0 {
		r.Notes.AppendSuccess("No nodes are stalled in draining state")
		result.Actions = append(
			executor.NoteAndReportFrom(r.Notes, r.Cluster.ID(), i.Name()),
			executor.Escalate("No stalled node drains detected, but alert fired: manual review required"),
		)
		return result, nil
	}

	blockingPDBs := i.checkBlockingPDBs(ctx, r.K8sClient, stalledNodes, r.Notes)
	unhealthyNodeCount := i.checkNodeHealth(ctx, r.K8sClient, r.Notes)
	i.checkScalingAssessment(blockingPDBs, unhealthyNodeCount, r.Notes)

	result.Actions = append(
		executor.NoteAndReportFrom(r.Notes, r.Cluster.ID(), i.Name()),
		executor.Escalate("PDB blocking node drain investigation: manual review required"),
	)
	return result, nil
}

// checkDrainingNodes lists all nodes and identifies those stuck in a draining state.
// A node is considered draining if it has the node.kubernetes.io/unschedulable taint.
// Nodes draining longer than drainStallThreshold are flagged as stalled.
//
// Returns the stalled draining nodes for use by subsequent investigation steps.
func (i *Investigation) checkDrainingNodes(ctx context.Context, k8sClient k8sclient.Client, notes *notewriter.NoteWriter) []stalledNode {
	nodeList := &corev1.NodeList{}
	if err := k8sClient.List(ctx, nodeList, &client.ListOptions{}); err != nil {
		notes.AppendWarning("Draining Nodes: failed to list nodes: %v", err)
		return nil
	}

	now := time.Now()
	var drainingCount int
	var stalled []stalledNode
	var stalledDetails []string
	var recentDetails []string

	for _, node := range nodeList.Items {
		taint, found := findUnschedulableTaint(node)
		if !found {
			continue
		}

		var unschedulableSince time.Time
		switch {
		case taint.TimeAdded != nil:
			unschedulableSince = taint.TimeAdded.Time
		case !node.CreationTimestamp.IsZero():
			unschedulableSince = node.CreationTimestamp.Time
		default:
			unschedulableSince = now
		}

		dn := stalledNode{
			Node:               node,
			UnschedulableSince: unschedulableSince,
			DrainDuration:      now.Sub(unschedulableSince),
		}
		drainingCount++

		duration := dn.DrainDuration.Truncate(time.Second)
		detail := fmt.Sprintf("%s: draining for %s", dn.Node.Name, duration)
		if dn.DrainDuration >= drainStallThreshold {
			stalled = append(stalled, dn)
			stalledDetails = append(stalledDetails, detail)
		} else {
			recentDetails = append(recentDetails, detail)
		}
	}

	if drainingCount == 0 {
		notes.AppendSuccess("Draining Nodes: no nodes are currently draining")
		return nil
	}

	if len(recentDetails) > 0 {
		notes.AppendSuccess("Draining Nodes: %d node(s) draining within threshold:\n  %s",
			len(recentDetails), strings.Join(recentDetails, "\n  "))
	}

	if len(stalled) == 0 {
		notes.AppendSuccess("Draining Nodes: %d node(s) draining, none stalled (all under %s threshold)",
			drainingCount, drainStallThreshold)
		return nil
	}

	notes.AppendWarning("Draining Nodes: %d/%d draining node(s) stalled (>%s):\n  %s",
		len(stalled), drainingCount, drainStallThreshold, strings.Join(stalledDetails, "\n  "))

	return stalled
}

// checkNodeHealth examines non-draining nodes and reports any that are NotReady or have
// resource pressure conditions. Unhealthy schedulable nodes mean evicted pods may not
// reschedule successfully, so scaling recommendations may not be effective.
func (i *Investigation) checkNodeHealth(ctx context.Context, k8sClient k8sclient.Client, notes *notewriter.NoteWriter) int {
	nodeList := &corev1.NodeList{}
	if err := k8sClient.List(ctx, nodeList, &client.ListOptions{}); err != nil {
		notes.AppendWarning("Node Health: failed to list nodes: %v", err)
		return 0
	}

	var unhealthyDetails []string
	for _, node := range nodeList.Items {
		if _, draining := findUnschedulableTaint(node); draining {
			continue
		}

		var issues []string
		for _, cond := range node.Status.Conditions {
			switch cond.Type {
			case corev1.NodeReady:
				if cond.Status != corev1.ConditionTrue {
					issues = append(issues, "NotReady")
				}
			case corev1.NodeDiskPressure, corev1.NodeMemoryPressure, corev1.NodePIDPressure:
				if cond.Status == corev1.ConditionTrue {
					issues = append(issues, string(cond.Type))
				}
			}
		}

		if len(issues) > 0 {
			unhealthyDetails = append(unhealthyDetails, fmt.Sprintf("%s: %s", node.Name, strings.Join(issues, ", ")))
		}
	}

	if len(unhealthyDetails) == 0 {
		notes.AppendSuccess("Node Health: all non-draining nodes are Ready with no resource pressure")
		return 0
	}

	notes.AppendWarning("Node Health: %d non-draining node(s) unhealthy, evicted pods may fail to reschedule:\n  %s",
		len(unhealthyDetails), strings.Join(unhealthyDetails, "\n  "))
	return len(unhealthyDetails)
}

// checkBlockingPDBs enumerates all PDBs with disruptionsAllowed==0 whose controlled pods
// are on draining nodes. For each blocking PDB it reports the configured constraint,
// matching pod names, and owning workloads.
//
// Returns the blocking PDBs for use by subsequent investigation steps.
func (i *Investigation) checkBlockingPDBs(ctx context.Context, k8sClient k8sclient.Client, stalledNodes []stalledNode, notes *notewriter.NoteWriter) []blockingPDB {
	stalledNodeNames := make(map[string]bool, len(stalledNodes))
	for _, dn := range stalledNodes {
		stalledNodeNames[dn.Node.Name] = true
	}

	pdbList := &policyv1.PodDisruptionBudgetList{}
	if err := k8sClient.List(ctx, pdbList); err != nil {
		notes.AppendWarning("Blocking PDBs: failed to list PodDisruptionBudgets: %v", err)
		return nil
	}

	// List all pods once and index by namespace for selector matching.
	podList := &corev1.PodList{}
	if err := k8sClient.List(ctx, podList); err != nil {
		notes.AppendWarning("Blocking PDBs: failed to list pods: %v", err)
		return nil
	}

	podsByNamespace := make(map[string][]corev1.Pod)
	for _, pod := range podList.Items {
		podsByNamespace[pod.Namespace] = append(podsByNamespace[pod.Namespace], pod)
	}

	blocking := make([]blockingPDB, 0, len(pdbList.Items))

	for _, pdb := range pdbList.Items {
		// Only consider PDBs that are fully blocking (no disruptions allowed at all).
		if pdb.Status.DisruptionsAllowed != 0 {
			continue
		}

		selector, err := metav1.LabelSelectorAsSelector(pdb.Spec.Selector)
		if err != nil {
			notes.AppendWarning("Blocking PDBs: failed to parse selector for %s/%s: %v", pdb.Namespace, pdb.Name, err)
			continue
		}

		// Find pods that match this PDB's selector AND are running on stalled nodes.
		var matchingPodNames []string
		ownerSet := make(map[string]bool)

		for _, pod := range podsByNamespace[pdb.Namespace] {
			if !selector.Matches(labels.Set(pod.Labels)) {
				continue
			}
			if !stalledNodeNames[pod.Spec.NodeName] {
				continue
			}

			matchingPodNames = append(matchingPodNames, pod.Name)

			owner := resolveWorkloadOwner(ctx, k8sClient, pod)
			ownerSet[owner] = true
		}

		if len(matchingPodNames) == 0 {
			continue
		}

		// Deduplicate owners (multiple pods may belong to the same workload).
		owners := make([]string, 0, len(ownerSet))
		for o := range ownerSet {
			owners = append(owners, o)
		}

		bp := blockingPDB{
			Namespace:          pdb.Namespace,
			Name:               pdb.Name,
			DisruptionsAllowed: pdb.Status.DisruptionsAllowed,
			CurrentHealthy:     pdb.Status.CurrentHealthy,
			ExpectedPods:       pdb.Status.ExpectedPods,
			MatchingPods:       matchingPodNames,
			OwnerWorkloads:     owners,
			IsPlatformManaged:  isPlatformNamespace(pdb.Namespace),
		}
		if pdb.Spec.MinAvailable != nil {
			bp.MinAvailable = pdb.Spec.MinAvailable.String()
		}
		if pdb.Spec.MaxUnavailable != nil {
			bp.MaxUnavailable = pdb.Spec.MaxUnavailable.String()
		}

		blocking = append(blocking, bp)
	}

	if len(blocking) == 0 {
		notes.AppendSuccess("Blocking PDBs: no PDBs with disruptionsAllowed=0 have pods on stalled nodes")
		return nil
	}

	var customerPDBs, platformPDBs []string
	for _, bp := range blocking {
		constraint := "minAvailable: " + bp.MinAvailable
		if bp.MinAvailable == "" {
			constraint = "maxUnavailable: " + bp.MaxUnavailable
		}
		managedBy := "customer"
		if bp.IsPlatformManaged {
			managedBy = "platform"
		}
		detail := fmt.Sprintf("%s/%s [%s] (%s, healthy: %d/%d)\n    Owner: %s\n    Pods on draining nodes: %s",
			bp.Namespace, bp.Name, managedBy, constraint, bp.CurrentHealthy, bp.ExpectedPods,
			strings.Join(bp.OwnerWorkloads, ", "),
			strings.Join(bp.MatchingPods, ", "))
		if bp.IsPlatformManaged {
			platformPDBs = append(platformPDBs, detail)
		} else {
			customerPDBs = append(customerPDBs, detail)
		}
	}

	allDetails := make([]string, 0, len(customerPDBs)+len(platformPDBs))
	allDetails = append(allDetails, customerPDBs...)
	allDetails = append(allDetails, platformPDBs...)
	notes.AppendWarning("Blocking PDBs: %d PDB(s) with disruptionsAllowed=0 affecting pods on stalled nodes:\n  %s",
		len(blocking), strings.Join(allDetails, "\n  "))

	if len(customerPDBs) > 0 {
		notes.AppendWarning("Remediation: %d customer-managed PDB(s): customer should relax the PDB or scale the workload to allow disruptions", len(customerPDBs))
	}
	if len(platformPDBs) > 0 {
		notes.AppendWarning("Remediation: %d platform-managed PDB(s): check node health or escalate to engineering if you suspect a bug that is blocking upgrades", len(platformPDBs))
	}

	return blocking
}

// resolveWorkloadOwner walks the owner reference chain of a pod to find the
// top-level workload (e.g. Deployment, StatefulSet, DaemonSet).
// For pods owned by a ReplicaSet, it checks if the ReplicaSet is owned by a Deployment.
func resolveWorkloadOwner(ctx context.Context, k8sClient k8sclient.Client, pod corev1.Pod) string {
	if len(pod.OwnerReferences) == 0 {
		return ownerNone
	}

	owner := pod.OwnerReferences[0]
	if owner.Kind != "ReplicaSet" {
		return fmt.Sprintf("%s/%s", owner.Kind, owner.Name)
	}

	rs := &appsv1.ReplicaSet{}
	if err := k8sClient.Get(ctx, ktypes.NamespacedName{Namespace: pod.Namespace, Name: owner.Name}, rs); err != nil {
		return fmt.Sprintf("ReplicaSet/%s", owner.Name)
	}
	for _, rsOwner := range rs.OwnerReferences {
		if rsOwner.Kind == "Deployment" {
			return fmt.Sprintf("Deployment/%s", rsOwner.Name)
		}
	}
	return fmt.Sprintf("ReplicaSet/%s", owner.Name)
}

// checkScalingAssessment evaluates whether scaling up the workload would unblock
// the drain for each blocking PDB, without requiring a PDB change.
func (i *Investigation) checkScalingAssessment(blockingPDBs []blockingPDB, unhealthyNodeCount int, notes *notewriter.NoteWriter) {
	if len(blockingPDBs) == 0 {
		return
	}

	var scalable, notScalable []string
	for _, bp := range blockingPDBs {
		assessment, canScale := assessScaling(bp)
		entry := fmt.Sprintf("%s/%s: %s", bp.Namespace, bp.Name, assessment)
		if canScale {
			scalable = append(scalable, entry)
		} else {
			notScalable = append(notScalable, entry)
		}
	}

	if len(scalable) > 0 {
		scalableMsg := strings.Join(scalable, "\n  ")
		if unhealthyNodeCount > 0 {
			scalableMsg += fmt.Sprintf("\n  NOTE: %d non-draining node(s) are unhealthy: new replicas may not schedule", unhealthyNodeCount)
		}
		notes.AppendWarning("Scaling Assessment: %d PDB(s) can be unblocked by scaling:\n  %s",
			len(scalable), scalableMsg)
	}
	if len(notScalable) > 0 {
		notes.AppendWarning("Scaling Assessment: %d PDB(s) cannot be unblocked by scaling alone:\n  %s",
			len(notScalable), strings.Join(notScalable, "\n  "))
	}
}

// assessScaling determines whether scaling the workload would unblock the drain
// for a given blocking PDB.
func assessScaling(bp blockingPDB) (string, bool) {
	if bp.MaxUnavailable != "" {
		if bp.MaxUnavailable == "0" || bp.MaxUnavailable == "0%" {
			return "scaling will not help: maxUnavailable=0 forbids all disruptions, PDB must be changed", false
		}
		unhealthy := bp.ExpectedPods - bp.CurrentHealthy
		return fmt.Sprintf("scaling will not help: %d pod(s) unhealthy beyond maxUnavailable threshold, unhealthy pods must recover (check for scheduling constraints such as anti-affinity, node selectors, or resource limits)", unhealthy), false
	}

	if bp.MinAvailable == "100%" {
		return "scaling will not help: minAvailable=100% requires all pods healthy, PDB must be changed", false
	}

	if bp.CurrentHealthy == bp.ExpectedPods {
		return fmt.Sprintf("scaling up by 1 replica would unblock the drain (healthy: %d, minAvailable: %s)", bp.CurrentHealthy, bp.MinAvailable), true
	}

	unhealthy := bp.ExpectedPods - bp.CurrentHealthy
	return fmt.Sprintf("scaling may help if new pods become healthy: %d of %d pod(s) currently unhealthy (minAvailable: %s); if pods remain Pending, check for scheduling constraints such as anti-affinity, node selectors, or resource limits",
		unhealthy, bp.ExpectedPods, bp.MinAvailable), true
}

func isPlatformNamespace(namespace string) bool {
	return strings.HasPrefix(namespace, "openshift-") ||
		strings.HasPrefix(namespace, "kube-") ||
		namespace == "openshift"
}

func findUnschedulableTaint(node corev1.Node) (corev1.Taint, bool) {
	for _, taint := range node.Spec.Taints {
		if taint.Key == corev1.TaintNodeUnschedulable && taint.Effect == corev1.TaintEffectNoSchedule {
			return taint, true
		}
	}
	return corev1.Taint{}, false
}

func (i *Investigation) Name() string {
	return "pdbblockingnodedrain"
}

func (i *Investigation) AlertTitle() string {
	return "HCPNodepoolUpgradeDelay"
}

func (i *Investigation) Description() string {
	return "Investigates PodDisruptionBudgets blocking node drain during cluster upgrades"
}

func (i *Investigation) IsExperimental() bool {
	return false
}

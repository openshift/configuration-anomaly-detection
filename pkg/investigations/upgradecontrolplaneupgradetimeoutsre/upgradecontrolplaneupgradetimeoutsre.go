// Package upgradecontrolplaneupgradetimeoutsre contains the investigation for the
// UpgradeControlPlaneUpgradeTimeoutSRE alert.
//
// The alert is raised by the managed-upgrade-operator (MUO) when the control-plane
// portion of a Classic cluster upgrade exceeds its timeout. The investigation only
// acts where CAD can take a concrete action:
//
//   - the upgrade has already completed: silence, MUO resolves the alert
//   - a node drain is blocked only by customer-managed PodDisruptionBudgets:
//     send the customer_pdb_preventing_drain_automated service log and silence
//
// Every other case is escalated to on-call without further classification.
package upgradecontrolplaneupgradetimeoutsre

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	servicelogsv1 "github.com/openshift-online/ocm-sdk-go/servicelogs/v1"
	configv1 "github.com/openshift/api/config/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/openshift/configuration-anomaly-detection/pkg/executor"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/investigation"
	k8sclient "github.com/openshift/configuration-anomaly-detection/pkg/k8s"
	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
	"github.com/openshift/configuration-anomaly-detection/pkg/ocm"
	"github.com/openshift/configuration-anomaly-detection/pkg/types"
)

const (
	investigationName = "upgradecontrolplaneupgradetimeoutsre"

	// checksTimeout bounds all cluster reads so a hung API call cannot block
	// the PD note and escalation.
	checksTimeout = 2 * time.Minute

	// drainStallThreshold is how long a node must have been cordoned before a
	// PDB with zero allowed disruptions is treated as blocking its drain.
	drainStallThreshold = 10 * time.Minute
)

// blockingPDB is a PodDisruptionBudget with zero allowed disruptions that
// selects at least one pod on a stalled draining node.
type blockingPDB struct {
	Namespace string
	Name      string
	Pods      []string // "namespace/pod" on stalled nodes
	Nodes     []string // stalled nodes those pods run on
	Customer  bool
}

// Investigation implements the UpgradeControlPlaneUpgradeTimeoutSRE investigation.
type Investigation struct{}

// Run gates on cluster type, then silences completed upgrades and sends a
// service log for customer-PDB-blocked drains. Everything else is escalated.
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

	// Management / service clusters: a stuck upgrade here is an incident with its own SOP.
	if r.IsInfrastructureCluster {
		r.Notes.AppendWarning("Cluster is a management/service cluster: treat as an incident and follow the infrastructure-cluster upgrade SOP.")
		result.StopInvestigations = errors.New("infrastructure cluster: manual incident handling")
		return escalate("Control-plane upgrade timeout on an infrastructure cluster")
	}

	// The alert comes from MUO, which only manages Classic upgrades.
	if r.IsHCP {
		r.Notes.AppendWarning("Cluster is HCP: UpgradeControlPlaneUpgradeTimeoutSRE is a Classic (MUO) alert.")
		return escalate("Unexpected HCP cluster for UpgradeControlPlaneUpgradeTimeoutSRE")
	}

	ctx, cancel := context.WithTimeout(context.Background(), checksTimeout)
	defer cancel()

	cv := &configv1.ClusterVersion{}
	if err := r.K8sClient.Get(ctx, client.ObjectKey{Name: "version"}, cv); err != nil {
		r.Notes.AppendWarning("ClusterVersion: failed to get: %v", err)
		return escalate("Could not read ClusterVersion")
	}

	if upgradeCompleted(cv) {
		r.Notes.AppendSuccess("ClusterVersion: upgrade to %s has completed; MUO will resolve the alert", cv.Status.Desired.Version)
		result.Actions = append(
			executor.NoteAndReportFrom(r.Notes, r.Cluster.ID(), i.Name()),
			executor.Silence("Control-plane upgrade already completed"),
		)
		return result, nil
	}

	pdbs, err := findBlockingPDBs(ctx, r.K8sClient, time.Now())
	if err != nil {
		r.Notes.AppendWarning("Blocking PDBs: %v", err)
		return escalate("Could not check for PDBs blocking node drain")
	}

	var customer, platform []blockingPDB
	for _, p := range pdbs {
		if p.Customer {
			customer = append(customer, p)
		} else {
			platform = append(platform, p)
		}
	}

	switch {
	case len(pdbs) == 0:
		r.Notes.AppendWarning("No automated action: no node drain is blocked by a PodDisruptionBudget")
		return escalate("UpgradeControlPlaneUpgradeTimeoutSRE: no automated action available")
	case len(platform) > 0:
		r.Notes.AppendWarning("Platform-managed PDB(s) blocking node drain: %s", pdbNames(platform))
		return escalate("Platform-managed PDB blocking node drain")
	}

	sl := newCustomerPDBPreventingDrainSL(customer)
	r.Notes.AppendWarning("Customer-managed PDB(s) blocking node drain: %s", pdbNames(customer))
	r.Notes.AppendAutomation("Sending service log: %s", sl.Summary)
	result.Actions = append(
		executor.NoteAndReportFrom(r.Notes, r.Cluster.ID(), i.Name()),
		executor.NewServiceLogAction(sl.Severity, sl.Summary).
			WithDescription(sl.Description).
			WithServiceName(sl.ServiceName).
			Build(),
		executor.Silence("Customer PDB blocking node drain: service log sent"),
	)
	return result, nil
}

// upgradeCompleted reports whether ClusterVersion has completed the desired
// release. A status that has not yet observed the latest spec is not trusted.
func upgradeCompleted(cv *configv1.ClusterVersion) bool {
	if cv.Status.ObservedGeneration != cv.Generation || len(cv.Status.History) == 0 {
		return false
	}
	latest := cv.Status.History[0]
	return latest.State == configv1.CompletedUpdate && latest.Version == cv.Status.Desired.Version
}

// findBlockingPDBs returns PDBs with zero allowed disruptions that select pods
// on control-plane nodes which have been cordoned for longer than drainStallThreshold.
func findBlockingPDBs(ctx context.Context, k8sClient k8sclient.Client, now time.Time) ([]blockingPDB, error) {
	nodes := &corev1.NodeList{}
	if err := k8sClient.List(ctx, nodes); err != nil {
		return nil, fmt.Errorf("failed to list nodes: %w", err)
	}
	stalled := map[string]bool{}
	for _, n := range nodes.Items {
		// The alert covers the control-plane part of the upgrade only; a cordoned
		// worker is not evidence for it.
		if isControlPlaneNode(n) && isStalledDrain(n, now) {
			stalled[n.Name] = true
		}
	}
	if len(stalled) == 0 {
		return nil, nil
	}

	pdbList := &policyv1.PodDisruptionBudgetList{}
	if err := k8sClient.List(ctx, pdbList); err != nil {
		return nil, fmt.Errorf("failed to list PodDisruptionBudgets: %w", err)
	}
	podList := &corev1.PodList{}
	if err := k8sClient.List(ctx, podList); err != nil {
		return nil, fmt.Errorf("failed to list pods: %w", err)
	}
	podsByNamespace := map[string][]corev1.Pod{}
	for _, p := range podList.Items {
		// Completed pods (e.g. finished Jobs) still match PDB selectors but do not block a drain.
		if p.Status.Phase == corev1.PodSucceeded || p.Status.Phase == corev1.PodFailed {
			continue
		}
		podsByNamespace[p.Namespace] = append(podsByNamespace[p.Namespace], p)
	}

	blocking := make([]blockingPDB, 0, len(pdbList.Items))
	for _, pdb := range pdbList.Items {
		if pdb.Status.DisruptionsAllowed != 0 {
			continue
		}
		selector, err := metav1.LabelSelectorAsSelector(pdb.Spec.Selector)
		if err != nil {
			continue
		}
		bp := blockingPDB{Namespace: pdb.Namespace, Name: pdb.Name, Customer: !isPlatformNamespace(pdb.Namespace)}
		nodeSet := map[string]bool{}
		for _, pod := range podsByNamespace[pdb.Namespace] {
			if stalled[pod.Spec.NodeName] && selector.Matches(labels.Set(pod.Labels)) {
				bp.Pods = append(bp.Pods, pod.Namespace+"/"+pod.Name)
				nodeSet[pod.Spec.NodeName] = true
			}
		}
		if len(bp.Pods) == 0 {
			continue
		}
		for n := range nodeSet {
			bp.Nodes = append(bp.Nodes, n)
		}
		sort.Strings(bp.Nodes)
		blocking = append(blocking, bp)
	}
	return blocking, nil
}

// isStalledDrain reports whether a node carries the unschedulable NoSchedule
// taint and has for at least drainStallThreshold. A taint without a recorded
// time is treated as stalled, since the alert itself only fires after the
// upgrade timeout. spec.unschedulable alone is not enough: it is set before the
// taint is added, so a freshly cordoned node would otherwise count as stalled.
func isStalledDrain(n corev1.Node, now time.Time) bool {
	for _, t := range n.Spec.Taints {
		if t.Key == corev1.TaintNodeUnschedulable && t.Effect == corev1.TaintEffectNoSchedule {
			return t.TimeAdded == nil || now.Sub(t.TimeAdded.Time) >= drainStallThreshold
		}
	}
	return false
}

// isControlPlaneNode reports whether a node carries a control-plane role label.
func isControlPlaneNode(n corev1.Node) bool {
	_, master := n.Labels["node-role.kubernetes.io/master"]
	_, controlPlane := n.Labels["node-role.kubernetes.io/control-plane"]
	return master || controlPlane
}

// isPlatformNamespace reports whether a namespace is owned by the platform.
func isPlatformNamespace(namespace string) bool {
	return strings.HasPrefix(namespace, "openshift-") ||
		strings.HasPrefix(namespace, "kube-") ||
		namespace == "openshift"
}

// pdbNames formats PDBs as "namespace/name" for the PD note.
func pdbNames(pdbs []blockingPDB) string {
	names := make([]string, 0, len(pdbs))
	for _, p := range pdbs {
		names = append(names, p.Namespace+"/"+p.Name)
	}
	return strings.Join(names, ", ")
}

// newCustomerPDBPreventingDrainSL mirrors the managed-notifications template
// osd/customer_pdb_preventing_drain_automated.json.
func newCustomerPDBPreventingDrainSL(pdbs []blockingPDB) *ocm.ServiceLog {
	nodeSet := map[string]bool{}
	var pods []string
	for _, p := range pdbs {
		pods = append(pods, p.Pods...)
		for _, n := range p.Nodes {
			nodeSet[n] = true
		}
	}
	nodes := make([]string, 0, len(nodeSet))
	for n := range nodeSet {
		nodes = append(nodes, n)
	}
	sort.Strings(nodes)
	sort.Strings(pods)

	return &ocm.ServiceLog{
		Severity:    servicelogsv1.SeverityImportant,
		ServiceName: "SREManualAction",
		Summary:     "Action required: Pod Disruption Budget(s) preventing Node Drain",
		Description: fmt.Sprintf("Your cluster is attempting to drain the node(s): `%s` but there is a pod disruption budget set that is preventing the drain. "+
			"The Managed OpenShift SRE team has identified the following workload(s) affected in namespace/pod-name format: `%s`. "+
			"Please re-schedule this pod so that the node can drain. For more information on pod disruption budgets please see "+
			"https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/nodes/working-with-pods#nodes-pods-pod-disruption-about_nodes-pods-configuring.",
			strings.Join(nodes, ", "), strings.Join(pods, ", ")),
		InternalOnly: false,
	}
}

// Name returns the investigation name, which must match the package directory.
func (i *Investigation) Name() string {
	return investigationName
}

// AlertTitle returns the PagerDuty alert title this investigation handles.
func (i *Investigation) AlertTitle() string {
	return "UpgradeControlPlaneUpgradeTimeoutSRE"
}

// Description returns a one-line summary of the investigation.
func (i *Investigation) Description() string {
	return "Silences completed control-plane upgrades and notifies customers whose PDBs block node drain"
}

// IsExperimental reports whether the investigation is gated behind CAD_EXPERIMENTAL_ENABLED.
func (i *Investigation) IsExperimental() bool {
	return false
}

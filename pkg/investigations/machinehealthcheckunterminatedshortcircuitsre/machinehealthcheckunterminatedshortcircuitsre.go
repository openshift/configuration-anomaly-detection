/*
machinehealthcheckunterminatedshortcircuitsre defines the investigation logic for the MachineHealthCheckUnterminatedShortCircuitSRE alert
*/
package machinehealthcheckunterminatedshortcircuitsre

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	servicelogsv1 "github.com/openshift-online/ocm-sdk-go/servicelogs/v1"
	machinev1beta1 "github.com/openshift/api/machine/v1beta1"
	"github.com/openshift/configuration-anomaly-detection/pkg/executor"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/investigation"
	machineutil "github.com/openshift/configuration-anomaly-detection/pkg/investigations/utils/machine"
	nodeutil "github.com/openshift/configuration-anomaly-detection/pkg/investigations/utils/node"
	k8sclient "github.com/openshift/configuration-anomaly-detection/pkg/k8s"
	"github.com/openshift/configuration-anomaly-detection/pkg/notewriter"
	"github.com/openshift/configuration-anomaly-detection/pkg/ocm"
	"github.com/openshift/configuration-anomaly-detection/pkg/types"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	alertname = "MachineHealthCheckUnterminatedShortCircuitSRE"
)

// scpSL is based on the managed-notifications template:
// https://github.com/openshift/managed-notifications/blob/master/osd/rosa_cluster_cant_manage_instances.json
// Severity updated from Major to Important per OSL HCC-alignment (ROSAENG-59901).
var scpSL = ocm.ServiceLog{
	Severity:     servicelogsv1.SeverityImportant,
	ServiceName:  "SREManualAction",
	Summary:      "Cluster degraded, action required",
	Description:  "Your cluster is unable to manage its AWS EC2 instances using AWS API operations such as ec2:RunInstances and ec2:TerminateInstances, which prevents critical cluster functions from operating. This can be caused by insufficient AWS IAM permissions, insufficient AWS quota, or ABAC policies blocking AWS instance operations. Please review the product documentation and ensure your cluster fulfils all prerequisites: https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws_classic_architecture/4/html/prepare_your_environment/rosa-sts-aws-prereqs.",
	InternalOnly: false,
}

type Investigation struct {
	// k8scli provides access to on-cluster resources
	k8scli k8sclient.Client
	// notes holds the messages that will be shared with Primary upon completion
	notes *notewriter.NoteWriter
	// recommendations holds the set of actions CAD recommends primary to take
	recommendations investigationRecommendations
	// scpMisconfigured is true when a misconfigured SCP prevents AWS access (e.g. runInstances)
	scpMisconfigured bool
	// stalledDrains maps the name of each healthcheck-managed node whose drain has stalled to how
	// long it has been draining
	stalledDrains map[string]time.Duration
	// drainBlockers maps a stalled node's name to the PodDisruptionBudget(s) holding its drain open
	drainBlockers map[string][]drainBlocker
	// pdbServiceLogs holds the servicelogs CAD would send for customer-managed PDBs blocking a drain.
	// They are only dispatched once the informing phase concludes - see Run()
	pdbServiceLogs []ocm.ServiceLog
	// notReadyNodesFound is true when at least one healthcheck-managed node is not Ready, which is
	// what makes a pull secret check worth running
	notReadyNodesFound bool
}

// Run investigates the MachineHealthCheckUnterminatedShortCircuitSRE alert
//
// The investigation seeks to provide exactly one recommended action per affected machine/node pair.
// The machine object is evaluated first, as it represents a lower-level object that could affect the health of the node.
// If the investigation determines that the breakage is occurring at the machine-level, the corresponding node is *not* investigated.
// After investigating all affected machines, potentially affected nodes are investigated.
func (i *Investigation) Run(rb investigation.ResourceBuilder) (investigation.InvestigationResult, error) {
	ctx := context.Background()
	result := investigation.InvestigationResult{}
	r, err := rb.WithK8sClient().WithCluster().WithNotes().Build()
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

	i.k8scli = r.K8sClient
	i.notes = r.Notes
	i.recommendations = investigationRecommendations{}
	i.scpMisconfigured = false
	i.stalledDrains = map[string]time.Duration{}
	i.drainBlockers = map[string][]drainBlocker{}
	i.pdbServiceLogs = nil
	i.notReadyNodesFound = false

	targetMachines, err := i.getMachinesFromFailingMHC(ctx)
	if err != nil {
		i.notes.AppendWarning("failed to retrieve one or more target machines: %v", err)
	}
	if len(targetMachines) == 0 {
		i.notes.AppendWarning("no machines found for short-circuited machinehealthcheck objects")
		result.Actions = append(
			executor.NoteAndReportFrom(i.notes, r.Cluster.ID(), i.Name()),
			executor.Escalate("No machines found for short-circuited MHC objects"),
		)
		return result, nil
	}

	// Evaluate the drain state of every node managed by the short-circuited healthcheck(s) up front.
	// A node can sit stalled mid-drain without its machine ever carrying a DeletionTimestamp -
	// cluster-autoscaler scale-down and `oc scale machineset --replicas=0` both produce that shape -
	// so this cannot be driven off the deleting-machine path alone.
	i.investigateDrainBlockers(ctx, targetMachines)

	problemMachines, err := i.InvestigateMachines(ctx, targetMachines)
	if err != nil {
		i.notes.AppendWarning("failed to investigate machines: %v", err)
	}

	// Trim out the machines that we've already investigated and know have problems
	//
	// The purpose of this is to avoid re-investigating nodes whose machines were already investigated. Any node-level issue on a failing machine
	// is most likely related to the machine itself, and providing duplicate/conflicting advice will only prove confusing to the responder
	targetMachines = slices.DeleteFunc(targetMachines, func(targetMachine machinev1beta1.Machine) bool {
		for _, problemMachine := range problemMachines {
			if problemMachine.Name == targetMachine.Name {
				return true
			}
		}
		return false
	})

	// If one or more machines managed by the machinehealthcheck have not yet been identified as a problem, check on the machine's
	// node to determine if there are node-level problems that need remediating
	if len(targetMachines) > 0 {
		targetNodes, err := machineutil.GetNodesForMachines(ctx, i.k8scli, targetMachines)
		if err != nil {
			i.notes.AppendWarning("failed to retrieve one or more target nodes: %v", err)
		}
		if len(targetNodes) > 0 {
			i.InvestigateNodes(targetNodes)
		}
	}

	// A pull secret that no longer matches OCM stops the kubelet pulling images, which is one of the
	// ways a group of nodes goes NotReady at once and short-circuits the healthcheck. Only worth the
	// extra API calls once we know some node is actually NotReady.
	if i.notReadyNodesFound {
		i.validatePullSecret(r)
	}

	if i.scpMisconfigured {
		i.notes.AppendWarning("a misconfigured SCP is denying ec2:RunInstances; a service log has been sent to the customer to review the AWS permissions required to manage cluster instances")
		result.Actions = append(
			result.Actions,
			executor.NewServiceLogAction(scpSL.Severity, scpSL.Summary).
				WithDescription(scpSL.Description).
				WithServiceName(scpSL.ServiceName).
				Build(),
		)
	}

	// Summarize recommendations from investigation in PD notes, if any found
	if len(i.recommendations) > 0 {
		i.notes.AppendWarning("%s", i.recommendations.summarize())
	} else {
		i.notes.AppendSuccess("no recommended actions to take against cluster")
	}

	// Per the Pod Disruption Budget section of the MCDDrainError SOP, a customer-managed PDB blocking
	// a drain is remediated by servicelog rather than by SRE touching the workload. CAD is still in
	// the informing phase for this detection: it states the servicelog it would send so the
	// condition can be validated against real incidents before CAD is allowed to message customers.
	//
	// Remove this gate, and send unconditionally, once the informing phase concludes.
	if len(i.pdbServiceLogs) > 0 {
		experimentalEnabled, _ := strconv.ParseBool(os.Getenv("CAD_EXPERIMENTAL_ENABLED"))
		for _, sl := range i.pdbServiceLogs {
			if !experimentalEnabled {
				i.notes.AppendWarning(
					"INFORMING PHASE: CAD did NOT send the following service log. Please confirm it is correct before sending it manually.\nSummary: %s\nDescription: %s",
					sl.Summary, sl.Description,
				)
				continue
			}
			result.Actions = append(
				result.Actions,
				executor.NewServiceLogAction(sl.Severity, sl.Summary).
					WithDescription(sl.Description).
					WithServiceName(sl.ServiceName).
					Build(),
			)
		}
	}

	result.Actions = append(
		result.Actions,
		executor.NoteAndReportFrom(i.notes, r.Cluster.ID(), i.Name())...,
	)

	// A SL is queued to be sent already for the SCP, no other actionable items
	if i.scpMisconfigured && len(i.recommendations) == 0 {
		result.Actions = append(
			result.Actions,
			executor.Silence("Unactionable by SRE"),
		)
	} else {
		// A SL is queued to be sent out for a misconfigured SCP, but there are other findings
		// to be addressed by primary.
		result.Actions = append(
			result.Actions,
			executor.Escalate("MachineHealthCheck investigation complete"),
		)
	}
	return result, nil
}

func (i *Investigation) getMachinesFromFailingMHC(ctx context.Context) ([]machinev1beta1.Machine, error) {
	healthchecks := machinev1beta1.MachineHealthCheckList{}
	err := i.k8scli.List(ctx, &healthchecks, &client.ListOptions{Namespace: machineutil.MachineNamespace})
	if err != nil {
		return []machinev1beta1.Machine{}, investigation.WrapInfrastructure(
			fmt.Errorf("failed to retrieve machinehealthchecks from cluster: %w", err),
			"K8s API failure listing MachineHealthChecks")
	}

	targets := []machinev1beta1.Machine{}
	for _, healthcheck := range healthchecks.Items {
		if !machineutil.HealthcheckRemediationAllowed(healthcheck) {
			machines, err := machineutil.GetMachinesForMHC(ctx, i.k8scli, healthcheck)
			if err != nil {
				i.notes.AppendWarning("failed to retrieve machines from machinehealthcheck %q: %v", healthcheck.Name, err)
				continue
			}
			targets = append(targets, machines...)
		}
	}

	return targets, nil
}

// InvestigateMachines evaluates the state of the machines in the cluster and returns a list of the failing machines, along with a categorized set of recommendations based on the failure state of
// each machine
func (i *Investigation) InvestigateMachines(ctx context.Context, targets []machinev1beta1.Machine) ([]machinev1beta1.Machine, error) {
	investigatedMachines := []machinev1beta1.Machine{}
	var errs error
	for _, machine := range targets {
		if machine.DeletionTimestamp != nil {
			err := i.investigateDeletingMachine(ctx, machine)
			investigatedMachines = append(investigatedMachines, machine)
			if err != nil {
				errs = errors.Join(errs, fmt.Errorf("failed to investigate deleting machine: %w", err))
			}
			continue
		}

		if (machine.Status.Phase != nil && *machine.Status.Phase == machinev1beta1.PhaseFailed) || machine.Status.ErrorReason != nil {
			err := i.investigateFailingMachine(machine)
			investigatedMachines = append(investigatedMachines, machine)
			if err != nil {
				errs = errors.Join(errs, fmt.Errorf("failed to investigate failing machine: %w", err))
			}
		}
	}

	if len(investigatedMachines) == 0 {
		i.notes.AppendSuccess("no deleting or Failed machines found")
	}
	return investigatedMachines, errs
}

// investigateFailingMachin evaluates a machine whose .Status.Phase is failed, and provides a recommendation based on the cause of the failure
func (i *Investigation) investigateFailingMachine(machine machinev1beta1.Machine) error {
	role, err := machineutil.GetRole(machine)
	if err != nil {
		// Failing to determine whether a machine is Red Hat-managed warrants manual investigation
		notes := fmt.Sprintf("unable to determine machine role: %v", err)
		i.recommendations.addRecommendation(recommendationInvestigateMachine, machine.Name, notes)
		return fmt.Errorf("failed to determine role for machine %q: %w", machine.Name, err)
	}

	// Safely dereference status fields to avoid panics in cases where machines' statuses haven't been fully populated
	var errorMsg string
	if machine.Status.ErrorMessage != nil {
		errorMsg = *machine.Status.ErrorMessage
	}

	// A SCP prevents runInstances
	if isSCPRunInstancesDeny(errorMsg) {
		i.scpMisconfigured = true
		return nil
	}

	if role != machineutil.WorkerRoleLabelValue {
		// If machine is Red-Hat owned, always require manual investigation
		notes := fmt.Sprintf("Red Hat-owned machine in terminal error state with message: %s", errorMsg)
		i.recommendations.addRecommendation(recommendationInvestigateMachine, machine.Name, notes)
		return nil
	}

	var errorReason machinev1beta1.MachineStatusError
	if machine.Status.ErrorReason != nil {
		errorReason = *machine.Status.ErrorReason
	}

	switch errorReason {
	case machinev1beta1.IPAddressInvalidReason:
		notes := fmt.Sprintf("invalid IP address: %q. Deleting machine may allow the cloud provider to assign a valid IP address", errorMsg)
		i.recommendations.addRecommendation(recommendationDeleteMachine, machine.Name, notes)

	case machinev1beta1.CreateMachineError:
		notes := fmt.Sprintf("machine failed to create: %q. Deleting machine may resolve any transient issues with the cloud provider", errorMsg)
		i.recommendations.addRecommendation(recommendationDeleteMachine, machine.Name, notes)

	case machinev1beta1.InvalidConfigurationMachineError:
		notes := fmt.Sprintf("the machine configuration is invalid: %q. Checking splunk audit logs may indicate whether the customer has modified the machine or its machineset", errorMsg)
		i.recommendations.addRecommendation(recommendationInvestigateMachine, machine.Name, notes)

	case machinev1beta1.DeleteMachineError:
		notes := fmt.Sprintf("the machine's node could not be gracefully terminated automatically: %q", errorMsg)
		i.recommendations.addRecommendation(recommendationInvestigateMachine, machine.Name, notes)

	case machinev1beta1.InsufficientResourcesMachineError:
		notes := fmt.Sprintf("a servicelog should be sent because there is insufficient quota to provision the machine: %q", errorMsg)
		i.recommendations.addRecommendation(recommendationQuotaServiceLog, machine.Name, notes)

	default:
		notes := "no .Status.ErrorReason found for machine"
		i.recommendations.addRecommendation(recommendationInvestigateMachine, machine.Name, notes)
	}
	return nil
}

// InvestigateDeletingMachines evaluates machines which are being deleted, to determine if & why they are blocked, along with a recommendation on how to unblock them
func (i *Investigation) investigateDeletingMachine(ctx context.Context, machine machinev1beta1.Machine) error {
	if machine.Status.NodeRef == nil {
		notes := "machine stuck deleting with no node"
		i.recommendations.addRecommendation(recommendationInvestigateMachine, machine.Name, notes)
		return nil
	}
	node, err := machineutil.GetNodeForMachine(ctx, i.k8scli, machine)
	if err != nil {
		notes := "machine's node could not be determined"
		i.recommendations.addRecommendation(recommendationInvestigateMachine, machine.Name, notes)
		return fmt.Errorf("failed to retrieve node for machine %q: %w", machine.Name, err)
	}

	if i.recommendStuckDrain(node.Name) {
		return nil
	}

	notes := "unable to determine why machine is stuck deleting"
	i.recommendations.addRecommendation(recommendationInvestigateMachine, machine.Name, notes)
	return nil
}

// investigateDrainBlockers determines which of the healthcheck's nodes are stalled mid-drain, and
// which PodDisruptionBudget - if any - is holding each one open.
//
// Results are cached on the Investigation so the per-machine and per-node passes can report them
// without re-querying the API, and so a node is never reported twice.
func (i *Investigation) investigateDrainBlockers(ctx context.Context, machines []machinev1beta1.Machine) {
	nodes, err := machineutil.GetNodesForMachines(ctx, i.k8scli, machines)
	if err != nil {
		i.notes.AppendWarning("failed to retrieve nodes while checking for stalled drains: %v", err)
		return
	}

	stalled := []corev1.Node{}
	for _, node := range nodes {
		if duration, isStalled := stalledDrainDuration(node); isStalled {
			i.stalledDrains[node.Name] = duration
			stalled = append(stalled, node)
		}
	}
	if len(stalled) == 0 {
		return
	}

	// A partial result is still worth reporting, so the blockers found before the error are kept.
	blockers, err := findDrainBlockingPDBs(ctx, i.k8scli, stalled)
	if err != nil {
		i.notes.AppendWarning("failed to determine whether a PodDisruptionBudget is blocking the stalled drain(s): %v", err)
	}
	for _, blocker := range blockers {
		i.drainBlockers[blocker.Node] = append(i.drainBlockers[blocker.Node], blocker)
	}
}

// recommendStuckDrain records a recommendation for a node whose drain has stalled, naming the
// blocking PodDisruptionBudget where one was found.
//
// It reports whether the node was stalled at all, so callers can fall through to their own
// diagnosis when it was not.
func (i *Investigation) recommendStuckDrain(nodeName string) bool {
	duration, stalled := i.stalledDrains[nodeName]
	if !stalled {
		return false
	}

	blockers := i.drainBlockers[nodeName]
	if len(blockers) == 0 {
		notes := fmt.Sprintf(
			"drain stalled for %s, but no PodDisruptionBudget with disruptionsAllowed=0 selects a pod on this node. Something else is holding the drain open: check for pods stuck Terminating, a volume that will not detach, or an unresponsive kubelet",
			duration.Truncate(time.Second),
		)
		i.recommendations.addRecommendation(recommendationInvestigateNode, nodeName, notes)
		return true
	}

	for _, blocker := range blockers {
		if blocker.IsPlatformManaged {
			i.recommendations.addRecommendation(recommendationPlatformPDBBlockingDrain, nodeName, blocker.summarize(duration))
			continue
		}
		i.recommendations.addRecommendation(recommendationCustomerPDBBlockingDrain, nodeName, blocker.summarize(duration))
		i.pdbServiceLogs = append(i.pdbServiceLogs, customerPDBServiceLog(blocker))
	}
	return true
}

// InvestigateNodes examines the provided nodes and returns recommended actions, if any are needed
func (i *Investigation) InvestigateNodes(nodes []corev1.Node) {
	for _, node := range nodes {
		i.InvestigateNode(node)
	}
}

// InvestigateNode examines a node and determines if further investigation is required
func (i *Investigation) InvestigateNode(node corev1.Node) {
	roleLabel, found := nodeutil.GetRole(node)
	if !found {
		notes := fmt.Sprintf("no role label containing %q found for node", nodeutil.RoleLabelPrefix)
		i.recommendations.addRecommendation(recommendationInvestigateNode, node.Name, notes)
		return
	} else if !strings.Contains(roleLabel, nodeutil.WorkerRoleSuffix) {
		notes := "non-worker node affected"
		i.recommendations.addRecommendation(recommendationInvestigateNode, node.Name, notes)
		return
	}

	// A node stalled mid-drain is usually still Ready, and the drain is the more specific and more
	// actionable finding, so it takes precedence over the Ready condition below.
	if i.recommendStuckDrain(node.Name) {
		return
	}

	ready, found := nodeutil.FindReadyCondition(node)
	if !found {
		notes := "found no 'Ready' .Status.Condition for the node"
		i.recommendations.addRecommendation(recommendationInvestigateNode, node.Name, notes)
		return
	}

	if ready.Status != corev1.ConditionTrue {
		i.notReadyNodesFound = true
		lastCheckinElapsed := time.Since(ready.LastHeartbeatTime.Time).Truncate(time.Second)
		statusDesc := "Unknown"
		if ready.Status == corev1.ConditionFalse {
			statusDesc = "NotReady"
		}
		notes := fmt.Sprintf("node has been in %s state for %s", statusDesc, lastCheckinElapsed)
		i.recommendations.addRecommendation(recommendationInvestigateNode, node.Name, notes)
	}
}

func (i *Investigation) Name() string {
	return strings.ToLower(alertname)
}

// isSCPRunInstancesDeny verifies if the error message is due to a SCP denying RunInstances events
func isSCPRunInstancesDeny(errorMsg string) bool {
	return strings.Contains(errorMsg, "is not authorized to perform: ec2:RunInstances") &&
		strings.Contains(errorMsg, "with an explicit deny in a service control policy")
}

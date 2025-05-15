/*
machinehealthcheckunterminatedshortcircuitsre defines the investigation logic for the MachineHealthCheckUnterminatedShortCircuitSRE alert
*/
package machinehealthcheckunterminatedshortcircuitsre

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	machinev1beta1 "github.com/openshift/api/machine/v1beta1"

	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/investigation"
	machineutil "github.com/openshift/configuration-anomaly-detection/pkg/investigations/utils/machine"
	nodeutil "github.com/openshift/configuration-anomaly-detection/pkg/investigations/utils/node"
	k8sclient "github.com/openshift/configuration-anomaly-detection/pkg/k8s"
	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
	"github.com/openshift/configuration-anomaly-detection/pkg/notewriter"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	alertname = "MachineHealthCheckUnterminatedShortCircuitSRE"
	// remediationName must match the name of this investigation's directory, so it can be looked up via the backplane-api
	remediationName = "machineHealthCheckUnterminatedShortCircuitSRE"
)

type Investigation struct {
	// kclient provides access to on-cluster resources
	kclient client.Client
	// notes holds the messages that will be shared with Primary upon completion
	notes *notewriter.NoteWriter
	// recommendations holds the set of actions CAD recommends primary to take
	recommendations investigationRecommendations
}

func (i *Investigation) setup(r *investigation.Resources) error {
	// Setup investigation
	k, err := k8sclient.New(r.Cluster.ID(), r.OcmClient, remediationName)
	if err != nil {
		return fmt.Errorf("failed to initialize kubernetes client: %w", err)
	}
	i.kclient = k
	i.notes = notewriter.New(r.Name, logging.RawLogger)
	i.recommendations = investigationRecommendations{}

	return nil
}

// Run investigates the MachineHealthCheckUnterminatedShortCircuitSRE alert
//
// The investigation seeks to provide exactly one recommended action per affected machine/node pair.
// The machine object is evaluated first, as it represents a lower-level object that could affect the health of the node.
// If the investigation determines that the breakage is occurring at the machine-level, the corresponding node is *not* investigated.
// After investigating all affected machines, potentially affected nodes are investigated.
func (i *Investigation) Run(r *investigation.Resources) (investigation.InvestigationResult, error) {
	ctx := context.Background()
	result := investigation.InvestigationResult{}

	// Setup & teardown
	err := i.setup(r)
	if err != nil {
		return result, fmt.Errorf("failed to setup investigation: %w", err)
	}
	defer func(r *investigation.Resources) {
		err := k8sclient.Cleanup(r.Cluster.ID(), r.OcmClient, remediationName)
		if err != nil {
			logging.Errorf("failed to cleanup investigation: %w", err)
		}
	}(r)

	targetMachines, err := i.getMachinesFromFailingMHC(ctx)
	if err != nil {
		i.notes.AppendWarning("failed to retrieve one or more target machines: %v", err)
	}
	if len(targetMachines) == 0 {
		i.notes.AppendWarning("no machines found for short-circuited machinehealthcheck objects")
		return result, r.PdClient.EscalateIncidentWithNote(i.notes.String())
	}

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
		targetNodes, err := machineutil.GetNodesForMachines(ctx, i.kclient, targetMachines)
		if err != nil {
			i.notes.AppendWarning("failed to retrieve one or more target nodes: %v", err)
		}
		if len(targetNodes) > 0 {
			i.InvestigateNodes(targetNodes)
		}
	}

	// Summarize recommendations from investigation in PD notes, if any found
	if len(i.recommendations) > 0 {
		i.notes.AppendWarning(i.recommendations.summarize())
	} else {
		i.notes.AppendSuccess("no recommended actions to take against cluster")
	}

	return result, r.PdClient.EscalateIncidentWithNote(i.notes.String())
}

func (i *Investigation) getMachinesFromFailingMHC(ctx context.Context) ([]machinev1beta1.Machine, error) {
	healthchecks := machinev1beta1.MachineHealthCheckList{}
	err := i.kclient.List(ctx, &healthchecks, &client.ListOptions{Namespace: machineutil.MachineNamespace})
	if err != nil {
		return []machinev1beta1.Machine{}, fmt.Errorf("failed to retrieve machinehealthchecks from cluster: %w", err)
	}

	targets := []machinev1beta1.Machine{}
	for _, healthcheck := range healthchecks.Items {
		if !machineutil.HealthcheckRemediationAllowed(healthcheck) {
			machines, err := machineutil.GetMachinesForMHC(ctx, i.kclient, healthcheck)
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

	var errorReason machinev1beta1.MachineStatusError
	if machine.Status.ErrorReason != nil {
		errorReason = *machine.Status.ErrorReason
	}

	if role != machineutil.WorkerRoleLabelValue {
		// If machine is Red-Hat owned, always require manual investigation
		notes := fmt.Sprintf("Red Hat-owned machine in state %q due to %q", errorReason, errorMsg)
		i.recommendations.addRecommendation(recommendationInvestigateMachine, machine.Name, notes)
		return nil
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
	node, err := machineutil.GetNodeForMachine(ctx, i.kclient, machine)
	if err != nil {
		notes := "machine's node could not be determined"
		i.recommendations.addRecommendation(recommendationInvestigateMachine, machine.Name, notes)
		return fmt.Errorf("failed to retrieve node for machine %q: %w", machine.Name, err)
	}

	stuck, duration := checkForStuckDrain(node)
	if stuck {
		notes := fmt.Sprintf("node %q found to be stuck draining for %s", node.Name, duration.Truncate(time.Second).String())
		i.recommendations.addRecommendation(recommendationInvestigateNode, node.Name, notes)
		return nil
	}

	notes := "unable to determine why machine is stuck deleting"
	i.recommendations.addRecommendation(recommendationInvestigateMachine, machine.Name, notes)
	return nil
}

// checkForStuckDrain makes a best-effort approximation at whether a node is stuck draining a specific pod
func checkForStuckDrain(node corev1.Node) (bool, *time.Duration) {
	if len(node.Spec.Taints) == 0 {
		return false, nil
	}

	taint, found := nodeutil.FindNoScheduleTaint(node)
	if !found {
		return false, nil
	}

	// TODO - Once CAD can access on-cluster metrics, we can query the `pods_preventing_node_drain` metric from prometheus
	// to more accurately gauge if a node is truly stuck deleting, and what pod is causing it
	drainDuration := time.Since(taint.TimeAdded.Time)
	if drainDuration > 10*time.Minute {
		return true, &drainDuration
	}

	return false, nil
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

	ready, found := nodeutil.FindReadyCondition(node)
	if !found {
		notes := "found no 'Ready' .Status.Condition for the node"
		i.recommendations.addRecommendation(recommendationInvestigateNode, node.Name, notes)
		return
	}

	if ready.Status != corev1.ConditionTrue {
		lastCheckinElapsed := time.Since(ready.LastHeartbeatTime.Time).Truncate(time.Second)
		notes := fmt.Sprintf("node has been %q for %s", ready.Status, lastCheckinElapsed)
		i.recommendations.addRecommendation(recommendationInvestigateNode, node.Name, notes)
	}
}

func (i *Investigation) Name() string {
	return alertname
}

func (i *Investigation) Description() string {
	return fmt.Sprintf("Investigates '%s' alerts", alertname)
}

func (i *Investigation) IsExperimental() bool {
	return false
}

func (i *Investigation) ShouldInvestigateAlert(alert string) bool {
	return strings.Contains(alert, alertname)
}

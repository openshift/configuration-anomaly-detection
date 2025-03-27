/*
machinehealthcheckunterminatedshortcircuitsre defines the investigation logic for the MachineHealthCheckUnterminatedShortCircuitSRE alert
*/
package machinehealthcheckunterminatedshortcircuitsre

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/investigation"
	k8sclient "github.com/openshift/configuration-anomaly-detection/pkg/k8s"
	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
	"github.com/openshift/configuration-anomaly-detection/pkg/notewriter"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	machinev1beta1 "github.com/openshift/api/machine/v1beta1"
)

const (
	alertname = "MachineHealthCheckUnterminatedShortCircuitSRE"
	// remediationName must match the name of this investigation's directory, so it can be looked up via the backplane-api
	remediationName = "machineHealthCheckUnterminatedShortCircuitSRE"

	machineNamespace  = "openshift-machine-api"
	machineRoleLabel  = "machine.openshift.io/cluster-api-machine-role"
	machineRoleWorker = "worker"

	nodeRoleLabelPrefix  = "node-role.kubernetes.io"
	nodeRoleWorkerSuffix = "worker"
)

type Investigation struct{
	kclient client.Client
	notes   *notewriter.NoteWriter
}

func (i *Investigation) setup(r *investigation.Resources) error {
	// Setup investigation
	k, err := k8sclient.New(r.Cluster.ID(), r.OcmClient, remediationName)
	if err != nil {
		return fmt.Errorf("failed to initialize kubernetes client: %w", err)
	}
	i.kclient = k
	i.notes = notewriter.New(r.Name, logging.RawLogger)

	return nil
}

func (i *Investigation) cleanup(r *investigation.Resources) error {
		return k8sclient.Cleanup(r.Cluster.ID(), r.OcmClient, remediationName)
}

// Run investigates the MachineHealthCheckUnterminatedShortCircuitSRE alert
func (i *Investigation) Run(r *investigation.Resources) (investigation.InvestigationResult, error) {
	result := investigation.InvestigationResult{}

	// Setup & teardown
	err := i.setup(r)
	if err != nil {
		return result, fmt.Errorf("failed to setup investigation: %w", err)
	}
	defer func(r *investigation.Resources) {
		err := i.cleanup(r)
		if err != nil {
			logging.Errorf("failed to cleanup investigation: %w", err)
		}
	}(r)

	// Execute investigation

	// Examine machines - in addition to broken nodes, machines in the 'Failing' phase are counted against a machinehealthcheck's maxUnhealthy count:
	// https://github.com/openshift/machine-api-operator/blob/e4bd10f78bada4cc8b36236e9b0b1c1332e5ef88/pkg/controller/machinehealthcheck/machinehealthcheck_controller.go#L764
	failedMachines, err := i.getNotRunningMachines()
	if err != nil {
		logging.Errorf("failed to retrieve machines: %w", err)
		i.notes.AppendWarning("failed to retrieve machines: %v", err)
	}

	if len(failedMachines) > 0 {
		machineRecommendations := i.InvestigateMachines(failedMachines)
		machineSummary := machineRecommendations.summarize()
		i.notes.AppendWarning(machineSummary)
		logging.Info("machine investigation summary: %s", machineSummary)
	} else {
		i.notes.AppendSuccess("no Failing machines found")
		logging.Info("no Failing machines found")
	}

	// Examine nodes
	notReadyNodes, err := i.getNotReadyNodes()
	if err != nil {
		logging.Error("failed to retrieve nodes: %w", err)
		i.notes.AppendWarning("failed to retrieve nodes: %v", err)
	}
	// Avoid re-investigating nodes whose machines were already investigated above: any node-level issue is most likely related to the underlying machine failing, and
	// providing duplicate/conflicting advice will only prove confusing to the responder
	notReadyNodes = i.excludeNodesFromMachineList(notReadyNodes, failedMachines)
	if len(notReadyNodes) > 0 {
		nodeRecommendations := i.InvestigateNodes(notReadyNodes)
		nodeSummary := nodeRecommendations.summarize()
		i.notes.AppendWarning(nodeSummary)
		logging.Info("node investigation summary: %s", nodeSummary)
	} else {
		i.notes.AppendSuccess("no additional affected nodes found")
		logging.Info("no additional affected nodes found")
	}

	return result, r.PdClient.EscalateIncidentWithNote(i.notes.String())
}

// InvestigateMachines accepts a list of failing machines and returns a categorized set of recommendations based on the failure state of
// each machine.
func (i *Investigation) InvestigateMachines(machines []machinev1beta1.Machine) machineRecommendations {
	recommendations := machineRecommendations{}
	for _, machine := range machines {
		fmt.Printf("machine: %#v\n", machine)
		// Confirm only worker machines are failing - if Red Hat-managed machines are affected, forward to Primary
		role, err := i.getMachineRole(machine)
		if err != nil {
			// Failing to determine whether a machine is Red Hat-managed warrants human investigation
			notes := fmt.Sprintf("manual investigation required to determine cause of machine misconfiguration: failed to determine machine role: %v", err)
			recommendations.addManualInvestigationRecommendation(machine, notes)
			continue
		}
		if role != machineRoleWorker {
			notes := fmt.Sprintf("manual investigation required for Red Hat-owned machine: non-worker machine in state %q due to %q", *machine.Status.ErrorReason, *machine.Status.ErrorMessage)
			recommendations.addManualInvestigationRecommendation(machine, notes)
			continue
		}

		switch *machine.Status.ErrorReason {
		case machinev1beta1.IPAddressInvalidReason:
			notes := fmt.Sprintf("invalid IP address: %q. Deleting machine may allow the cloud provider to assign a valid IP address", *machine.Status.ErrorMessage)
			recommendations.addDeletionRecommendation(machine, notes)
		case machinev1beta1.CreateMachineError:
			notes := fmt.Sprintf("machine failed to create: %q. Deleting machine may resolve any transient issues with the cloud provider", *machine.Status.ErrorMessage)
			recommendations.addDeletionRecommendation(machine, notes)
		case machinev1beta1.InvalidConfigurationMachineError:
			notes := fmt.Sprintf("manual investigation required because the machine configuration is invalid: %q. Checking splunk audit logs may indicate whether the customer has modified the machine or its machineset", *machine.Status.ErrorMessage)
			recommendations.addManualInvestigationRecommendation(machine, notes)
		case machinev1beta1.DeleteMachineError:
			notes := fmt.Sprintf("manual investigation required because the machine's node could not be gracefully terminated automatically: %q", *machine.Status.ErrorMessage)
			recommendations.addManualInvestigationRecommendation(machine, notes)
		case machinev1beta1.InsufficientResourcesMachineError:
			notes := fmt.Sprintf("a servicelog should be sent because there is insufficient quota to provision the machine: %q", *machine.Status.ErrorMessage)
			recommendations.addServiceLogRecommendation(machine, notes)
		default:
			notes := "manual investigation required to validate machine health: no .Status.ErrorReason found for machine"
			recommendations.addManualInvestigationRecommendation(machine, notes)
		}
	}
	return recommendations
}

// getMachineRole returns the role of the given machine, if present. If not found, an error is returned
func (i *Investigation) getMachineRole(machine machinev1beta1.Machine) (string, error) {
	role, found := machine.Labels[machineRoleLabel]
	if !found {
		return "", fmt.Errorf("expected label key %q not found", machineRoleLabel)
	}
	return role, nil
}

// getFailingMachines returns machines in the failing state, if any. If no machines are found, an empty slice and nil error are returned
func (i *Investigation) getNotRunningMachines() ([]machinev1beta1.Machine, error) {
	machines := &machinev1beta1.MachineList{}
	listOptions := &client.ListOptions{Namespace: machineNamespace}
	err := i.kclient.List(context.TODO(), machines, listOptions)
	if err != nil {
		return []machinev1beta1.Machine{}, fmt.Errorf("failed to retrieve machines from cluster: %w", err)
	}

	failed := []machinev1beta1.Machine{}
	for _, machine := range machines.Items {
		if machine.Status.Phase == nil {
			// Rare edge-case where a machine was created but not yet reconciled by the machine-api operator.
			// We should be able to safely skip evaluating this machine because it should not yet be provivisioned, and
			// therefore would have no impact on the machinehealthcheck's maxUnhealthy count
			logging.Info("skipped evaluating machine %q: .Status.Phase was nil", machine.Name)
			continue
		}
		if *machine.Status.Phase == machinev1beta1.PhaseFailed || machine.Status.ErrorReason != nil {
			failed = append(failed, machine)
		}
	}
	return failed, nil
}

// excludeNodesWithMachine returns all nodes that do not have a matching machine in the provided list
func (i *Investigation) excludeNodesFromMachineList(nodes []corev1.Node, machines []machinev1beta1.Machine) []corev1.Node {
	excludeNodes := i.getNodesForMachines(machines)
	n := []corev1.Node{}
	for _, node := range nodes {
		if !slices.Contains(excludeNodes, node.Name) {
			n = append(n, node)
		}
	}
	return n
}

// getMachineNodes returns the names of the nodes associated with the provided machines
func (i *Investigation) getNodesForMachines(machines []machinev1beta1.Machine) []string {
	nodes := []string{}
	for _, machine := range machines {
		if machine.Status.NodeRef != nil {
			nodes = append(nodes, machine.Status.NodeRef.Name)
		}
	}
	return nodes
}

// getNotReadyNodes returns any nodes whose ReadyCondition is false or missing
func (i *Investigation) getNotReadyNodes() ([]corev1.Node, error) {
	nodes := &corev1.NodeList{}
	err := i.kclient.List(context.TODO(), nodes)
	if err != nil {
		return []corev1.Node{}, fmt.Errorf("failed to retrieve nodes from cluster: %w", err)
	}

	notReady := []corev1.Node{}
	for _, node := range nodes.Items {
		readyCondition, found := i.findReadyCondition(node)
		// Interpret no Ready condition as "unknown", though in reality this shouldn't ever happen
		if !found || readyCondition.Status != corev1.ConditionTrue {
			notReady = append(notReady, node)
		}
	}
	return notReady, nil
}

// findReadyCondition searchs a node's .Status for the NodeReady condition, and returns it alongside a boolean value which
// indicates whether the condition was found or not
func (i *Investigation) findReadyCondition(node corev1.Node) (corev1.NodeCondition, bool) {
	for _, condition := range node.Status.Conditions {
		if condition.Type == corev1.NodeReady {
			return condition, true
		}
	}
	return corev1.NodeCondition{}, false
}

func (i *Investigation) InvestigateNodes(nodes []corev1.Node) nodeRecommendations {
	recommendations := nodeRecommendations{}
	for _, node := range nodes {
		roleLabel, found := i.getNodeRole(node)
		if !found {
			notes := fmt.Sprintf("manual investigation required: no role label containing %q found for node", nodeRoleLabelPrefix)
			recommendations.addManualInvestigationRecommendation(node, notes)
			continue
		} else if !strings.Contains(roleLabel, nodeRoleWorkerSuffix) {
			notes := "manual investigation required: non-worker node affected"
			recommendations.addManualInvestigationRecommendation(node, notes)
			continue
		}

		ready, found := i.findReadyCondition(node)
		if !found {
			notes := fmt.Sprintf("manual investigation required: found no 'Ready' .Status.Condition for the node")
			recommendations.addManualInvestigationRecommendation(node, notes)
			continue
		}

		lastCheckinElapsed := time.Since(ready.LastHeartbeatTime.Time)
		notes := fmt.Sprintf("node has been %q for %s", ready.Status, lastCheckinElapsed)
		recommendations.addManualInvestigationRecommendation(node, notes)
	}
	return recommendations
}

func (i *Investigation) getNodeRole(node corev1.Node) (string, bool) {
	for label := range node.Labels {
		if strings.Contains(label, nodeRoleLabelPrefix) {
			return label, true
		}
	}
	return "", false
}

func (i *Investigation) Name() string {
	return alertname
}

func (i *Investigation) Description() string {
	return fmt.Sprintf("Investigates '%s' alerts", alertname)
}

func (i *Investigation) IsExperimental() bool {
	return true
}

func (i *Investigation) ShouldInvestigateAlert(alert string) bool {
	return strings.Contains(alert, alertname)
}

type machineRecommendedAction string
const (
	// machineRecommendationDelete indicates that the machine(s) in question should be deleted so the machine-api can reprovision them
	machineRecommendationDelete      = "delete"
	// machineRecommendationInvestigate indicates that the machine(s) in question need manual investigation, because the error-state is too
	// dangerous or complex for this controller (ie - control-plane/infra machines affected)
	machineRecommendationInvestigate = "manually investigate"
	// machineRecommendationServiceLog indicates that the machine(s) in question need to be remediated by the customer, and SRE should notify them
	// of that fact via servicelog
	machineRecommendationServiceLog = "send a service log regarding"
)

// machineInvestigationResult holds the investigation
type machineInvestigationResult struct {
	// machineName indicates which machine was investigated
	machineName string
	// notes provides a high-level summary of the investigation results
	notes       string
}

func (s *machineInvestigationResult) String() string {
	msg := fmt.Sprintf("machine %q: %s", s.machineName, s.notes)
	return msg
}

// machineRecommendations categorizes each machine's individual investigation summary into a recommended course of action
type machineRecommendations map[machineRecommendedAction][]machineInvestigationResult

// addManualInvestigationRecommendation indicates that the machine should be manually investigated by the responder
func (r machineRecommendations) addManualInvestigationRecommendation(machine machinev1beta1.Machine, notes string) {
	result := machineInvestigationResult{
		machineName: machine.Name,
		notes: notes,
	}

	r[machineRecommendationInvestigate] = append(r[machineRecommendationInvestigate], result)
}

// addDeletionRecommendation indicates that the machine should be deleted
func (r machineRecommendations) addDeletionRecommendation(machine machinev1beta1.Machine, notes string) {
	result := machineInvestigationResult{
		machineName: machine.Name,
		notes: notes,
	}

	r[machineRecommendationDelete] = append(r[machineRecommendationDelete], result)
}

func (r machineRecommendations) addServiceLogRecommendation(machine machinev1beta1.Machine, notes string) {
	result := machineInvestigationResult{
		machineName: machine.Name,
		notes: notes,
	}
	r[machineRecommendationServiceLog] = append(r[machineRecommendationServiceLog], result)
}

// summarize prints the machine investigation recommendations into a human read-able format.
func (r machineRecommendations) summarize() string {
	msg := ""
	for action, investigations := range r {
		msg += fmt.Sprintf("%s the following machines:\n", action)

		switch action {
		case machineRecommendationDelete:
			// Consolidate all machine deletion requests into a single oc command for ease of use
			deleteCmd := fmt.Sprintf("oc delete machine -n %s", machineNamespace)
			for _, summary := range investigations {
				msg += fmt.Sprintf("- %q: %s\n", summary.machineName, summary.notes)
				deleteCmd += " " + summary.machineName
			}
			msg += fmt.Sprintf("to delete these machines, run:\n\n%s\n", deleteCmd)
		case machineRecommendationServiceLog:
			fallthrough
		case machineRecommendationInvestigate:
			for _, summary := range investigations {
				msg += fmt.Sprintf("- %q: %s\n", summary.machineName, summary.notes)
			}
		}
	}
	return msg
}

// nodeRecommendedAction enumerates the possible follow-up actions for node issues found by this investigation
type nodeRecommendedAction string
const (
	// nodeRecommendationDelete indicates that the node's underlying machine should be deleted so that the compute instance can be recreated
	nodeRecommendationDelete      = "delete"
	// nodeRecommendationInvestigate indicates that the node requires manual investigation
	nodeRecommendationInvestigate = "manually investigate"
)

// nodeInvestigationResult holds the investigation data for a failing node
type nodeInvestigationResult struct {
	// nodeName specifies the node the investigation revolved around
	nodeName string
	// notes contains a summary of the investigation, which will be relayed to the responder
	notes    string
}

// nodeRecommendations maps a recommended course of action for the responder to take to the list of node issues that fall under that category
type nodeRecommendations map[nodeRecommendedAction][]nodeInvestigationResult

// addManualInvestigationRecommendation indicates that the node should be manually investigated by the responder
func (r nodeRecommendations) addManualInvestigationRecommendation(node corev1.Node, notes string) {
	result := nodeInvestigationResult{
		nodeName: node.Name,
		notes: notes,
	}

	r[nodeRecommendationInvestigate] = append(r[nodeRecommendationInvestigate], result)
}

// addDeletionRecommendation indicates the node's underlying machine should be deleted
func (r nodeRecommendations) addDeletionRecommendation(node corev1.Node, notes string) {
	result := nodeInvestigationResult{
		nodeName: node.Name,
		notes: notes,
	}

	r[nodeRecommendationDelete] = append(r[nodeRecommendationDelete], result)
}

// summarize prints a recommendation map's summary
func (r nodeRecommendations) summarize() string {
	msg := ""
	for action, investigations := range r {
		msg += fmt.Sprintf("%s the following nodes:\n", action)
		for _, investigation := range investigations {
			msg += fmt.Sprintf("- %s\n", investigation.String())
		}
	}
	return msg
}

func (s *nodeInvestigationResult) String() string {
	msg := fmt.Sprintf("node %q: %s", s.nodeName, s.notes)
	return msg
}

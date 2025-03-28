/*
machinehealthcheckunterminatedshortcircuitsre defines the investigation logic for the MachineHealthCheckUnterminatedShortCircuitSRE alert
*/
package machinehealthcheckunterminatedshortcircuitsre

import (
	"context"
	"fmt"
	"strings"
	"time"

	//"time"

	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/investigation"
	k8sclient "github.com/openshift/configuration-anomaly-detection/pkg/k8s"
	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
	"github.com/openshift/configuration-anomaly-detection/pkg/notewriter"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	//metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	machinev1beta1 "github.com/openshift/api/machine/v1beta1"
)

const (
	alertname = "MachineHealthCheckUnterminatedShortCircuitSRE"
	// remediationName must match the name of this investigation's directory, so it can be looked up via the backplane-api
	remediationName = "machineHealthCheckUnterminatedShortCircuitSRE"

	machineNamespace  = "openshift-machine-api"
	machineRoleLabel  = "machine.openshift.io/cluster-api-machine-role"
	machineRoleWorker = "worker"
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

	recommendations := []summary{}

	// Examine machines - in addition to broken nodes, machines in the 'Failing' phase are counted against a machinehealthcheck's maxUnhealthy count:
	// https://github.com/openshift/machine-api-operator/blob/e4bd10f78bada4cc8b36236e9b0b1c1332e5ef88/pkg/controller/machinehealthcheck/machinehealthcheck_controller.go#L764
	failedMachines, err := i.getFailingMachines()
	if err != nil {
		logging.Errorf("failed to retrieve machines: %w", err)
		i.notes.AppendWarning("failed to retrieve machines: %v", err)
	}
	for _, machine := range failedMachines {
		// Confirm only worker machines are failing - if Red Hat-managed machines are affected, forward to Primary
		role, err := i.getMachineRole(machine)
		if err != nil {
			// Failing to determine whether a machine is Red Hat-managed warrants human investigation
			logging.Error("failed to determine machine role: %w", err)
			i.notes.AppendWarning("failed to determine machine role: %v\nEscalating to Primary", err)
			i.notes.AppendWarning("Primary: one or more machines was detected as missing the %q label, which can impact machine-api functionality. Please investigate the issue and take any appropriate action to address this.", machineRoleLabel)
			return result, r.PdClient.EscalateIncidentWithNote(i.notes.String())
		}
		if role != machineRoleWorker {
			logging.Error("found non-worker machine in %q state; escalating incident to Primary", err)
			i.notes.AppendWarning("found non-worker machine in %q state; escalating incident to Primary", *machine.Status.Phase)
			i.notes.AppendWarning("Primary: one or more Red Hat-managed machines was detected to have a .Status.Phase of %q, which can impact SLOs. Please investigate the issue and take any appropriate action to address this.", *machine.Status.Phase)
			return result, r.PdClient.EscalateIncidentWithNote(i.notes.String())
		}

		recommendation, err := i.machineRecommendation(machine)
		if err != nil {
			logging.Error("failed to make recommendation for node %q: %w", machine.Name, err)
			i.notes.AppendWarning("failed to make recommendation for node %q: %v", machine.Name, err)
		} else {
			recommendations = append(recommendations, recommendation)
		}
	}

	// Examine nodes
	notReadyNodes, err := i.getNotReadyNodes()
	if err != nil {
		logging.Error("failed to retrieve nodes: %w", err)
		i.notes.AppendWarning("failed to retrieve nodes: %v", err)
	}
	for _, node := range notReadyNodes {
		if i.nodeMachineRemediated(node, failedMachines) {
			// Don't bother double checking nodes whose machine we've already investigated
			continue
		}

		recommendation, err := i.nodeRecommendation(node)
		if err != nil {
			logging.Errorf("failed to make recommendation for node %q: %w", node.Name, err)
			i.notes.AppendWarning("failed to make recommendation for node %q: %v", node.Name, err)
		} else {
			recommendations = append(recommendations, recommendation)
		}
	}

	recommendationMsg := "the following action(s) are recommended:"
	for _, recommendation := range recommendations {
		recommendationMsg = fmt.Sprintf("%s\n  - %s", recommendationMsg, recommendation)
	}
	i.notes.AppendWarning(recommendationMsg)
	return result, r.PdClient.EscalateIncidentWithNote(i.notes.String())
}

func (i *Investigation) nodeMachineRemediated(node corev1.Node, remediatedMachines []machinev1beta1.Machine) bool {
	for _, machine := range remediatedMachines {
		if machine.Status.NodeRef != nil && machine.Status.NodeRef.Name == node.Name {
			return true
		}
	}
	return false
}

func (i *Investigation) getMachineRole(machine machinev1beta1.Machine) (string, error) {
	role, found := machine.Labels[machineRoleLabel]
	if !found {
		return "", fmt.Errorf("expected label '%s' not found", machineRoleLabel)
	}
	return role, nil
}

func (i *Investigation) getFailingMachines() ([]machinev1beta1.Machine, error) {
	machines := &machinev1beta1.MachineList{}
	listOptions := &client.ListOptions{Namespace: machineNamespace}
	err := i.kclient.List(context.TODO(), machines, listOptions)
	if err != nil {
		return []machinev1beta1.Machine{}, fmt.Errorf("failed to retrieve machines from cluster: %w", err)
	}

	failed := []machinev1beta1.Machine{}
	for _, machine := range machines.Items {
		if *machine.Status.Phase == machinev1beta1.PhaseFailed || machine.Status.ErrorReason != nil {
			failed = append(failed, machine)
		}
	}
	return failed, nil
}

// summary provides a simple structure to pair each problem found with a recommended solution
type summary struct {
	issue          string
	recommendation string
}

func (s summary) String() string {
	return fmt.Sprintf("issue: %s\nrecommendation: %sn\n", s.issue, s.recommendation)
}

// machineRecommendation determines the recommended course of action for a machine
func (i *Investigation) machineRecommendation(machine machinev1beta1.Machine) (summary, error) {
	summary := summary{}
	switch *machine.Status.ErrorReason {
	case machinev1beta1.IPAddressInvalidReason:
		summary.issue          = fmt.Sprintf("invalid IP address: %q", *machine.Status.ErrorMessage)
		summary.recommendation = fmt.Sprintf("deleting the machine may allow the cloud provider to assign a valid IP address:\n\n  oc delete machine -n %s %s", machine.Namespace, machine.Name)
	case machinev1beta1.CreateMachineError:
		summary.issue          = fmt.Sprintf("machine failed to create: %q", *machine.Status.ErrorMessage)
		summary.recommendation = fmt.Sprintf("deleteing the machine may bypass any transient issue with the cloud provider:\n\n  oc delete machine -n %s %s", machine.Namespace, machine.Name)
	case machinev1beta1.InvalidConfigurationMachineError:
		summary.issue          = fmt.Sprintf("machine configuration is invalid: %q", *machine.Status.ErrorMessage)
		summary.recommendation = fmt.Sprintf("check audit history for cluster to determine whether a third-party has modified the machine or its machineset")
	default:
		summary.issue          = "no .Status.ErrorReason found for machine"
		summary.recommendation = fmt.Sprintf("manual investigation for machine %s required", machine.Name)
	}
	return summary, nil
}

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

func (i *Investigation) findReadyCondition(node corev1.Node) (corev1.NodeCondition, bool) {
	for _, condition := range node.Status.Conditions {
		if condition.Type == corev1.NodeReady {
			return condition, true
		}
	}
	return corev1.NodeCondition{}, false
}

//func (i *Investigation) nodeRecommendation(node corev1.Node) (string, error) {
func (i *Investigation) nodeRecommendation(node corev1.Node) (summary, error) {
	// TODO
	summary := summary{}
	ready, found := i.findReadyCondition(node)
	if !found {
		summary.issue = "node has no Ready condition set"
		summary.recommendation = "manual investigation required to determine why node %q does not contain a Ready .Status.Condition"
		return summary, nil
	}

	lastCheckinElapsed := time.Since(ready.LastHeartbeatTime.Time)
	summary.issue = fmt.Sprintf("node %q has been %q for %s", node.Name, ready.Status, lastCheckinElapsed)
	summary.recommendation = "manual investigation required"
	return summary, nil
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

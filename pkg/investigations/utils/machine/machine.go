package machine

import (
	"context"
	"fmt"

	machinev1beta1 "github.com/openshift/api/machine/v1beta1"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/utils/node"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	MachineNamespace     = "openshift-machine-api"
	RoleLabelKey         = "machine.openshift.io/cluster-api-machine-role"
	WorkerRoleLabelValue = "worker"
)

// HealthcheckRemediationAllowed searches the status conditions for the machinehealthcheck object and determines if remediation is allowed
func HealthcheckRemediationAllowed(healthcheck machinev1beta1.MachineHealthCheck) bool {
	for _, condition := range healthcheck.Status.Conditions {
		if condition.Type == machinev1beta1.RemediationAllowedCondition && condition.Status == corev1.ConditionTrue {
			// Only rule out that the mhc is failing if we can both find the condition and determine its current status
			return true
		}
	}
	return false
}

// GetMachinesForMHC retrieves the machines managed by the given MachineHealthCheck object
func GetMachinesForMHC(ctx context.Context, k8scli client.Client, healthcheck machinev1beta1.MachineHealthCheck) ([]machinev1beta1.Machine, error) {
	machines := machinev1beta1.MachineList{}
	selector, err := metav1.LabelSelectorAsSelector(&healthcheck.Spec.Selector)
	if err != nil {
		return []machinev1beta1.Machine{}, fmt.Errorf("failed to convert machinehealthcheck %q .spec.selector: %w", healthcheck.Name, err)
	}
	err = k8scli.List(ctx, &machines, client.MatchingLabelsSelector{Selector: selector}, &client.ListOptions{Namespace: MachineNamespace})
	if err != nil {
		return []machinev1beta1.Machine{}, fmt.Errorf("failed to retrieve machines from machinehealthcheck %q: %w", healthcheck.Name, err)
	}
	return machines.Items, nil
}

// GetMachineRole returns the role of the given machine, if present. If not found, an error is returned
func GetRole(machine machinev1beta1.Machine) (string, error) {
	role, found := machine.Labels[RoleLabelKey]
	if !found {
		return "", fmt.Errorf("expected label key %q not found", RoleLabelKey)
	}
	return role, nil
}

// GetNodesForMachines retrieves the nodes for the given machines. Errors encountered are joined, but do not block the retrieval of other machines
func GetNodesForMachines(ctx context.Context, k8scli client.Client, machines []machinev1beta1.Machine) ([]corev1.Node, error) {
	// Retrieving all nodes initially & filtering out irrelevant objects results in fewer API calls
	nodes, err := node.GetAll(ctx, k8scli)
	if err != nil {
		return []corev1.Node{}, fmt.Errorf("failed to retrieve nodes: %w", err)
	}

	matches := []corev1.Node{}
	for _, machine := range machines {
		node, found := findMatchingNode(machine, nodes)
		if found {
			matches = append(matches, node)
		}
	}
	return matches, nil
}

// findMatchingNode retrieves the node owned by the provided machine, if one exists, along with a boolean indicating whether
// the search succeeded
func findMatchingNode(machine machinev1beta1.Machine, nodes []corev1.Node) (corev1.Node, bool) {
	if machine.Status.NodeRef == nil || machine.Status.NodeRef.Name == "" {
		return corev1.Node{}, false
	}
	for _, node := range nodes {
		if machine.Status.NodeRef.Name == node.Name {
			return node, true
		}
	}

	return corev1.Node{}, false
}

// GetNodeForMachine retrieves the node for the given machine. If the provided machine's .Status.NodeRef is empty,
// an error is returned
func GetNodeForMachine(ctx context.Context, k8scli client.Client, machine machinev1beta1.Machine) (corev1.Node, error) {
	if machine.Status.NodeRef == nil || machine.Status.NodeRef.Name == "" {
		return corev1.Node{}, fmt.Errorf("no .Status.NodeRef defined for machine %q", machine.Name)
	}
	node := &corev1.Node{}
	err := k8scli.Get(ctx, types.NamespacedName{Name: machine.Status.NodeRef.Name}, node)
	return *node, err
}

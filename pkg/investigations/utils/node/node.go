/*
node defines investigation utility logic related to node objects
*/
package node

import (
	"context"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	RoleLabelPrefix  = "node-role.kubernetes.io"
	WorkerRoleSuffix = "worker"
)

// FindNoScheduleTaint searches the node's taints to find one with effect: NoSchedule, if present.
//
// If none is present, an empty taint and 'false' are returned
func FindNoScheduleTaint(node corev1.Node) (corev1.Taint, bool) {
	for _, taint := range node.Spec.Taints {
		if taint.Effect == corev1.TaintEffectNoSchedule {
			return taint, true
		}
	}
	return corev1.Taint{}, false
}

// GetNodes retrieves all nodes present in the cluster
func GetAll(ctx context.Context, k8scli client.Client) ([]corev1.Node, error) {
	nodes := corev1.NodeList{}
	err := k8scli.List(ctx, &nodes)
	return nodes.Items, err
}

// FindReadyCondition searches a node's .Status for the NodeReady condition, and returns it alongside a boolean value which
// indicates whether the condition was found or not
func FindReadyCondition(node corev1.Node) (corev1.NodeCondition, bool) {
	for _, condition := range node.Status.Conditions {
		if condition.Type == corev1.NodeReady {
			return condition, true
		}
	}
	return corev1.NodeCondition{}, false
}

// GetNodeRole returns the role of the provided node
func GetRole(node corev1.Node) (string, bool) {
	for label := range node.Labels {
		if strings.Contains(label, RoleLabelPrefix) {
			return label, true
		}
	}
	return "", false
}

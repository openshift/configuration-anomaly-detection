// Package describenodes implements a CAD investigation that describes all nodes
// in a cluster, providing the full output of `oc describe nodes` including pod
// details.
package describenodes

import (
	"context"
	"fmt"
	"strings"

	"github.com/openshift/configuration-anomaly-detection/pkg/executor"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/investigation"
	k8sclient "github.com/openshift/configuration-anomaly-detection/pkg/k8s"
	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
	"github.com/openshift/configuration-anomaly-detection/pkg/notewriter"
	"github.com/openshift/configuration-anomaly-detection/pkg/types"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"
	"k8s.io/kubectl/pkg/describe"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type nodeDescriber interface {
	Describe(namespace, name string, settings describe.DescriberSettings) (string, error)
}

type Investigation struct {
	describer nodeDescriber
}

// Node selection is controlled via Params (passed via --params flags):
// flags (MASTER, INFRA, WORKER) can be combined. If no params are provided,
// all nodes are described.
func (i *Investigation) Run(rb investigation.ResourceBuilder) (investigation.InvestigationResult, error) {
	ctx := context.Background()
	result := investigation.InvestigationResult{}

	r, err := rb.WithCluster().WithK8sClient().Build()
	if err != nil {
		if msg, ok := investigation.ClusterAccessErrorMessage(err); ok {
			logging.Warnf("Cluster access error for describe-nodes: %v", err)
			result.Actions = []types.Action{
				executor.Note(msg),
			}
			return result, nil
		}
		return result, investigation.WrapInfrastructure(err, "failed to build resources for describe-nodes")
	}

	notes := notewriter.New(i.Name(), logging.RawLogger)

	if r.IsHCP {
		notes.AppendWarning("This is an HCP cluster - control plane nodes are not present on the service cluster")
	}

	nodes, err := selectNodes(ctx, r.K8sClient, r.Params, r.IsHCP, notes)
	if err != nil {
		return result, err
	}

	if len(nodes) == 0 {
		notes.AppendWarning("No nodes found matching the selection criteria")
		result.Actions = executor.NoteAndReportFrom(notes, r.Cluster.ID(), i.Name())
		return result, nil
	}

	describer := i.describer
	if describer == nil {
		describer, err = newNodeDescriber(r.K8sClient)
		if err != nil {
			return result, err
		}
	}

	var output strings.Builder
	var describeErrors []string

	for _, node := range nodes {
		desc, err := describer.Describe("", node.Name, describe.DescriberSettings{ShowEvents: true})
		if err != nil {
			describeErrors = append(describeErrors, fmt.Sprintf("failed to describe node %s: %v", node.Name, err))
			continue
		}
		output.WriteString(desc)
		output.WriteString("\n---\n\n")
	}

	describedCount := len(nodes) - len(describeErrors)
	notes.AppendSuccess("Described %d/%d nodes", describedCount, len(nodes))

	for _, errMsg := range describeErrors {
		notes.AppendWarning("%s", errMsg)
	}

	notes.AppendAutomation("Full node descriptions below:\n\n%s", output.String())

	result.Actions = executor.NoteAndReportFrom(notes, r.Cluster.ID(), i.Name())
	return result, nil
}

// Priority: NODES > SELECTOR > role flags (MASTER/INFRA/WORKER) > all nodes.
func selectNodes(ctx context.Context, k8sClient k8sclient.Client, params map[string]string, isHCP bool, notes *notewriter.NoteWriter) ([]corev1.Node, error) {
	if names := params["NODES"]; names != "" {
		return getNodesByName(ctx, k8sClient, strings.Split(names, ","))
	}

	if sel := params["SELECTOR"]; sel != "" {
		return listNodesWithSelector(ctx, k8sClient, sel)
	}

	const trueValue = "true"
	master := params["MASTER"] == trueValue
	infra := params["INFRA"] == trueValue
	worker := params["WORKER"] == trueValue

	if master || infra || worker {
		return getNodesByRole(ctx, k8sClient, master, infra, worker, isHCP, notes)
	}

	return listAllNodes(ctx, k8sClient)
}

func getNodesByName(ctx context.Context, k8sClient k8sclient.Client, names []string) ([]corev1.Node, error) {
	nodes := make([]corev1.Node, 0, len(names))
	for _, name := range names {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		node := corev1.Node{}
		if err := k8sClient.Get(ctx, client.ObjectKey{Name: name}, &node); err != nil {
			logging.Warnf("Node %q not found: %v", name, err)
			continue
		}
		nodes = append(nodes, node)
	}
	return nodes, nil
}

// listNodesWithSelector lists nodes matching a label selector string.
func listNodesWithSelector(ctx context.Context, k8sClient k8sclient.Client, selectorStr string) ([]corev1.Node, error) {
	selector, err := labels.Parse(selectorStr)
	if err != nil {
		return nil, investigation.WrapInfrastructure(err, fmt.Sprintf("invalid label selector %q", selectorStr))
	}

	nodeList := &corev1.NodeList{}
	if err := k8sClient.List(ctx, nodeList, client.MatchingLabelsSelector{Selector: selector}); err != nil {
		return nil, investigation.WrapInfrastructure(err, "failed to list nodes with selector")
	}
	return nodeList.Items, nil
}

// getNodesByRole lists nodes by role flags, roles are combianble.
func getNodesByRole(ctx context.Context, k8sClient k8sclient.Client, master, infra, worker, isHCP bool, notes *notewriter.NoteWriter) ([]corev1.Node, error) {
	seen := make(map[string]bool)
	var nodes []corev1.Node

	addNodes := func(newNodes []corev1.Node) {
		for _, n := range newNodes {
			if !seen[n.Name] {
				seen[n.Name] = true
				nodes = append(nodes, n)
			}
		}
	}

	if master {
		if isHCP {
			notes.AppendWarning("Skipping master node selection - control plane nodes are not present on HCP clusters")
		} else {
			masterNodes, err := listNodesWithSelector(ctx, k8sClient, "node-role.kubernetes.io/master")
			if err != nil {
				return nil, err
			}
			addNodes(masterNodes)
		}
	}

	if infra {
		infraNodes, err := listNodesWithSelector(ctx, k8sClient, "node-role.kubernetes.io=infra")
		if err != nil {
			return nil, err
		}
		addNodes(infraNodes)
	}

	if worker {
		workerNodes, err := listNodesWithSelector(ctx, k8sClient, "node-role.kubernetes.io!=infra,node-role.kubernetes.io/worker")
		if err != nil {
			return nil, err
		}
		addNodes(workerNodes)
	}

	return nodes, nil
}

func listAllNodes(ctx context.Context, k8sClient k8sclient.Client) ([]corev1.Node, error) {
	nodeList := &corev1.NodeList{}
	if err := k8sClient.List(ctx, nodeList, &client.ListOptions{}); err != nil {
		return nil, investigation.WrapInfrastructure(err, "failed to list nodes")
	}
	return nodeList.Items, nil
}

func newNodeDescriber(k8sClient k8sclient.Client) (nodeDescriber, error) {
	restConfig, err := k8sclient.GetRestConfig(k8sClient)
	if err != nil {
		return nil, investigation.WrapInfrastructure(err, "failed to get rest config from k8s client")
	}

	clientset, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		return nil, investigation.WrapInfrastructure(err, "failed to create kubernetes clientset")
	}

	return &describe.NodeDescriber{Interface: clientset}, nil
}

func (i *Investigation) Name() string {
	return "describenodes"
}

func (i *Investigation) AlertTitle() string {
	return ""
}

func (i *Investigation) Description() string {
	return "Describe all nodes in the cluster with full details including pod information"
}

func (i *Investigation) IsExperimental() bool {
	return true
}

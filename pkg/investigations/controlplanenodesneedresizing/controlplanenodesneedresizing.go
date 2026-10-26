// Package controlplanenodesneedresizing identifies which pods are running on
// control plane nodes when ControlPlaneNodesNeedResizingSRE fires.
// The resize itself stays manual.
package controlplanenodesneedresizing

import (
	"context"
	"fmt"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/openshift/configuration-anomaly-detection/pkg/executor"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/investigation"
	k8sclient "github.com/openshift/configuration-anomaly-detection/pkg/k8s"
	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
	"github.com/openshift/configuration-anomaly-detection/pkg/types"
)

const masterRoleLabel = "node-role.kubernetes.io/master"

// Investigation writes a PagerDuty note describing control-plane pod usage.
type Investigation struct{}

func (i *Investigation) Name() string {
	return "controlplanenodesneedresizing"
}

func (i *Investigation) Run(rb investigation.ResourceBuilder) (investigation.InvestigationResult, error) {
	ctx := context.Background()
	result := investigation.InvestigationResult{}

	r, err := rb.WithCluster().WithNotes().Build()
	if err != nil {
		if msg, ok := investigation.ClusterAccessErrorMessage(err); ok {
			result.Actions = []types.Action{executor.Escalate(msg)}
			return result, nil
		}
		return result, err
	}

	if r.IsHCP {
		r.Notes.AppendWarning("ControlPlaneNodesNeedResizingSRE applies to classic ROSA. This cluster is HCP, so no control-plane pod list was taken.")
		result.Actions = append(
			executor.NoteAndReportFrom(r.Notes, r.Cluster.ID(), i.Name()),
			executor.Escalate("HCP cluster - control plane resize alert is not handled here"),
		)
		return result, nil
	}

	r, err = rb.WithK8sClient().Build()
	if err != nil {
		if msg, ok := investigation.ClusterAccessErrorMessage(err); ok {
			result.Actions = []types.Action{executor.Escalate(msg)}
			return result, nil
		}
		return result, err
	}

	summary, err := summarizeMasterPods(ctx, r.K8sClient)
	if err != nil {
		if investigation.IsInfrastructureError(err) {
			return result, err
		}
		logging.Errorf("control plane pod summary failed: %v", err)
		r.Notes.AppendWarning("Failed to list control plane pods: %v", err)
		result.Actions = append(
			executor.NoteAndReportFrom(r.Notes, r.Cluster.ID(), i.Name()),
			executor.Escalate("Failed to list control plane pods - manual investigation required"),
		)
		return result, nil
	}

	r.Notes.AppendSuccess("%s", summary)
	r.Notes.AppendWarning("CAD does not resize control plane nodes. Use the resize SOP after reading this note.")
	result.Actions = append(
		executor.NoteAndReportFrom(r.Notes, r.Cluster.ID(), i.Name()),
		executor.Escalate("Control plane resize stays manual. Pod breakdown is in the note."),
	)
	return result, nil
}

type namespaceCount struct {
	namespace string
	count     int
	platform  bool
}

func summarizeMasterPods(ctx context.Context, k8sClient k8sclient.Client) (string, error) {
	var nodes corev1.NodeList
	if err := k8sClient.List(ctx, &nodes, client.HasLabels{masterRoleLabel}); err != nil {
		return "", investigation.WrapInfrastructure(err, "listing control plane nodes")
	}
	if len(nodes.Items) == 0 {
		return "No nodes with label node-role.kubernetes.io/master were found.", nil
	}

	counts := map[string]int{}
	var b strings.Builder
	fmt.Fprintf(&b, "Control plane nodes: %d\n", len(nodes.Items))
	for _, node := range nodes.Items {
		var pods corev1.PodList
		if err := k8sClient.List(ctx, &pods, client.MatchingFields{"spec.nodeName": node.Name}); err != nil {
			return "", investigation.WrapInfrastructure(err, "listing pods on "+node.Name)
		}
		fmt.Fprintf(&b, "\nNode %s (%d pods)\n", node.Name, len(pods.Items))
		for _, pod := range pods.Items {
			counts[pod.Namespace]++
		}
	}

	ranked := make([]namespaceCount, 0, len(counts))
	for ns, n := range counts {
		ranked = append(ranked, namespaceCount{namespace: ns, count: n, platform: isPlatformNamespace(ns)})
	}
	sort.Slice(ranked, func(i, j int) bool {
		if ranked[i].count == ranked[j].count {
			return ranked[i].namespace < ranked[j].namespace
		}
		return ranked[i].count > ranked[j].count
	})

	b.WriteString("\nNamespaces on control plane nodes:\n")
	for _, item := range ranked {
		kind := "customer"
		if item.platform {
			kind = "platform"
		}
		fmt.Fprintf(&b, "- %s: %d pods (%s)\n", item.namespace, item.count, kind)
	}
	return b.String(), nil
}

func isPlatformNamespace(ns string) bool {
	return strings.HasPrefix(ns, "openshift-") || strings.HasPrefix(ns, "kube-")
}

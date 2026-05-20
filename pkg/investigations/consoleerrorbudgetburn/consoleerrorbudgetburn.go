// Package consoleerrorbudgetburn investigates console-ErrorBudgetBurn alerts
// by checking ingress configuration, DNS, router/console pod health, and node conditions.
package consoleerrorbudgetburn

import (
	"context"
	"fmt"
	"net"
	"strings"

	operatorv1 "github.com/openshift/api/operator/v1"

	"github.com/openshift/configuration-anomaly-detection/pkg/executor"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/investigation"
	nodeutils "github.com/openshift/configuration-anomaly-detection/pkg/investigations/utils/node"
	k8sclient "github.com/openshift/configuration-anomaly-detection/pkg/k8s"
	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
	"github.com/openshift/configuration-anomaly-detection/pkg/notewriter"
	"github.com/openshift/configuration-anomaly-detection/pkg/ocm"
	"github.com/openshift/configuration-anomaly-detection/pkg/types"

	corev1 "k8s.io/api/core/v1"
	ktypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type consoleServiceChecker interface {
	checkConsoleEndpoint(ctx context.Context, k8sClient k8sclient.Client, restConfig *rest.Config) (string, error)
}

type Investigation struct {
	consoleChecker consoleServiceChecker
}

func (i *Investigation) Run(rb investigation.ResourceBuilder) (investigation.InvestigationResult, error) {
	if i.consoleChecker == nil {
		i.consoleChecker = &defaultConsoleServiceChecker{}
	}

	ctx := context.Background()
	result := investigation.InvestigationResult{}

	r, err := rb.WithCluster().WithK8sClient().Build()
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

	notes := notewriter.New(i.Name(), logging.RawLogger)

	// Check allowedSourceRanges on the default IngressController.
	// Applies to: classic
	if !r.IsHCP {
		if i.checkAllowedSourceRanges(ctx, r, notes) {
			// Definitive root cause found;send SL, silence, return early.
			machineCIDR := r.Cluster.Network().MachineCIDR()
			sl := newAllowedSourceRangesSL(machineCIDR)
			notes.AppendAutomation("Sent AllowedSourceRanges service log and silenced alert")
			result.Actions = append(
				executor.NoteAndReportFrom(notes, r.Cluster.ID(), i.Name()),
				executor.NewServiceLogAction(sl.Severity, sl.Summary).
					WithDescription(sl.Description).
					WithServiceName(sl.ServiceName).
					Build(),
				executor.Silence("AllowedSourceRanges misconfiguration on default IngressController"),
			)
			return result, nil
		}
	}

	// Check for customer-configured upstream DNS resolvers.
	// Applies to: Classic + HCP.
	i.checkUpstreamDNS(ctx, r.K8sClient, notes)

	// Check router pod health in openshift-ingress.
	// Applies to: Classic + HCP.
	i.checkPodHealth(ctx, r.K8sClient, "openshift-ingress", "Router", notes)

	// Check console service reachability from within the cluster.
	// Applies to: Classic + HCP.
	i.checkConsoleService(ctx, r, notes)

	// Check console pod health in openshift-console.
	// Applies to: Classic + HCP.
	i.checkPodHealth(ctx, r.K8sClient, "openshift-console", "Console", notes)

	// Check health of nodes running console pods.
	// Applies to: Classic + HCP.
	i.checkNodeHealth(ctx, r.K8sClient, notes)

	// No automated root cause identified — escalate for manual investigation.
	result.Actions = append(
		executor.NoteAndReportFrom(notes, r.Cluster.ID(), i.Name()),
		executor.Escalate("No automated root cause identified — manual investigation required"),
	)
	return result, nil
}

// checkAllowedSourceRanges checks whether the default IngressController's allowedSourceRanges
// includes the cluster's machine CIDR.
//
// Return true if a misconfig was detected.
func (i *Investigation) checkAllowedSourceRanges(ctx context.Context, r *investigation.Resources, notes *notewriter.NoteWriter) bool {
	machineCIDR := r.Cluster.Network().MachineCIDR()
	if machineCIDR == "" {
		notes.AppendWarning("AllowedSourceRanges: unable to determine machine CIDR from cluster info")
		return false
	}

	machineIP, machineNet, err := net.ParseCIDR(machineCIDR)
	if err != nil {
		notes.AppendWarning("AllowedSourceRanges: failed to parse machine CIDR %q - %v", machineCIDR, err)
		return false
	}

	ic := &operatorv1.IngressController{}
	if err := r.K8sClient.Get(ctx, ktypes.NamespacedName{Namespace: "openshift-ingress-operator", Name: "default"}, ic); err != nil {
		notes.AppendWarning("AllowedSourceRanges: failed to get default IngressController - %v", err)
		return false
	}

	if ic.Spec.EndpointPublishingStrategy == nil || ic.Spec.EndpointPublishingStrategy.LoadBalancer == nil || len(ic.Spec.EndpointPublishingStrategy.LoadBalancer.AllowedSourceRanges) == 0 {
		notes.AppendSuccess("AllowedSourceRanges: not configured on default IngressController")
		return false
	}

	ranges := ic.Spec.EndpointPublishingStrategy.LoadBalancer.AllowedSourceRanges
	for _, r := range ranges {
		if cidrContains(string(r), machineIP, machineNet) {
			notes.AppendSuccess("AllowedSourceRanges: machine CIDR %s is covered by allowedSourceRanges on default IngressController", machineCIDR)
			return false
		}
	}

	notes.AppendWarning("AllowedSourceRanges: machine CIDR %s is NOT included in allowedSourceRanges on default IngressController (ranges: %v)", machineCIDR, ranges)
	return true
}

// cidrContains checks whether allowedCIDR is contained in (or equal to) machine CIDR.
// This matches the semantics of the ops-sop check-allowed-source-ranges.py cidr_fit function.
func cidrContains(allowedCIDR string, machineIP net.IP, machineNet *net.IPNet) bool {
	_, allowedNet, err := net.ParseCIDR(allowedCIDR)
	if err != nil {
		return false
	}

	allowedOnes, _ := allowedNet.Mask.Size()
	machineOnes, _ := machineNet.Mask.Size()

	return allowedOnes <= machineOnes && allowedNet.Contains(machineIP)
}

// newAllowedSourceRangesSL returns the service log for an allowedSourceRanges misconfiguration.
// Content matches the managed-notifications AllowedSourceRanges.json template.
func newAllowedSourceRangesSL(machineCIDR string) *ocm.ServiceLog {
	return &ocm.ServiceLog{
		Severity:     "Critical",
		ServiceName:  "SREManualAction",
		Summary:      "Action required: Incorrect Default IngressController Configuration",
		Description:  fmt.Sprintf("Your cluster requires you to take action. Your default ingresscontroller is misconfigured, generating alerts for Red Hat SRE and degrading cluster health. The Machine CIDR for the cluster, '%s', needs to be added to the allowlist.", machineCIDR),
		InternalOnly: false,
	}
}

// checkUpstreamDNS checks whether the cluster has customer-configured upstream DNS resolvers.
// If upstreamResolvers with type "Network" are found on dns.operator.openshift.io/default,
// this flags them as a potential cause of probe DNS resolution failures.
//
// Informational-only check.
func (i *Investigation) checkUpstreamDNS(ctx context.Context, k8sClient k8sclient.Client, notes *notewriter.NoteWriter) {
	dns := &operatorv1.DNS{}
	if err := k8sClient.Get(ctx, ktypes.NamespacedName{Name: "default"}, dns); err != nil {
		notes.AppendWarning("DNS: failed to get dns.operator.openshift.io/default - %v", err)
		return
	}

	var customUpstreams []string
	for _, u := range dns.Spec.UpstreamResolvers.Upstreams {
		if u.Type == operatorv1.NetworkResolverType {
			customUpstreams = append(customUpstreams, fmt.Sprintf("%s:%d", u.Address, u.Port))
		}
	}

	if len(customUpstreams) == 0 {
		notes.AppendSuccess("DNS: no custom upstream resolvers configured")
		return
	}

	notes.AppendWarning("DNS: customer-configured upstream resolvers detected (may prevent *.apps domain resolution): %s", strings.Join(customUpstreams, ", "))
}

// checkPodHealth checks the health of pods in the given namespace, reporting any
// failed, pending, crashlooping, or not-ready pods as well as warning events.
//
// Informational-only check.
func (i *Investigation) checkPodHealth(ctx context.Context, k8sClient k8sclient.Client, namespace, label string, notes *notewriter.NoteWriter) {
	const restartThreshold int32 = 3

	podList := &corev1.PodList{}
	if err := k8sClient.List(ctx, podList, client.InNamespace(namespace)); err != nil {
		notes.AppendWarning("%s: failed to list pods in %s - %v", label, namespace, err)
		return
	}

	if len(podList.Items) == 0 {
		notes.AppendWarning("%s: no pods found in %s", label, namespace)
		return
	}

	type podIssue struct {
		name   string
		reason string
	}

	var issues []podIssue
	for _, pod := range podList.Items {
		if pod.Status.Phase == corev1.PodSucceeded {
			continue
		}
		if pod.Status.Phase == corev1.PodFailed {
			reason := pod.Status.Reason
			if reason == "" {
				reason = "Failed"
			}
			issues = append(issues, podIssue{name: pod.Name, reason: reason})
			continue
		}
		if pod.Status.Phase == corev1.PodPending {
			issues = append(issues, podIssue{name: pod.Name, reason: "Pending"})
			continue
		}
		for _, cs := range pod.Status.ContainerStatuses {
			if cs.RestartCount > restartThreshold {
				issues = append(issues, podIssue{
					name:   pod.Name,
					reason: fmt.Sprintf("container %s has %d restarts", cs.Name, cs.RestartCount),
				})
			}
			if cs.State.Waiting != nil && (cs.State.Waiting.Reason == "CrashLoopBackOff" ||
				cs.State.Waiting.Reason == "Error" ||
				cs.State.Waiting.Reason == "ImagePullBackOff" ||
				cs.State.Waiting.Reason == "ErrImagePull") {
				issues = append(issues, podIssue{
					name:   pod.Name,
					reason: fmt.Sprintf("container %s: %s", cs.Name, cs.State.Waiting.Reason),
				})
			}
			if !cs.Ready && pod.Status.Phase == corev1.PodRunning {
				issues = append(issues, podIssue{
					name:   pod.Name,
					reason: fmt.Sprintf("container %s not ready", cs.Name),
				})
			}
		}
	}

	// Check for warning events in the namespace.
	eventList := &corev1.EventList{}
	var warningEvents []string
	if err := k8sClient.List(ctx, eventList, client.InNamespace(namespace)); err != nil {
		notes.AppendWarning("%s: failed to list events in %s - %v", label, namespace, err)
	} else {
		for _, event := range eventList.Items {
			if event.Type != corev1.EventTypeNormal {
				msg := event.Message
				if len(msg) > 120 {
					msg = msg[:120] + "..."
				}
				countStr := ""
				if event.Count > 1 {
					countStr = fmt.Sprintf(" (x%d)", event.Count)
				}
				warningEvents = append(warningEvents, fmt.Sprintf("  %s/%s: %s%s - %s", event.InvolvedObject.Kind, event.InvolvedObject.Name, event.Reason, countStr, msg))
			}
		}
	}

	if len(issues) == 0 && len(warningEvents) == 0 {
		notes.AppendSuccess("%s: all %d pod(s) in %s are running and ready", label, len(podList.Items), namespace)
		return
	}

	var sb strings.Builder
	if len(issues) > 0 {
		sb.WriteString(fmt.Sprintf("%d pod issue(s):\n", len(issues)))
		for _, issue := range issues {
			sb.WriteString(fmt.Sprintf("  %s: %s\n", issue.name, issue.reason))
		}
	}
	if len(warningEvents) > 0 {
		sb.WriteString(fmt.Sprintf("%d warning event(s):\n", len(warningEvents)))
		for _, e := range warningEvents {
			sb.WriteString(e + "\n")
		}
	}
	notes.AppendWarning("%s: %s", label, sb.String())
}

// checkConsoleService tests whether the console service is reachable from within the cluster
// by exec'ing into a CMO pod and curling the console ClusterIP service.
//
// informational-only check.
func (i *Investigation) checkConsoleService(ctx context.Context, r *investigation.Resources, notes *notewriter.NoteWriter) {
	restConfig, err := getRestConfig(r)
	if err != nil {
		notes.AppendWarning("Console Service: unable to get REST config - %v", err)
		return
	}

	output, err := i.consoleChecker.checkConsoleEndpoint(ctx, r.K8sClient, restConfig)
	if err != nil {
		notes.AppendWarning("Console Service: unable to reach console service - %v", err)
		return
	}

	if output == "200" {
		notes.AppendSuccess("Console Service: console is responding (HTTP 200) from within the cluster")
	} else {
		notes.AppendWarning("Console Service: console returned HTTP %s from within the cluster", output)
	}
}

// defaultConsoleServiceChecker implements consoleServiceChecker by exec'ing curl
// into a cluster-monitoring-operator pod in openshift-monitoring.
type defaultConsoleServiceChecker struct{}

func (d *defaultConsoleServiceChecker) checkConsoleEndpoint(ctx context.Context, k8sClient k8sclient.Client, restConfig *rest.Config) (string, error) {
	podList := &corev1.PodList{}
	if err := k8sClient.List(
		ctx, podList,
		client.InNamespace("openshift-monitoring"),
		client.MatchingLabels{"app.kubernetes.io/name": "cluster-monitoring-operator"},
	); err != nil {
		return "", fmt.Errorf("failed to list cluster-monitoring-operator pods: %w", err)
	}

	var cmoPod *corev1.Pod
	for idx := range podList.Items {
		if podList.Items[idx].Status.Phase == corev1.PodRunning {
			cmoPod = &podList.Items[idx]
			break
		}
	}
	if cmoPod == nil {
		return "", fmt.Errorf("no running cluster-monitoring-operator pod found in openshift-monitoring")
	}

	output, err := k8sclient.ExecInPod(ctx, restConfig, cmoPod, "cluster-monitoring-operator", []string{
		"curl", "-sk", "-o", "/dev/null", "-w", "%{http_code}",
		"https://console.openshift-console.svc.cluster.local",
	})
	if err != nil {
		return output, fmt.Errorf("exec failed: %w", err)
	}
	return strings.TrimSpace(output), nil
}

// checkNodeHealth checks the health of nodes that run console pods.
// It looks for NotReady, MemoryPressure, DiskPressure, PIDPressure conditions
// and Unschedulable status.
//
// Informational-only check.
func (i *Investigation) checkNodeHealth(ctx context.Context, k8sClient k8sclient.Client, notes *notewriter.NoteWriter) {
	// find which nodes run console pods
	podList := &corev1.PodList{}
	if err := k8sClient.List(ctx, podList, client.InNamespace("openshift-console")); err != nil {
		notes.AppendWarning("Node Health: failed to list console pods - %v", err)
		return
	}

	nodeNames := make(map[string]struct{})
	for _, pod := range podList.Items {
		if pod.Spec.NodeName != "" {
			nodeNames[pod.Spec.NodeName] = struct{}{}
		}
	}

	if len(nodeNames) == 0 {
		notes.AppendWarning("Node Health: no console pods found to determine nodes")
		return
	}

	var issues []string
	nodeCount := 0
	for nodeName := range nodeNames {
		node := &corev1.Node{}
		if err := k8sClient.Get(ctx, ktypes.NamespacedName{Name: nodeName}, node); err != nil {
			issues = append(issues, fmt.Sprintf("%s: failed to get node - %v", nodeName, err))
			continue
		}
		nodeCount++

		// Check NodeReady condition using the utils helper.
		if readyCond, found := nodeutils.FindReadyCondition(*node); found {
			if readyCond.Status != corev1.ConditionTrue {
				issues = append(issues, fmt.Sprintf("%s: NotReady (status: %s, reason: %s)", nodeName, readyCond.Status, readyCond.Reason))
			}
		} else {
			issues = append(issues, fmt.Sprintf("%s: NodeReady condition not found", nodeName))
		}

		for _, cond := range node.Status.Conditions {
			switch cond.Type {
			case corev1.NodeMemoryPressure:
				if cond.Status == corev1.ConditionTrue {
					issues = append(issues, fmt.Sprintf("%s: MemoryPressure", nodeName))
				}
			case corev1.NodeDiskPressure:
				if cond.Status == corev1.ConditionTrue {
					issues = append(issues, fmt.Sprintf("%s: DiskPressure", nodeName))
				}
			case corev1.NodePIDPressure:
				if cond.Status == corev1.ConditionTrue {
					issues = append(issues, fmt.Sprintf("%s: PIDPressure", nodeName))
				}
			}
		}

		if node.Spec.Unschedulable {
			issues = append(issues, fmt.Sprintf("%s: Unschedulable (cordoned)", nodeName))
		}
	}

	if len(issues) == 0 {
		notes.AppendSuccess("Node Health: all %d node(s) running console pods are healthy", nodeCount)
	} else {
		notes.AppendWarning("Node Health: %d issue(s) on nodes running console pods:\n  %s", len(issues), strings.Join(issues, "\n  "))
	}
}

// getRestConfig extracts the *rest.Config from the investigation resources.
func getRestConfig(r *investigation.Resources) (*rest.Config, error) {
	if r.RestConfig != nil {
		return &r.RestConfig.Config, nil
	}
	return k8sclient.GetRestConfig(r.K8sClient)
}

func (i *Investigation) Name() string {
	return "consoleerrorbudgetburn"
}

func (i *Investigation) AlertTitle() string {
	return "console-errorbudgetburn"
}

func (i *Investigation) Description() string {
	return "Investigation to analyze a console-ErrorBudgetBurn alert"
}

func (i *Investigation) IsExperimental() bool {
	return true
}

// Package consoleerrorbudgetburn investigates console-ErrorBudgetBurn alerts
// by checking ingress configuration, DNS, router/console pod health, and node conditions.
package consoleerrorbudgetburn

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"

	operatorv1 "github.com/openshift/api/operator/v1"

	"github.com/openshift/configuration-anomaly-detection/pkg/aws"
	"github.com/openshift/configuration-anomaly-detection/pkg/executor"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/investigation"
	nodeutils "github.com/openshift/configuration-anomaly-detection/pkg/investigations/utils/node"
	k8sclient "github.com/openshift/configuration-anomaly-detection/pkg/k8s"
	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
	"github.com/openshift/configuration-anomaly-detection/pkg/networkverifier"
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

type blackboxProber interface {
	runProbe(ctx context.Context, k8sClient k8sclient.Client, restConfig *rest.Config, consoleURL string) (string, error)
}

type egressVerifier interface {
	run(r *investigation.Resources) (networkverifier.VerifierResult, string, error)
}

type defaultEgressVerifier struct{}

func (d *defaultEgressVerifier) run(r *investigation.Resources) (networkverifier.VerifierResult, string, error) {
	return networkverifier.Run(r.Cluster, r.ClusterDeployment, r.AwsClient)
}

type Investigation struct {
	consoleChecker consoleServiceChecker
	blackboxProber blackboxProber
	egressVerifier egressVerifier
}

func (i *Investigation) Run(rb investigation.ResourceBuilder) (investigation.InvestigationResult, error) {
	if i.consoleChecker == nil {
		i.consoleChecker = &defaultConsoleServiceChecker{}
	}
	if i.blackboxProber == nil {
		i.blackboxProber = &defaultBlackboxProber{}
	}
	if i.egressVerifier == nil {
		i.egressVerifier = &defaultEgressVerifier{}
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

	// Check blackbox probe
	// Applies to: Classic + HCP.
	i.checkBlackboxProbe(ctx, r, notes)

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

	// AWS-specific checks.
	// Applies to: AWS clusters only.
	if r.Cluster.CloudProvider() != nil && r.Cluster.CloudProvider().ID() == "aws" {
		r, err = rb.WithAwsClient().Build()
		if err != nil {
			notes.AppendWarning("AWS: unable to initialize AWS client — %v", err)
		}
	}

	if r.AwsClient != nil {
		// Route53 DNS check (classic + HCP, early return on missing records).
		if i.checkRoute53DNS(ctx, r, notes) {
			clusterDomain := r.Cluster.DomainPrefix() + "." + r.Cluster.DNS().BaseDomain()
			sl := newNetworkMisconfigurationSL(
				fmt.Sprintf("The *.apps.%s DNS record is missing from Route53 hosted zones", clusterDomain),
			)
			notes.AppendAutomation("Sent NetworkMisconfiguration service log and silenced alert")
			result.Actions = append(
				executor.NoteAndReportFrom(notes, r.Cluster.ID(), i.Name()),
				executor.NewServiceLogAction(sl.Severity, sl.Summary).
					WithDescription(sl.Description).
					WithServiceName(sl.ServiceName).
					Build(),
				executor.Silence("Missing *.apps DNS records in Route53"),
			)
			return result, nil
		}
		// DHCP option set check (classic only).
		if !r.IsHCP {
			i.checkDHCPOptions(ctx, r, notes)
		}
		// Load balancer health check (classic only).
		if !r.IsHCP {
			i.checkLoadBalancerHealth(ctx, r, notes)
		}
		// VPC egress check (classic, public only).
		// PrivateLink clusters are excluded because the network verifier's probe
		// methodology (launching an instance to test internet-bound egress) does not
		// apply to PrivateLink clusters, which use AWS PrivateLink endpoints instead
		// of public internet egress.
		if !r.IsHCP && r.Cluster.AWS() != nil && !r.Cluster.AWS().PrivateLink() {
			r, err = rb.WithClusterDeployment().Build()
			if err != nil {
				notes.AppendWarning("VPC Egress: unable to fetch ClusterDeployment — %v", err)
			} else {
				i.checkVPCEgress(r, notes)
			}
		}
	}

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

// newNetworkMisconfigurationSL returns the service log for a network misconfiguration
func newNetworkMisconfigurationSL(change string) *ocm.ServiceLog {
	return &ocm.ServiceLog{
		Severity:     "Critical",
		ServiceName:  "SREManualAction",
		Summary:      "Action required: Network misconfiguration",
		Description:  fmt.Sprintf("Your cluster requires you to take action. SRE has observed that there have been changes made to network configuration which impact normal working of the cluster: %s.", change),
		InternalOnly: false,
	}
}

// checkRoute53DNS verifies that *.apps DNS records exist in the cluster's Route53 hosted zones.
// For non-PrivateLink, check both private and public hosted zones.
// For PrivateLink clusters, only the private hosted zone is checked.
func (i *Investigation) checkRoute53DNS(ctx context.Context, r *investigation.Resources, notes *notewriter.NoteWriter) bool {
	baseDomain := r.Cluster.DNS().BaseDomain()
	domainPrefix := r.Cluster.DomainPrefix()
	if baseDomain == "" || domainPrefix == "" {
		notes.AppendWarning("Route53: unable to determine cluster domain (missing base domain or domain prefix)")
		return false
	}

	clusterDomain := domainPrefix + "." + baseDomain
	appsRecordName := "\\052.apps." + clusterDomain + "."

	privateZoneID, err := r.AwsClient.FindHostedZone(clusterDomain, true)
	if err != nil {
		notes.AppendWarning("Route53: error looking up private hosted zone for %s — %v", clusterDomain, err)
		return false
	}

	var missingPrivate, missingPublic bool

	if privateZoneID == "" {
		notes.AppendWarning("Route53: no private hosted zone found for %s", clusterDomain)
		return false
	}

	hasPrivateRecord, err := r.AwsClient.HasResourceRecordSet(privateZoneID, appsRecordName, "A")
	if err != nil {
		notes.AppendWarning("Route53: error checking *.apps record in private zone for %s — %v", clusterDomain, err)
		return false
	}
	missingPrivate = !hasPrivateRecord

	isPrivateLink := r.Cluster.AWS() != nil && r.Cluster.AWS().PrivateLink()
	if !isPrivateLink {
		publicZoneID, err := r.AwsClient.FindHostedZone(baseDomain, false)
		if err != nil {
			notes.AppendWarning("Route53: error looking up public hosted zone for %s — %v", baseDomain, err)
			return false
		}
		if publicZoneID == "" {
			notes.AppendWarning("Route53: no public hosted zone found for %s", baseDomain)
			return false
		}

		hasPublicRecord, err := r.AwsClient.HasResourceRecordSet(publicZoneID, appsRecordName, "A")
		if err != nil {
			notes.AppendWarning("Route53: error checking *.apps record in public zone for %s — %v", clusterDomain, err)
			return false
		}
		missingPublic = !hasPublicRecord
	}

	if missingPrivate && missingPublic {
		notes.AppendWarning("Route53: *.apps DNS record missing from BOTH private and public hosted zones for %s", clusterDomain)
		return true
	}
	if missingPrivate {
		notes.AppendWarning("Route53: *.apps DNS record missing from private hosted zone for %s", clusterDomain)
		return true
	}
	if missingPublic {
		notes.AppendWarning("Route53: *.apps DNS record missing from public hosted zone for %s", clusterDomain)
		return true
	}

	if isPrivateLink {
		notes.AppendSuccess("Route53: *.apps DNS record verified in private hosted zone for %s", clusterDomain)
	} else {
		notes.AppendSuccess("Route53: *.apps DNS records verified in private and public hosted zones for %s", clusterDomain)
	}
	return false
}

// checkDHCPOptions checks whether the VPC's DHCP option set includes AmazonProvidedDNS.
//
// Classic only, informational check.
func (i *Investigation) checkDHCPOptions(ctx context.Context, r *investigation.Resources, notes *notewriter.NoteWriter) {
	infraID := r.Cluster.InfraID()
	if infraID == "" {
		notes.AppendWarning("DHCP: unable to determine cluster infrastructure ID")
		return
	}

	servers, err := r.AwsClient.GetVpcDhcpConfiguration(infraID)
	if err != nil {
		notes.AppendWarning("DHCP: unable to check VPC DHCP options — %v", err)
		return
	}

	if len(servers) == 0 {
		notes.AppendSuccess("DHCP: VPC DHCP option set uses AWS default DNS (AmazonProvidedDNS)")
		return
	}

	hasAmazonDNS := false
	for _, s := range servers {
		if s == "AmazonProvidedDNS" {
			hasAmazonDNS = true
			break
		}
	}

	if !hasAmazonDNS {
		notes.AppendWarning("DHCP: VPC DHCP option set uses custom DNS servers %v instead of AmazonProvidedDNS — this may prevent in-VPC DNS resolution", servers)
		return
	}

	if len(servers) > 1 {
		notes.AppendSuccess("DHCP: VPC DHCP option set includes AmazonProvidedDNS alongside custom servers %v", servers)
		return
	}

	notes.AppendSuccess("DHCP: VPC DHCP option set uses AmazonProvidedDNS")
}

// determineLBType extracts the AWS load balancer type from the IngressController.
// Returns "NLB" or "Classic". Defaults to "Classic" if the provider parameters are not set
func determineLBType(ic *operatorv1.IngressController) string {
	// check Spec first, fall back to status
	for _, eps := range []*operatorv1.EndpointPublishingStrategy{
		ic.Spec.EndpointPublishingStrategy,
		ic.Status.EndpointPublishingStrategy,
	} {
		if eps != nil &&
			eps.LoadBalancer != nil &&
			eps.LoadBalancer.ProviderParameters != nil &&
			eps.LoadBalancer.ProviderParameters.AWS != nil {
			if eps.LoadBalancer.ProviderParameters.AWS.Type == operatorv1.AWSNetworkLoadBalancer {
				return "NLB"
			}
			return "Classic"
		}
	}
	return "Classic"
}

// checkLoadBalancerHealth checks the health of the cluster's ingress load balancer targets.
// Identifies the LB type (CLB vs NLB) from the IngressController, reads the router-default
// Service to find the LB hostname, then queries AWS for target health status.
//
// Classic only (not applicable to HCP). Informational-only check.
func (i *Investigation) checkLoadBalancerHealth(ctx context.Context, r *investigation.Resources, notes *notewriter.NoteWriter) {
	// Get IngressController to determine LB type.
	ic := &operatorv1.IngressController{}
	if err := r.K8sClient.Get(ctx, ktypes.NamespacedName{
		Namespace: "openshift-ingress-operator",
		Name:      "default",
	}, ic); err != nil {
		notes.AppendWarning("LB Health: failed to get default IngressController — %v", err)
		return
	}
	lbType := determineLBType(ic)

	svc := &corev1.Service{}
	if err := r.K8sClient.Get(ctx, ktypes.NamespacedName{
		Namespace: "openshift-ingress",
		Name:      "router-default",
	}, svc); err != nil {
		notes.AppendWarning("LB Health: failed to get router-default Service — %v", err)
		return
	}
	if len(svc.Status.LoadBalancer.Ingress) == 0 || svc.Status.LoadBalancer.Ingress[0].Hostname == "" {
		notes.AppendWarning("LB Health: router-default Service has no LoadBalancer hostname assigned")
		return
	}
	hostname := svc.Status.LoadBalancer.Ingress[0].Hostname

	switch lbType {
	case "NLB":
		i.checkNLBHealth(r, hostname, notes)
	default:
		i.checkCLBHealth(r, hostname, notes)
	}
}

// checkNLBHealth finds an NLB by DNS name and reports target health.
func (i *Investigation) checkNLBHealth(r *investigation.Resources, hostname string, notes *notewriter.NoteWriter) {
	arn, name, err := r.AwsClient.FindNLBByDNSName(hostname)
	if err != nil {
		notes.AppendWarning("LB Health: failed to look up NLB — %v", err)
		return
	}
	if arn == "" {
		notes.AppendWarning("LB Health: no NLB found matching DNS name %s", hostname)
		return
	}

	targets, err := r.AwsClient.GetNLBTargetHealth(arn)
	if err != nil {
		notes.AppendWarning("LB Health: failed to get NLB target health for %s — %v", name, err)
		return
	}
	if len(targets) == 0 {
		notes.AppendWarning("LB Health: NLB %s has no registered targets", name)
		return
	}

	reportNLBTargetHealth(name, targets, notes)
}

// reportNLBTargetHealth formats and appends NLB target health to the notewriter.
func reportNLBTargetHealth(lbName string, targets []aws.NLBTargetHealth, notes *notewriter.NoteWriter) {
	var unhealthy []aws.NLBTargetHealth
	for _, t := range targets {
		if t.State != "healthy" {
			unhealthy = append(unhealthy, t)
		}
	}

	if len(unhealthy) == 0 {
		notes.AppendSuccess("LB Health: NLB %s — all %d target(s) healthy", lbName, len(targets))
		return
	}

	details := make([]string, 0, len(unhealthy))
	for _, t := range unhealthy {
		detail := fmt.Sprintf("%s (port %d): %s", t.TargetID, t.Port, t.State)
		if t.Reason != "" {
			detail += " — " + t.Reason
		}
		details = append(details, detail)
	}
	notes.AppendWarning("LB Health: NLB %s — %d/%d target(s) unhealthy:\n  %s",
		lbName, len(unhealthy), len(targets), strings.Join(details, "\n  "))
}

// checkCLBHealth finds a CLB by DNS name and reports instance health.
func (i *Investigation) checkCLBHealth(r *investigation.Resources, hostname string, notes *notewriter.NoteWriter) {
	name, err := r.AwsClient.FindCLBByDNSName(hostname)
	if err != nil {
		notes.AppendWarning("LB Health: failed to look up CLB — %v", err)
		return
	}
	if name == "" {
		notes.AppendWarning("LB Health: no CLB found matching DNS name %s", hostname)
		return
	}

	instances, err := r.AwsClient.GetCLBInstanceHealth(name)
	if err != nil {
		notes.AppendWarning("LB Health: failed to get CLB instance health for %s — %v", name, err)
		return
	}
	if len(instances) == 0 {
		notes.AppendWarning("LB Health: CLB %s has no registered instances", name)
		return
	}

	reportCLBInstanceHealth(name, instances, notes)
}

// reportCLBInstanceHealth formats and appends CLB instance health to the notewriter.
func reportCLBInstanceHealth(lbName string, instances []aws.CLBInstanceHealth, notes *notewriter.NoteWriter) {
	var unhealthy []aws.CLBInstanceHealth
	for _, inst := range instances {
		if inst.State != "InService" {
			unhealthy = append(unhealthy, inst)
		}
	}

	if len(unhealthy) == 0 {
		notes.AppendSuccess("LB Health: CLB %s — all %d instance(s) InService", lbName, len(instances))
		return
	}

	details := make([]string, 0, len(unhealthy))
	for _, inst := range unhealthy {
		detail := fmt.Sprintf("%s: %s", inst.InstanceID, inst.State)
		if inst.Description != "" {
			detail += " — " + inst.Description
		}
		details = append(details, detail)
	}
	notes.AppendWarning("LB Health: CLB %s — %d/%d instance(s) not InService:\n  %s",
		lbName, len(unhealthy), len(instances), strings.Join(details, "\n  "))
}

// checkVPCEgress runs the network verifier to validate VPC egress connectivity.
// The network verifier launches a temporary t3.micro EC2 instance in a private subnet
// to test outbound connectivity to required endpoints.
//
// Classic only, public only (not PrivateLink). Informational-only check.
func (i *Investigation) checkVPCEgress(r *investigation.Resources, notes *notewriter.NoteWriter) {
	verifierResult, failureReason, err := i.egressVerifier.run(r)
	if err != nil {
		notes.AppendWarning("VPC Egress: network verifier error — %v", err)
		return
	}

	switch verifierResult {
	case networkverifier.Failure:
		notes.AppendWarning("VPC Egress: network verifier reported blocked egress — %s", failureReason)
	case networkverifier.Success:
		notes.AppendSuccess("VPC Egress: network verifier passed — all egress endpoints reachable")
	default:
		notes.AppendWarning("VPC Egress: network verifier returned undefined result")
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

// defaultBlackboxProber implements blackboxProber by exec'ing wget into the
// blackbox-exporter pod in openshift-route-monitor-operator.
type defaultBlackboxProber struct{}

func (d *defaultBlackboxProber) runProbe(ctx context.Context, k8sClient k8sclient.Client, restConfig *rest.Config, consoleURL string) (string, error) {
	podList := &corev1.PodList{}
	if err := k8sClient.List(
		ctx, podList,
		client.InNamespace("openshift-route-monitor-operator"),
		client.MatchingLabels{"app": "blackbox-exporter"},
	); err != nil {
		return "", fmt.Errorf("failed to list blackbox-exporter pods: %w", err)
	}

	var bbPod *corev1.Pod
	for idx := range podList.Items {
		if podList.Items[idx].Status.Phase == corev1.PodRunning {
			bbPod = &podList.Items[idx]
			break
		}
	}
	if bbPod == nil {
		return "", fmt.Errorf("no running blackbox-exporter pod found in openshift-route-monitor-operator")
	}

	probeURL := fmt.Sprintf("http://localhost:9115/probe?target=%s&module=http_2xx&debug=true", consoleURL)
	output, err := k8sclient.ExecInPod(ctx, restConfig, bbPod, "blackbox-exporter", []string{
		"wget", "-qO-", probeURL,
	})
	if err != nil {
		return output, fmt.Errorf("exec failed: %w", err)
	}
	return strings.TrimSpace(output), nil
}

type probeResult struct {
	success       bool
	httpStatus    int
	failureMode   string // "dns", "timeout", "tls", "connection_refused", "server_error", "unknown"
	failureDetail string // human-readable detail extracted from logs
	duration      float64
}

var (
	probeSuccessRe    = regexp.MustCompile(`probe_success\s+([01])`)
	probeHTTPStatusRe = regexp.MustCompile(`probe_http_status_code\s+(\d+)`)
	probeDurationRe   = regexp.MustCompile(`probe_duration_seconds\s+([\d.]+)`)
)

func parseProbeResponse(body string) probeResult {
	result := probeResult{}

	const metricsSeparator = "Metrics that would have been returned:"
	logSection := body
	metricsSection := ""
	if idx := strings.Index(body, metricsSeparator); idx >= 0 {
		logSection = body[:idx]
		metricsSection = body[idx+len(metricsSeparator):]
	}

	if m := probeSuccessRe.FindStringSubmatch(metricsSection); len(m) > 1 {
		result.success = m[1] == "1"
	}
	if m := probeHTTPStatusRe.FindStringSubmatch(metricsSection); len(m) > 1 {
		result.httpStatus, _ = strconv.Atoi(m[1])
	}
	if m := probeDurationRe.FindStringSubmatch(metricsSection); len(m) > 1 {
		result.duration, _ = strconv.ParseFloat(m[1], 64)
	}

	if result.success {
		return result
	}

	logLower := strings.ToLower(logSection)

	type pattern struct {
		needles []string
		mode    string
	}
	patterns := []pattern{
		{needles: []string{"no such host", "server misbehaving"}, mode: "dns"},
		{needles: []string{"context deadline exceeded", "i/o timeout"}, mode: "timeout"},
		{needles: []string{"x509", "certificate"}, mode: "tls"},
		{needles: []string{"connection refused"}, mode: "connection_refused"},
	}

	for _, p := range patterns {
		for _, needle := range p.needles {
			if strings.Contains(logLower, needle) {
				result.failureMode = p.mode
				result.failureDetail = extractDetail(logSection, needle)
				return result
			}
		}
	}

	// Check for server error (5xx) from the HTTP status code.
	if result.httpStatus >= 500 && result.httpStatus < 600 {
		result.failureMode = "server_error"
		result.failureDetail = fmt.Sprintf("HTTP %d", result.httpStatus)
		return result
	}

	result.failureMode = "unknown"
	result.failureDetail = "probe failed with no recognized error pattern"
	return result
}

func extractDetail(logSection, needle string) string {
	needleLower := strings.ToLower(needle)
	for _, line := range strings.Split(logSection, "\n") {
		if strings.Contains(strings.ToLower(line), needleLower) {
			line = strings.TrimSpace(line)

			// Try to extract just the err= or msg= value for concise detail.
			for _, prefix := range []string{"err=", "msg="} {
				if idx := strings.Index(line, prefix); idx >= 0 {
					snippet := line[idx:]
					if len(snippet) > 200 {
						snippet = snippet[:200] + "..."
					}
					return snippet
				}
			}

			if len(line) > 200 {
				line = line[:200] + "..."
			}
			return line
		}
	}
	return needle
}

// checkBlackboxProbe queries the blackbox exporter's /probe endpoint by exec'ing
// into the blackbox-exporter pod and classifies the result.
//
// Informational-only check.
func (i *Investigation) checkBlackboxProbe(ctx context.Context, r *investigation.Resources, notes *notewriter.NoteWriter) {
	consoleURL := r.Cluster.Console().URL()
	if consoleURL == "" {
		notes.AppendWarning("Blackbox Probe: unable to determine console URL from cluster info")
		return
	}

	restConfig, err := getRestConfig(r)
	if err != nil {
		notes.AppendWarning("Blackbox Probe: unable to get REST config - %v", err)
		return
	}

	output, err := i.blackboxProber.runProbe(ctx, r.K8sClient, restConfig, consoleURL)
	if err != nil {
		notes.AppendWarning("Blackbox Probe: failed to query blackbox exporter - %v", err)
		return
	}

	pr := parseProbeResponse(output)
	if pr.success {
		notes.AppendSuccess("Blackbox Probe: probe succeeded (HTTP %d, %.2fs) for %s", pr.httpStatus, pr.duration, consoleURL)
	} else {
		notes.AppendWarning("Blackbox Probe: probe FAILED for %s — failure mode: %s — %s", consoleURL, pr.failureMode, pr.failureDetail)
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

package consoleerrorbudgetburn

import (
	"context"
	"fmt"
	"strings"
	"testing"

	cmv1 "github.com/openshift-online/ocm-sdk-go/clustersmgmt/v1"
	operatorv1 "github.com/openshift/api/operator/v1"
	"github.com/openshift/configuration-anomaly-detection/pkg/backplane"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/investigation"
	k8sclient "github.com/openshift/configuration-anomaly-detection/pkg/k8s"
	"github.com/openshift/configuration-anomaly-detection/pkg/notewriter"
	"github.com/openshift/configuration-anomaly-detection/pkg/ocm"
	"gotest.tools/v3/assert"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func testScheme() *runtime.Scheme {
	s := runtime.NewScheme()
	_ = corev1.AddToScheme(s)
	_ = operatorv1.Install(s)
	return s
}

func newFakeClient(objs ...client.Object) client.Client {
	return fake.NewClientBuilder().WithScheme(testScheme()).WithObjects(objs...).Build()
}

func newTestCluster(id, machineCIDR, consoleURL string) *cmv1.Cluster {
	builder := cmv1.NewCluster().
		ID(id).
		Network(cmv1.NewNetwork().MachineCIDR(machineCIDR))
	if consoleURL != "" {
		builder = builder.Console(cmv1.NewClusterConsole().URL(consoleURL))
	}
	cluster, _ := builder.Build()
	return cluster
}

func newTestNotes() *notewriter.NoteWriter {
	return notewriter.New("consoleerrorbudgetburn", nil)
}

// newDefaultIngressController creates an IngressController named "default" in openshift-ingress-operator
// with the given allowedSourceRanges. Pass nil for no EndpointPublishingStrategy.
func newDefaultIngressController(allowedSourceRanges []operatorv1.CIDR) *operatorv1.IngressController {
	ic := &operatorv1.IngressController{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "default",
			Namespace: "openshift-ingress-operator",
		},
	}
	if allowedSourceRanges != nil {
		ic.Spec.EndpointPublishingStrategy = &operatorv1.EndpointPublishingStrategy{
			LoadBalancer: &operatorv1.LoadBalancerStrategy{
				AllowedSourceRanges: allowedSourceRanges,
			},
		}
	}
	return ic
}

type mockConsoleServiceChecker struct {
	output string
	err    error
}

func (m *mockConsoleServiceChecker) checkConsoleEndpoint(_ context.Context, _ k8sclient.Client, _ *rest.Config) (string, error) {
	return m.output, m.err
}

// healthyConsoleChecker returns a mock that simulates a healthy console (HTTP 200).
func healthyConsoleChecker() *mockConsoleServiceChecker {
	return &mockConsoleServiceChecker{output: "200"}
}

// testRestConfig returns a dummy backplane.RestConfig for tests that need getRestConfig to succeed.
func testRestConfig() *backplane.RestConfig {
	return &backplane.RestConfig{Config: rest.Config{Host: "https://test-cluster:6443"}}
}

// mockBlackboxProber implements blackboxProber for testing.
type mockBlackboxProber struct {
	output string
	err    error
}

func (m *mockBlackboxProber) runProbe(_ context.Context, _ k8sclient.Client, _ *rest.Config, _ string) (string, error) {
	return m.output, m.err
}

func healthyBlackboxProber() *mockBlackboxProber {
	return &mockBlackboxProber{output: successfulProbeResponse}
}

const successfulProbeResponse = `Logs for the probe:
ts=2024-01-01T00:00:00.000Z caller=handler.go:119 module=http_2xx target=https://console-openshift-console.apps.test.example.com level=debug msg="Beginning probe"
ts=2024-01-01T00:00:00.001Z caller=handler.go:119 module=http_2xx target=https://console-openshift-console.apps.test.example.com level=debug msg="Resolving target address" ip_protocol=ip4
ts=2024-01-01T00:00:00.002Z caller=handler.go:119 module=http_2xx target=https://console-openshift-console.apps.test.example.com level=debug msg="Resolved target address" ip=10.0.1.50
ts=2024-01-01T00:00:00.003Z caller=handler.go:119 module=http_2xx target=https://console-openshift-console.apps.test.example.com level=debug msg="Making HTTP request" url=https://10.0.1.50 host=console-openshift-console.apps.test.example.com
ts=2024-01-01T00:00:00.200Z caller=handler.go:119 module=http_2xx target=https://console-openshift-console.apps.test.example.com level=debug msg="Received HTTP response" status_code=200
ts=2024-01-01T00:00:00.201Z caller=handler.go:119 module=http_2xx target=https://console-openshift-console.apps.test.example.com level=debug msg="Probe succeeded" duration_seconds=0.198

Metrics that would have been returned:
# HELP probe_success Displays whether or not the probe was a success
# TYPE probe_success gauge
probe_success 1
# HELP probe_http_status_code Response HTTP status code
# TYPE probe_http_status_code gauge
probe_http_status_code 200
# HELP probe_duration_seconds Returns how long the probe took to complete in seconds
# TYPE probe_duration_seconds gauge
probe_duration_seconds 0.198
`

const dnsFailureProbeResponse = `Logs for the probe:
ts=2024-01-01T00:00:00.000Z caller=handler.go:119 module=http_2xx target=https://console-openshift-console.apps.test.example.com level=debug msg="Beginning probe"
ts=2024-01-01T00:00:00.001Z caller=handler.go:119 module=http_2xx target=https://console-openshift-console.apps.test.example.com level=debug msg="Resolving target address" ip_protocol=ip4
ts=2024-01-01T00:00:00.002Z caller=handler.go:119 module=http_2xx target=https://console-openshift-console.apps.test.example.com level=error msg="Resolution failed" err="lookup console-openshift-console.apps.test.example.com: no such host"
ts=2024-01-01T00:00:00.002Z caller=handler.go:119 module=http_2xx target=https://console-openshift-console.apps.test.example.com level=debug msg="Probe failed" duration_seconds=0.001

Metrics that would have been returned:
# HELP probe_success Displays whether or not the probe was a success
# TYPE probe_success gauge
probe_success 0
# HELP probe_duration_seconds Returns how long the probe took to complete in seconds
# TYPE probe_duration_seconds gauge
probe_duration_seconds 0.001
`

const timeoutProbeResponse = `Logs for the probe:
ts=2024-01-01T00:00:00.000Z caller=handler.go:119 module=http_2xx target=https://console-openshift-console.apps.test.example.com level=debug msg="Beginning probe"
ts=2024-01-01T00:00:00.001Z caller=handler.go:119 module=http_2xx target=https://console-openshift-console.apps.test.example.com level=debug msg="Resolving target address" ip_protocol=ip4
ts=2024-01-01T00:00:00.002Z caller=handler.go:119 module=http_2xx target=https://console-openshift-console.apps.test.example.com level=debug msg="Resolved target address" ip=10.0.1.50
ts=2024-01-01T00:02:00.000Z caller=handler.go:119 module=http_2xx target=https://console-openshift-console.apps.test.example.com level=error msg="Error making HTTP request" err="Get \"https://10.0.1.50\": context deadline exceeded"
ts=2024-01-01T00:02:00.001Z caller=handler.go:119 module=http_2xx target=https://console-openshift-console.apps.test.example.com level=debug msg="Probe failed" duration_seconds=119.999

Metrics that would have been returned:
# HELP probe_success Displays whether or not the probe was a success
# TYPE probe_success gauge
probe_success 0
# HELP probe_duration_seconds Returns how long the probe took to complete in seconds
# TYPE probe_duration_seconds gauge
probe_duration_seconds 119.999
`

const tlsErrorProbeResponse = `Logs for the probe:
ts=2024-01-01T00:00:00.000Z caller=handler.go:119 module=http_2xx target=https://console-openshift-console.apps.test.example.com level=debug msg="Beginning probe"
ts=2024-01-01T00:00:00.001Z caller=handler.go:119 module=http_2xx target=https://console-openshift-console.apps.test.example.com level=debug msg="Resolving target address" ip_protocol=ip4
ts=2024-01-01T00:00:00.002Z caller=handler.go:119 module=http_2xx target=https://console-openshift-console.apps.test.example.com level=debug msg="Resolved target address" ip=10.0.1.50
ts=2024-01-01T00:00:00.100Z caller=handler.go:119 module=http_2xx target=https://console-openshift-console.apps.test.example.com level=error msg="Error making HTTP request" err="Get \"https://10.0.1.50\": x509: certificate signed by unknown authority"
ts=2024-01-01T00:00:00.101Z caller=handler.go:119 module=http_2xx target=https://console-openshift-console.apps.test.example.com level=debug msg="Probe failed" duration_seconds=0.099

Metrics that would have been returned:
# HELP probe_success Displays whether or not the probe was a success
# TYPE probe_success gauge
probe_success 0
# HELP probe_duration_seconds Returns how long the probe took to complete in seconds
# TYPE probe_duration_seconds gauge
probe_duration_seconds 0.099
`

const connectionRefusedProbeResponse = `Logs for the probe:
ts=2024-01-01T00:00:00.000Z caller=handler.go:119 module=http_2xx target=https://console-openshift-console.apps.test.example.com level=debug msg="Beginning probe"
ts=2024-01-01T00:00:00.001Z caller=handler.go:119 module=http_2xx target=https://console-openshift-console.apps.test.example.com level=debug msg="Resolving target address" ip_protocol=ip4
ts=2024-01-01T00:00:00.002Z caller=handler.go:119 module=http_2xx target=https://console-openshift-console.apps.test.example.com level=debug msg="Resolved target address" ip=10.0.1.50
ts=2024-01-01T00:00:00.003Z caller=handler.go:119 module=http_2xx target=https://console-openshift-console.apps.test.example.com level=error msg="Error making HTTP request" err="Get \"https://10.0.1.50\": dial tcp 10.0.1.50:443: connect: connection refused"
ts=2024-01-01T00:00:00.003Z caller=handler.go:119 module=http_2xx target=https://console-openshift-console.apps.test.example.com level=debug msg="Probe failed" duration_seconds=0.002

Metrics that would have been returned:
# HELP probe_success Displays whether or not the probe was a success
# TYPE probe_success gauge
probe_success 0
# HELP probe_duration_seconds Returns how long the probe took to complete in seconds
# TYPE probe_duration_seconds gauge
probe_duration_seconds 0.002
`

const serverErrorProbeResponse = `Logs for the probe:
ts=2024-01-01T00:00:00.000Z caller=handler.go:119 module=http_2xx target=https://console-openshift-console.apps.test.example.com level=debug msg="Beginning probe"
ts=2024-01-01T00:00:00.001Z caller=handler.go:119 module=http_2xx target=https://console-openshift-console.apps.test.example.com level=debug msg="Resolving target address" ip_protocol=ip4
ts=2024-01-01T00:00:00.002Z caller=handler.go:119 module=http_2xx target=https://console-openshift-console.apps.test.example.com level=debug msg="Resolved target address" ip=10.0.1.50
ts=2024-01-01T00:00:00.100Z caller=handler.go:119 module=http_2xx target=https://console-openshift-console.apps.test.example.com level=debug msg="Received HTTP response" status_code=503
ts=2024-01-01T00:00:00.101Z caller=handler.go:119 module=http_2xx target=https://console-openshift-console.apps.test.example.com level=debug msg="Probe failed" duration_seconds=0.099

Metrics that would have been returned:
# HELP probe_success Displays whether or not the probe was a success
# TYPE probe_success gauge
probe_success 0
# HELP probe_http_status_code Response HTTP status code
# TYPE probe_http_status_code gauge
probe_http_status_code 503
# HELP probe_duration_seconds Returns how long the probe took to complete in seconds
# TYPE probe_duration_seconds gauge
probe_duration_seconds 0.099
`

const unknownFailureProbeResponse = `Logs for the probe:
ts=2024-01-01T00:00:00.000Z caller=handler.go:119 module=http_2xx target=https://console-openshift-console.apps.test.example.com level=debug msg="Beginning probe"
ts=2024-01-01T00:00:00.100Z caller=handler.go:119 module=http_2xx target=https://console-openshift-console.apps.test.example.com level=debug msg="Probe failed" duration_seconds=0.099

Metrics that would have been returned:
# HELP probe_success Displays whether or not the probe was a success
# TYPE probe_success gauge
probe_success 0
# HELP probe_duration_seconds Returns how long the probe took to complete in seconds
# TYPE probe_duration_seconds gauge
probe_duration_seconds 0.099
`

func TestName(t *testing.T) {
	inv := &Investigation{}
	if inv.Name() != "consoleerrorbudgetburn" {
		t.Errorf("expected 'consoleerrorbudgetburn', got %q", inv.Name())
	}
}

func TestAlertTitle(t *testing.T) {
	inv := &Investigation{}
	if inv.AlertTitle() != "console-errorbudgetburn" {
		t.Errorf("expected 'console-errorbudgetburn', got %q", inv.AlertTitle())
	}
}

func TestDescription(t *testing.T) {
	inv := &Investigation{}
	if inv.Description() == "" {
		t.Error("expected non-empty description")
	}
}

func TestIsExperimental(t *testing.T) {
	inv := &Investigation{}
	if !inv.IsExperimental() {
		t.Error("expected IsExperimental to be true")
	}
}

// checkAllowedSourceRanges unit testing:

func TestCheckAllowedSourceRanges_NotConfigured(t *testing.T) {
	ic := newDefaultIngressController(nil)
	k8sClient := newFakeClient(ic)
	cluster := newTestCluster("test-cluster", "10.0.0.0/16", "")
	notes := newTestNotes()
	inv := &Investigation{}

	r := &investigation.Resources{
		Cluster:   cluster,
		K8sClient: k8sClient,
	}

	result := inv.checkAllowedSourceRanges(context.Background(), r, notes)
	if result {
		t.Error("expected false (no misconfiguration), got true")
	}
	if !strings.Contains(notes.String(), "not configured") {
		t.Errorf("expected 'not configured' in notes, got: %s", notes.String())
	}
}

func TestCheckAllowedSourceRanges_MachineIncluded(t *testing.T) {
	// CIDR 10.0.0.0/16 is contained within allowed range 10.0.0.0/8
	ic := newDefaultIngressController([]operatorv1.CIDR{"10.0.0.0/8"})
	k8sClient := newFakeClient(ic)
	cluster := newTestCluster("test-cluster", "10.0.0.0/16", "")
	notes := newTestNotes()
	inv := &Investigation{}

	r := &investigation.Resources{
		Cluster:   cluster,
		K8sClient: k8sClient,
	}

	result := inv.checkAllowedSourceRanges(context.Background(), r, notes)
	if result {
		t.Error("expected false (machine CIDR covered), got true")
	}
	if !strings.Contains(notes.String(), "is covered") {
		t.Errorf("expected 'is covered' in notes, got: %s", notes.String())
	}
}

func TestCheckAllowedSourceRanges_ExactMatch(t *testing.T) {
	// Exact match: allowed 10.0.0.0/16 == machine CIDR 10.0.0.0/16
	ic := newDefaultIngressController([]operatorv1.CIDR{"10.0.0.0/16"})
	k8sClient := newFakeClient(ic)
	cluster := newTestCluster("test-cluster", "10.0.0.0/16", "")
	notes := newTestNotes()
	inv := &Investigation{}

	r := &investigation.Resources{
		Cluster:   cluster,
		K8sClient: k8sClient,
	}

	result := inv.checkAllowedSourceRanges(context.Background(), r, notes)
	if result {
		t.Error("expected false (exact match is covered), got true")
	}
	if !strings.Contains(notes.String(), "is covered") {
		t.Errorf("expected 'is covered' in notes, got: %s", notes.String())
	}
}

func TestCheckAllowedSourceRanges_SmallerRangeDoesNotContain(t *testing.T) {
	// Allowed 10.0.0.0/24 does NOT contain 10.0.0.0/16
	ic := newDefaultIngressController([]operatorv1.CIDR{"10.0.0.0/24"})
	k8sClient := newFakeClient(ic)
	cluster := newTestCluster("test-cluster", "10.0.0.0/16", "")
	notes := newTestNotes()
	inv := &Investigation{}

	r := &investigation.Resources{
		Cluster:   cluster,
		K8sClient: k8sClient,
	}

	result := inv.checkAllowedSourceRanges(context.Background(), r, notes)
	if !result {
		t.Error("expected true (smaller range does not contain machine CIDR), got false")
	}
	if !strings.Contains(notes.String(), "NOT included") {
		t.Errorf("expected 'NOT included' in notes, got: %s", notes.String())
	}
}

func TestCheckAllowedSourceRanges_MachineExcluded(t *testing.T) {
	// CIDR 10.0.0.0/16 is not covered by 192.168.0.0/16
	ic := newDefaultIngressController([]operatorv1.CIDR{"192.168.0.0/16"})
	k8sClient := newFakeClient(ic)
	cluster := newTestCluster("test-cluster", "10.0.0.0/16", "")
	notes := newTestNotes()
	inv := &Investigation{}

	r := &investigation.Resources{
		Cluster:   cluster,
		K8sClient: k8sClient,
	}

	result := inv.checkAllowedSourceRanges(context.Background(), r, notes)
	if !result {
		t.Error("expected true (machine CIDR excluded), got false")
	}
	if !strings.Contains(notes.String(), "NOT included") {
		t.Errorf("expected 'NOT included' in notes, got: %s", notes.String())
	}
}

func TestCheckAllowedSourceRanges_MultipleRangesOneMatch(t *testing.T) {
	// First range doesn't match, but second range covers the machine CIDR
	ic := newDefaultIngressController([]operatorv1.CIDR{"192.168.0.0/16", "10.0.0.0/8"})
	k8sClient := newFakeClient(ic)
	cluster := newTestCluster("test-cluster", "10.0.0.0/16", "")
	notes := newTestNotes()
	inv := &Investigation{}

	r := &investigation.Resources{
		Cluster:   cluster,
		K8sClient: k8sClient,
	}

	result := inv.checkAllowedSourceRanges(context.Background(), r, notes)
	if result {
		t.Error("expected false (second range covers machine CIDR), got true")
	}
	if !strings.Contains(notes.String(), "is covered") {
		t.Errorf("expected 'is covered' in notes, got: %s", notes.String())
	}
}

func TestCheckAllowedSourceRanges_EmptyMachineCIDR(t *testing.T) {
	// CIDR empty; cluster info incomplete
	ic := newDefaultIngressController([]operatorv1.CIDR{"10.0.0.0/8"})
	k8sClient := newFakeClient(ic)
	cluster := newTestCluster("test-cluster", "", "")
	notes := newTestNotes()
	inv := &Investigation{}

	r := &investigation.Resources{
		Cluster:   cluster,
		K8sClient: k8sClient,
	}

	result := inv.checkAllowedSourceRanges(context.Background(), r, notes)
	if result {
		t.Error("expected false (cannot determine CIDR), got true")
	}
	if !strings.Contains(notes.String(), "unable to determine") {
		t.Errorf("expected 'unable to determine' in notes, got: %s", notes.String())
	}
}

func TestCheckAllowedSourceRanges_IngressControllerNotFound(t *testing.T) {
	// No IngressController in the fake client
	k8sClient := newFakeClient()
	cluster := newTestCluster("test-cluster", "10.0.0.0/16", "")
	notes := newTestNotes()
	inv := &Investigation{}

	r := &investigation.Resources{
		Cluster:   cluster,
		K8sClient: k8sClient,
	}

	result := inv.checkAllowedSourceRanges(context.Background(), r, notes)
	if result {
		t.Error("expected false (error fetching IC), got true")
	}
	if !strings.Contains(notes.String(), "failed to get") {
		t.Errorf("expected 'failed to get' in notes, got: %s", notes.String())
	}
}

func TestCheckAllowedSourceRanges_NilLoadBalancer(t *testing.T) {
	// EndpointPublishingStrategy exists but LoadBalancer is nil
	ic := &operatorv1.IngressController{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "default",
			Namespace: "openshift-ingress-operator",
		},
		Spec: operatorv1.IngressControllerSpec{
			EndpointPublishingStrategy: &operatorv1.EndpointPublishingStrategy{
				// LoadBalancer is nil
			},
		},
	}
	k8sClient := newFakeClient(ic)
	cluster := newTestCluster("test-cluster", "10.0.0.0/16", "")
	notes := newTestNotes()
	inv := &Investigation{}

	r := &investigation.Resources{
		Cluster:   cluster,
		K8sClient: k8sClient,
	}

	result := inv.checkAllowedSourceRanges(context.Background(), r, notes)
	if result {
		t.Error("expected false (no LB config), got true")
	}
	if !strings.Contains(notes.String(), "not configured") {
		t.Errorf("expected 'not configured' in notes, got: %s", notes.String())
	}
}

func TestCheckAllowedSourceRanges_EmptyAllowedSourceRanges(t *testing.T) {
	// LoadBalancer exists but AllowedSourceRanges is empty slice
	ic := newDefaultIngressController([]operatorv1.CIDR{})
	k8sClient := newFakeClient(ic)
	cluster := newTestCluster("test-cluster", "10.0.0.0/16", "")
	notes := newTestNotes()
	inv := &Investigation{}

	r := &investigation.Resources{
		Cluster:   cluster,
		K8sClient: k8sClient,
	}

	result := inv.checkAllowedSourceRanges(context.Background(), r, notes)
	if result {
		t.Error("expected false (empty ranges), got true")
	}
	if !strings.Contains(notes.String(), "not configured") {
		t.Errorf("expected 'not configured' in notes, got: %s", notes.String())
	}
}

func TestNewAllowedSourceRangesSL(t *testing.T) {
	machineCIDR := "10.0.0.0/16"
	expected := &ocm.ServiceLog{
		Severity:     "Critical",
		ServiceName:  "SREManualAction",
		Summary:      "Action required: Incorrect Default IngressController Configuration",
		Description:  fmt.Sprintf("Your cluster requires you to take action. Your default ingresscontroller is misconfigured, generating alerts for Red Hat SRE and degrading cluster health. The Machine CIDR for the cluster, '%s', needs to be added to the allowlist.", machineCIDR),
		InternalOnly: false,
	}

	result := newAllowedSourceRangesSL(machineCIDR)
	assert.Equal(t, *expected, *result)
}

// DNS test helper
// newDefaultDNS creates a dns.operator.openshift.io/default object with the given upstreams.
func newDefaultDNS(upstreams []operatorv1.Upstream) *operatorv1.DNS {
	return &operatorv1.DNS{
		ObjectMeta: metav1.ObjectMeta{
			Name: "default",
		},
		Spec: operatorv1.DNSSpec{
			UpstreamResolvers: operatorv1.UpstreamResolvers{
				Upstreams: upstreams,
			},
		},
	}
}

// checkUpstreamDNS unit tests
func TestCheckUpstreamDNS_NoCustomResolvers(t *testing.T) {
	dns := newDefaultDNS([]operatorv1.Upstream{
		{Type: operatorv1.SystemResolveConfType},
	})
	k8sClient := newFakeClient(dns)
	notes := newTestNotes()
	inv := &Investigation{}

	inv.checkUpstreamDNS(context.Background(), k8sClient, notes)

	if !strings.Contains(notes.String(), "no custom upstream resolvers") {
		t.Errorf("expected 'no custom upstream resolvers' in notes, got: %s", notes.String())
	}
}

func TestCheckUpstreamDNS_CustomResolverFound(t *testing.T) {
	dns := newDefaultDNS([]operatorv1.Upstream{
		{Type: operatorv1.NetworkResolverType, Address: "1.2.3.4", Port: 53},
	})
	k8sClient := newFakeClient(dns)
	notes := newTestNotes()
	inv := &Investigation{}

	inv.checkUpstreamDNS(context.Background(), k8sClient, notes)

	output := notes.String()
	if !strings.Contains(output, "customer-configured upstream resolvers") {
		t.Errorf("expected warning about custom resolvers, got: %s", output)
	}
	if !strings.Contains(output, "1.2.3.4:53") {
		t.Errorf("expected '1.2.3.4:53' in notes, got: %s", output)
	}
}

func TestCheckUpstreamDNS_MultipleCustomResolvers(t *testing.T) {
	dns := newDefaultDNS([]operatorv1.Upstream{
		{Type: operatorv1.NetworkResolverType, Address: "1.2.3.4", Port: 53},
		{Type: operatorv1.NetworkResolverType, Address: "5.6.7.8", Port: 5353},
	})
	k8sClient := newFakeClient(dns)
	notes := newTestNotes()
	inv := &Investigation{}

	inv.checkUpstreamDNS(context.Background(), k8sClient, notes)

	output := notes.String()
	if !strings.Contains(output, "1.2.3.4:53") {
		t.Errorf("expected '1.2.3.4:53' in notes, got: %s", output)
	}
	if !strings.Contains(output, "5.6.7.8:5353") {
		t.Errorf("expected '5.6.7.8:5353' in notes, got: %s", output)
	}
}

func TestCheckUpstreamDNS_MixedUpstreams(t *testing.T) {
	dns := newDefaultDNS([]operatorv1.Upstream{
		{Type: operatorv1.SystemResolveConfType},
		{Type: operatorv1.NetworkResolverType, Address: "8.8.8.8", Port: 53},
	})
	k8sClient := newFakeClient(dns)
	notes := newTestNotes()
	inv := &Investigation{}

	inv.checkUpstreamDNS(context.Background(), k8sClient, notes)

	output := notes.String()
	if !strings.Contains(output, "customer-configured upstream resolvers") {
		t.Errorf("expected warning about custom resolvers, got: %s", output)
	}
	if !strings.Contains(output, "8.8.8.8:53") {
		t.Errorf("expected '8.8.8.8:53' in notes, got: %s", output)
	}
}

func TestCheckUpstreamDNS_EmptyUpstreams(t *testing.T) {
	dns := newDefaultDNS([]operatorv1.Upstream{})
	k8sClient := newFakeClient(dns)
	notes := newTestNotes()
	inv := &Investigation{}

	inv.checkUpstreamDNS(context.Background(), k8sClient, notes)

	if !strings.Contains(notes.String(), "no custom upstream resolvers") {
		t.Errorf("expected 'no custom upstream resolvers' in notes, got: %s", notes.String())
	}
}

func TestCheckUpstreamDNS_GetError(t *testing.T) {
	// No DNS object in the fake client
	k8sClient := newFakeClient()
	notes := newTestNotes()
	inv := &Investigation{}

	inv.checkUpstreamDNS(context.Background(), k8sClient, notes)

	if !strings.Contains(notes.String(), "failed to get") {
		t.Errorf("expected 'failed to get' in notes, got: %s", notes.String())
	}
}

// checkPodHealth unit tests (Router)

func newRouterPod(name string, phase corev1.PodPhase, containers []corev1.ContainerStatus) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "openshift-ingress",
		},
		Status: corev1.PodStatus{
			Phase:             phase,
			ContainerStatuses: containers,
		},
	}
}

func TestCheckPodHealth_Router_AllHealthy(t *testing.T) {
	pod1 := newRouterPod("router-default-abc", corev1.PodRunning, []corev1.ContainerStatus{
		{Name: "router", Ready: true, RestartCount: 0},
	})
	pod2 := newRouterPod("router-default-def", corev1.PodRunning, []corev1.ContainerStatus{
		{Name: "router", Ready: true, RestartCount: 0},
	})
	k8sClient := newFakeClient(pod1, pod2)
	notes := newTestNotes()
	inv := &Investigation{}

	inv.checkPodHealth(context.Background(), k8sClient, "openshift-ingress", "Router", notes)

	output := notes.String()
	if !strings.Contains(output, "2 pod(s)") {
		t.Errorf("expected '2 pod(s)' in notes, got: %s", output)
	}
	if !strings.Contains(output, "running and ready") {
		t.Errorf("expected 'running and ready' in notes, got: %s", output)
	}
}

func TestCheckPodHealth_Router_CrashLooping(t *testing.T) {
	pod := newRouterPod("router-default-abc", corev1.PodRunning, []corev1.ContainerStatus{
		{Name: "router", Ready: false, RestartCount: 10, State: corev1.ContainerState{
			Waiting: &corev1.ContainerStateWaiting{Reason: "CrashLoopBackOff"},
		}},
	})
	k8sClient := newFakeClient(pod)
	notes := newTestNotes()
	inv := &Investigation{}

	inv.checkPodHealth(context.Background(), k8sClient, "openshift-ingress", "Router", notes)

	output := notes.String()
	if !strings.Contains(output, "CrashLoopBackOff") {
		t.Errorf("expected 'CrashLoopBackOff' in notes, got: %s", output)
	}
}

func TestCheckPodHealth_Router_PodNotReady(t *testing.T) {
	pod := newRouterPod("router-default-abc", corev1.PodRunning, []corev1.ContainerStatus{
		{Name: "router", Ready: false, RestartCount: 0},
	})
	k8sClient := newFakeClient(pod)
	notes := newTestNotes()
	inv := &Investigation{}

	inv.checkPodHealth(context.Background(), k8sClient, "openshift-ingress", "Router", notes)

	output := notes.String()
	if !strings.Contains(output, "not ready") {
		t.Errorf("expected 'not ready' in notes, got: %s", output)
	}
}

func TestCheckPodHealth_Router_NoPods(t *testing.T) {
	k8sClient := newFakeClient()
	notes := newTestNotes()
	inv := &Investigation{}

	inv.checkPodHealth(context.Background(), k8sClient, "openshift-ingress", "Router", notes)

	if !strings.Contains(notes.String(), "no pods found") {
		t.Errorf("expected 'no pods found' in notes, got: %s", notes.String())
	}
}

func TestCheckPodHealth_Router_WarningEvents(t *testing.T) {
	pod := newRouterPod("router-default-abc", corev1.PodRunning, []corev1.ContainerStatus{
		{Name: "router", Ready: true, RestartCount: 0},
	})
	event := &corev1.Event{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "router-default-abc.warning",
			Namespace: "openshift-ingress",
		},
		InvolvedObject: corev1.ObjectReference{Kind: "Pod", Name: "router-default-abc"},
		Type:           corev1.EventTypeWarning,
		Reason:         "Unhealthy",
		Message:        "Readiness probe failed",
		Count:          3,
	}
	k8sClient := newFakeClient(pod, event)
	notes := newTestNotes()
	inv := &Investigation{}

	inv.checkPodHealth(context.Background(), k8sClient, "openshift-ingress", "Router", notes)

	output := notes.String()
	if !strings.Contains(output, "Unhealthy") {
		t.Errorf("expected 'Unhealthy' in notes, got: %s", output)
	}
	if !strings.Contains(output, "Readiness probe failed") {
		t.Errorf("expected 'Readiness probe failed' in notes, got: %s", output)
	}
}

func TestCheckPodHealth_Router_ExcessiveRestarts(t *testing.T) {
	pod := newRouterPod("router-default-abc", corev1.PodRunning, []corev1.ContainerStatus{
		{Name: "router", Ready: true, RestartCount: 5},
	})
	k8sClient := newFakeClient(pod)
	notes := newTestNotes()
	inv := &Investigation{}

	inv.checkPodHealth(context.Background(), k8sClient, "openshift-ingress", "Router", notes)

	output := notes.String()
	if !strings.Contains(output, "5 restarts") {
		t.Errorf("expected '5 restarts' in notes, got: %s", output)
	}
}

// checkConsoleService unit tests

func TestCheckConsoleService_Healthy(t *testing.T) {
	cluster := newTestCluster("test-cluster", "10.0.0.0/16", "")
	k8sClient := newFakeClient()
	notes := newTestNotes()
	inv := &Investigation{consoleChecker: &mockConsoleServiceChecker{output: "200"}}

	r := &investigation.Resources{
		Cluster:    cluster,
		K8sClient:  k8sClient,
		RestConfig: testRestConfig(),
	}

	inv.checkConsoleService(context.Background(), r, notes)

	output := notes.String()
	if !strings.Contains(output, "HTTP 200") {
		t.Errorf("expected 'HTTP 200' in notes, got: %s", output)
	}
	if !strings.Contains(output, "responding") {
		t.Errorf("expected 'responding' in notes, got: %s", output)
	}
}

func TestCheckConsoleService_NonOK(t *testing.T) {
	cluster := newTestCluster("test-cluster", "10.0.0.0/16", "")
	k8sClient := newFakeClient()
	notes := newTestNotes()
	inv := &Investigation{consoleChecker: &mockConsoleServiceChecker{output: "503"}}

	r := &investigation.Resources{
		Cluster:    cluster,
		K8sClient:  k8sClient,
		RestConfig: testRestConfig(),
	}

	inv.checkConsoleService(context.Background(), r, notes)

	output := notes.String()
	if !strings.Contains(output, "HTTP 503") {
		t.Errorf("expected 'HTTP 503' in notes, got: %s", output)
	}
}

func TestCheckConsoleService_ExecError(t *testing.T) {
	cluster := newTestCluster("test-cluster", "10.0.0.0/16", "")
	k8sClient := newFakeClient()
	notes := newTestNotes()
	inv := &Investigation{consoleChecker: &mockConsoleServiceChecker{err: fmt.Errorf("connection refused")}}

	r := &investigation.Resources{
		Cluster:    cluster,
		K8sClient:  k8sClient,
		RestConfig: testRestConfig(),
	}

	inv.checkConsoleService(context.Background(), r, notes)

	output := notes.String()
	if !strings.Contains(output, "unable to reach") {
		t.Errorf("expected 'unable to reach' in notes, got: %s", output)
	}
}

// checkPodHealth unit tests (console)

func newConsolePod(name, nodeName string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "openshift-console",
		},
		Spec: corev1.PodSpec{
			NodeName: nodeName,
		},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
			ContainerStatuses: []corev1.ContainerStatus{
				{Name: "console", Ready: true, RestartCount: 0},
			},
		},
	}
}

func TestCheckPodHealth_Console_AllHealthy(t *testing.T) {
	pod1 := newConsolePod("console-abc", "node-1")
	pod2 := newConsolePod("console-def", "node-2")
	k8sClient := newFakeClient(pod1, pod2)
	notes := newTestNotes()
	inv := &Investigation{}

	inv.checkPodHealth(context.Background(), k8sClient, "openshift-console", "Console", notes)

	output := notes.String()
	if !strings.Contains(output, "Console: all 2 pod(s)") {
		t.Errorf("expected 'Console: all 2 pod(s)' in notes, got: %s", output)
	}
}

// checkNodeHealth tests

func newTestNode(name string, conditions []corev1.NodeCondition, unschedulable bool) *corev1.Node {
	return &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: corev1.NodeSpec{
			Unschedulable: unschedulable,
		},
		Status: corev1.NodeStatus{
			Conditions: conditions,
		},
	}
}

func healthyNodeConditions() []corev1.NodeCondition {
	return []corev1.NodeCondition{
		{Type: corev1.NodeReady, Status: corev1.ConditionTrue},
		{Type: corev1.NodeMemoryPressure, Status: corev1.ConditionFalse},
		{Type: corev1.NodeDiskPressure, Status: corev1.ConditionFalse},
		{Type: corev1.NodePIDPressure, Status: corev1.ConditionFalse},
	}
}

func TestCheckNodeHealth_AllHealthy(t *testing.T) {
	consolePod := newConsolePod("console-abc", "node-1")
	node := newTestNode("node-1", healthyNodeConditions(), false)
	k8sClient := newFakeClient(consolePod, node)
	notes := newTestNotes()
	inv := &Investigation{}

	inv.checkNodeHealth(context.Background(), k8sClient, notes)

	output := notes.String()
	if !strings.Contains(output, "1 node(s) running console pods are healthy") {
		t.Errorf("expected healthy node message, got: %s", output)
	}
}

func TestCheckNodeHealth_NodeNotReady(t *testing.T) {
	consolePod := newConsolePod("console-abc", "node-1")
	node := newTestNode("node-1", []corev1.NodeCondition{
		{Type: corev1.NodeReady, Status: corev1.ConditionFalse, Reason: "KubeletNotReady"},
	}, false)
	k8sClient := newFakeClient(consolePod, node)
	notes := newTestNotes()
	inv := &Investigation{}

	inv.checkNodeHealth(context.Background(), k8sClient, notes)

	output := notes.String()
	if !strings.Contains(output, "NotReady") {
		t.Errorf("expected 'NotReady' in notes, got: %s", output)
	}
}

func TestCheckNodeHealth_DiskPressure(t *testing.T) {
	consolePod := newConsolePod("console-abc", "node-1")
	node := newTestNode("node-1", []corev1.NodeCondition{
		{Type: corev1.NodeReady, Status: corev1.ConditionTrue},
		{Type: corev1.NodeDiskPressure, Status: corev1.ConditionTrue},
	}, false)
	k8sClient := newFakeClient(consolePod, node)
	notes := newTestNotes()
	inv := &Investigation{}

	inv.checkNodeHealth(context.Background(), k8sClient, notes)

	output := notes.String()
	if !strings.Contains(output, "DiskPressure") {
		t.Errorf("expected 'DiskPressure' in notes, got: %s", output)
	}
}

func TestCheckNodeHealth_NoConsolePods(t *testing.T) {
	k8sClient := newFakeClient()
	notes := newTestNotes()
	inv := &Investigation{}

	inv.checkNodeHealth(context.Background(), k8sClient, notes)

	output := notes.String()
	if !strings.Contains(output, "no console pods found") {
		t.Errorf("expected 'no console pods found' in notes, got: %s", output)
	}
}

func TestCheckNodeHealth_PIDPressure(t *testing.T) {
	consolePod := newConsolePod("console-abc", "node-1")
	node := newTestNode("node-1", []corev1.NodeCondition{
		{Type: corev1.NodeReady, Status: corev1.ConditionTrue},
		{Type: corev1.NodePIDPressure, Status: corev1.ConditionTrue},
	}, false)
	k8sClient := newFakeClient(consolePod, node)
	notes := newTestNotes()
	inv := &Investigation{}

	inv.checkNodeHealth(context.Background(), k8sClient, notes)

	output := notes.String()
	if !strings.Contains(output, "PIDPressure") {
		t.Errorf("expected 'PIDPressure' in notes, got: %s", output)
	}
}

func TestCheckNodeHealth_Unschedulable(t *testing.T) {
	consolePod := newConsolePod("console-abc", "node-1")
	node := newTestNode("node-1", healthyNodeConditions(), true)
	k8sClient := newFakeClient(consolePod, node)
	notes := newTestNotes()
	inv := &Investigation{}

	inv.checkNodeHealth(context.Background(), k8sClient, notes)

	output := notes.String()
	if !strings.Contains(output, "Unschedulable") {
		t.Errorf("expected 'Unschedulable' in notes, got: %s", output)
	}
}

func TestCheckNodeHealth_MultipleNodesOneUnhealthy(t *testing.T) {
	pod1 := newConsolePod("console-abc", "node-1")
	pod2 := newConsolePod("console-def", "node-2")
	node1 := newTestNode("node-1", healthyNodeConditions(), false)
	node2 := newTestNode("node-2", []corev1.NodeCondition{
		{Type: corev1.NodeReady, Status: corev1.ConditionTrue},
		{Type: corev1.NodeMemoryPressure, Status: corev1.ConditionTrue},
	}, false)
	k8sClient := newFakeClient(pod1, pod2, node1, node2)
	notes := newTestNotes()
	inv := &Investigation{}

	inv.checkNodeHealth(context.Background(), k8sClient, notes)

	output := notes.String()
	if !strings.Contains(output, "MemoryPressure") {
		t.Errorf("expected 'MemoryPressure' in notes, got: %s", output)
	}
	if !strings.Contains(output, "node-2") {
		t.Errorf("expected 'node-2' in notes, got: %s", output)
	}
}

// Run-level tests

func TestRun_HCP_SkipsAllowedSourceRanges(t *testing.T) {
	ic := newDefaultIngressController([]operatorv1.CIDR{"192.168.0.0/16"})
	dns := newDefaultDNS([]operatorv1.Upstream{{Type: operatorv1.SystemResolveConfType}})
	routerPod := newRouterPod("router-default-abc", corev1.PodRunning, []corev1.ContainerStatus{
		{Name: "router", Ready: true, RestartCount: 0},
	})
	consolePod := newConsolePod("console-abc", "node-1")
	node := newTestNode("node-1", healthyNodeConditions(), false)
	k8sClient := newFakeClient(ic, dns, routerPod, consolePod, node)
	cluster := newTestCluster("test-cluster", "10.0.0.0/16", "https://console.test.example.com")

	rb := &investigation.ResourceBuilderMock{
		Resources: &investigation.Resources{
			Cluster:    cluster,
			K8sClient:  k8sClient,
			IsHCP:      true,
			RestConfig: testRestConfig(),
		},
	}

	inv := &Investigation{consoleChecker: healthyConsoleChecker(), blackboxProber: healthyBlackboxProber()}
	result, err := inv.Run(rb)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should escalate (no root cause found), not silence
	hasSilence := false
	hasEscalate := false
	for _, a := range result.Actions {
		if a.Type() == "silence_incident" {
			hasSilence = true
		}
		if a.Type() == "escalate_incident" {
			hasEscalate = true
		}
	}
	if hasSilence {
		t.Error("expected no silence action for HCP cluster")
	}
	if !hasEscalate {
		t.Error("expected escalate action for HCP cluster (no root cause path)")
	}
}

func TestRun_AllowedSourceRangesMisconfigured(t *testing.T) {
	// Classic cluster with machine CIDR excluded from allowedSourceRanges
	ic := newDefaultIngressController([]operatorv1.CIDR{"192.168.0.0/16"})
	k8sClient := newFakeClient(ic)
	cluster := newTestCluster("test-cluster", "10.0.0.0/16", "https://console.test.example.com")

	rb := &investigation.ResourceBuilderMock{
		Resources: &investigation.Resources{
			Cluster:    cluster,
			K8sClient:  k8sClient,
			IsHCP:      false,
			RestConfig: testRestConfig(),
		},
	}

	inv := &Investigation{consoleChecker: healthyConsoleChecker(), blackboxProber: healthyBlackboxProber()}
	result, err := inv.Run(rb)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// should have: backplane report, PD note, service log, silence
	hasServiceLog := false
	hasSilence := false
	hasEscalate := false
	for _, a := range result.Actions {
		switch a.Type() {
		case "service_log":
			hasServiceLog = true
		case "silence_incident":
			hasSilence = true
		case "escalate_incident":
			hasEscalate = true
		}
	}
	if !hasServiceLog {
		t.Error("expected service log action for misconfigured allowedSourceRanges")
	}
	if !hasSilence {
		t.Error("expected silence action for misconfigured allowedSourceRanges")
	}
	if hasEscalate {
		t.Error("unexpected escalate action — should silence, not escalate")
	}
}

func TestRun_AllowedSourceRangesOK(t *testing.T) {
	// Classic cluster with machine CIDR properly included
	ic := newDefaultIngressController([]operatorv1.CIDR{"10.0.0.0/8"})
	dns := newDefaultDNS([]operatorv1.Upstream{{Type: operatorv1.SystemResolveConfType}})
	routerPod := newRouterPod("router-default-abc", corev1.PodRunning, []corev1.ContainerStatus{
		{Name: "router", Ready: true, RestartCount: 0},
	})
	consolePod := newConsolePod("console-abc", "node-1")
	node := newTestNode("node-1", healthyNodeConditions(), false)
	k8sClient := newFakeClient(ic, dns, routerPod, consolePod, node)
	cluster := newTestCluster("test-cluster", "10.0.0.0/16", "https://console.test.example.com")

	rb := &investigation.ResourceBuilderMock{
		Resources: &investigation.Resources{
			Cluster:    cluster,
			K8sClient:  k8sClient,
			IsHCP:      false,
			RestConfig: testRestConfig(),
		},
	}

	inv := &Investigation{consoleChecker: healthyConsoleChecker(), blackboxProber: healthyBlackboxProber()}
	result, err := inv.Run(rb)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should escalate (no root cause); no SL, no silence
	hasServiceLog := false
	hasSilence := false
	hasEscalate := false
	for _, a := range result.Actions {
		switch a.Type() {
		case "service_log":
			hasServiceLog = true
		case "silence_incident":
			hasSilence = true
		case "escalate_incident":
			hasEscalate = true
		}
	}
	if hasServiceLog {
		t.Error("unexpected service log action — ranges are OK")
	}
	if hasSilence {
		t.Error("unexpected silence action — ranges are OK")
	}
	if !hasEscalate {
		t.Error("expected escalate action (no root cause path)")
	}
}

func TestRun_ClusterAccessError(t *testing.T) {
	rb := &investigation.ResourceBuilderMock{
		BuildError: investigation.RestConfigError{ClusterID: "test-cluster", Err: fmt.Errorf("backplane unavailable")},
	}

	inv := &Investigation{}
	result, err := inv.Run(rb)
	if err != nil {
		t.Fatalf("expected nil error for cluster access error, got: %v", err)
	}

	hasEscalate := false
	for _, a := range result.Actions {
		if a.Type() == "escalate_incident" {
			hasEscalate = true
		}
	}
	if !hasEscalate {
		t.Error("expected escalate action for cluster access error")
	}
}

// parseProbeResponse unit tests

func TestParseProbeResponse_Success(t *testing.T) {
	pr := parseProbeResponse(successfulProbeResponse)
	if !pr.success {
		t.Error("expected success=true")
	}
	if pr.httpStatus != 200 {
		t.Errorf("expected httpStatus=200, got %d", pr.httpStatus)
	}
	if pr.duration < 0.19 || pr.duration > 0.20 {
		t.Errorf("expected duration≈0.198, got %f", pr.duration)
	}
}

func TestParseProbeResponse_DNSError(t *testing.T) {
	pr := parseProbeResponse(dnsFailureProbeResponse)
	if pr.success {
		t.Error("expected success=false")
	}
	if pr.failureMode != "dns" {
		t.Errorf("expected failureMode='dns', got %q", pr.failureMode)
	}
	if !strings.Contains(pr.failureDetail, "no such host") {
		t.Errorf("expected failureDetail to contain 'no such host', got %q", pr.failureDetail)
	}
}

func TestParseProbeResponse_Timeout(t *testing.T) {
	pr := parseProbeResponse(timeoutProbeResponse)
	if pr.success {
		t.Error("expected success=false")
	}
	if pr.failureMode != "timeout" {
		t.Errorf("expected failureMode='timeout', got %q", pr.failureMode)
	}
	if !strings.Contains(pr.failureDetail, "context deadline exceeded") {
		t.Errorf("expected failureDetail to contain 'context deadline exceeded', got %q", pr.failureDetail)
	}
}

func TestParseProbeResponse_TLSError(t *testing.T) {
	pr := parseProbeResponse(tlsErrorProbeResponse)
	if pr.success {
		t.Error("expected success=false")
	}
	if pr.failureMode != "tls" {
		t.Errorf("expected failureMode='tls', got %q", pr.failureMode)
	}
	if !strings.Contains(pr.failureDetail, "x509") {
		t.Errorf("expected failureDetail to contain 'x509', got %q", pr.failureDetail)
	}
}

func TestParseProbeResponse_ConnectionRefused(t *testing.T) {
	pr := parseProbeResponse(connectionRefusedProbeResponse)
	if pr.success {
		t.Error("expected success=false")
	}
	if pr.failureMode != "connection_refused" {
		t.Errorf("expected failureMode='connection_refused', got %q", pr.failureMode)
	}
	if !strings.Contains(pr.failureDetail, "connection refused") {
		t.Errorf("expected failureDetail to contain 'connection refused', got %q", pr.failureDetail)
	}
}

func TestParseProbeResponse_ServerError(t *testing.T) {
	pr := parseProbeResponse(serverErrorProbeResponse)
	if pr.success {
		t.Error("expected success=false")
	}
	if pr.failureMode != "server_error" {
		t.Errorf("expected failureMode='server_error', got %q", pr.failureMode)
	}
	if pr.httpStatus != 503 {
		t.Errorf("expected httpStatus=503, got %d", pr.httpStatus)
	}
}

func TestParseProbeResponse_UnknownFailure(t *testing.T) {
	pr := parseProbeResponse(unknownFailureProbeResponse)
	if pr.success {
		t.Error("expected success=false")
	}
	if pr.failureMode != "unknown" {
		t.Errorf("expected failureMode='unknown', got %q", pr.failureMode)
	}
}

func TestParseProbeResponse_EmptyResponse(t *testing.T) {
	pr := parseProbeResponse("")
	if pr.success {
		t.Error("expected success=false for empty response")
	}
	if pr.failureMode != "unknown" {
		t.Errorf("expected failureMode='unknown' for empty response, got %q", pr.failureMode)
	}
}

// checkBlackboxProbe unit tests

func TestCheckBlackboxProbe_Success(t *testing.T) {
	cluster := newTestCluster("test-cluster", "10.0.0.0/16", "https://console.test.example.com")
	k8sClient := newFakeClient()
	notes := newTestNotes()
	inv := &Investigation{blackboxProber: healthyBlackboxProber()}

	r := &investigation.Resources{
		Cluster:    cluster,
		K8sClient:  k8sClient,
		RestConfig: testRestConfig(),
	}

	inv.checkBlackboxProbe(context.Background(), r, notes)

	output := notes.String()
	if !strings.Contains(output, "probe succeeded") {
		t.Errorf("expected 'probe succeeded' in notes, got: %s", output)
	}
	if !strings.Contains(output, "HTTP 200") {
		t.Errorf("expected 'HTTP 200' in notes, got: %s", output)
	}
}

func TestCheckBlackboxProbe_DNSFailure(t *testing.T) {
	cluster := newTestCluster("test-cluster", "10.0.0.0/16", "https://console.test.example.com")
	k8sClient := newFakeClient()
	notes := newTestNotes()
	inv := &Investigation{blackboxProber: &mockBlackboxProber{output: dnsFailureProbeResponse}}

	r := &investigation.Resources{
		Cluster:    cluster,
		K8sClient:  k8sClient,
		RestConfig: testRestConfig(),
	}

	inv.checkBlackboxProbe(context.Background(), r, notes)

	output := notes.String()
	if !strings.Contains(output, "probe FAILED") {
		t.Errorf("expected 'probe FAILED' in notes, got: %s", output)
	}
	if !strings.Contains(output, "dns") {
		t.Errorf("expected 'dns' in notes, got: %s", output)
	}
}

func TestCheckBlackboxProbe_ProberError(t *testing.T) {
	cluster := newTestCluster("test-cluster", "10.0.0.0/16", "https://console.test.example.com")
	k8sClient := newFakeClient()
	notes := newTestNotes()
	inv := &Investigation{blackboxProber: &mockBlackboxProber{err: fmt.Errorf("service not found")}}

	r := &investigation.Resources{
		Cluster:    cluster,
		K8sClient:  k8sClient,
		RestConfig: testRestConfig(),
	}

	inv.checkBlackboxProbe(context.Background(), r, notes)

	output := notes.String()
	if !strings.Contains(output, "failed to query blackbox exporter") {
		t.Errorf("expected 'failed to query blackbox exporter' in notes, got: %s", output)
	}
}

func TestCheckBlackboxProbe_EmptyConsoleURL(t *testing.T) {
	cluster := newTestCluster("test-cluster", "10.0.0.0/16", "")
	k8sClient := newFakeClient()
	notes := newTestNotes()
	inv := &Investigation{blackboxProber: healthyBlackboxProber()}

	r := &investigation.Resources{
		Cluster:    cluster,
		K8sClient:  k8sClient,
		RestConfig: testRestConfig(),
	}

	inv.checkBlackboxProbe(context.Background(), r, notes)

	output := notes.String()
	if !strings.Contains(output, "unable to determine console URL") {
		t.Errorf("expected 'unable to determine console URL' in notes, got: %s", output)
	}
}

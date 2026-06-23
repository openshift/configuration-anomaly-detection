package consoleerrorbudgetburn

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	ec2v2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	cmv1 "github.com/openshift-online/ocm-sdk-go/clustersmgmt/v1"
	operatorv1 "github.com/openshift/api/operator/v1"
	"github.com/openshift/configuration-anomaly-detection/pkg/aws"
	awsmock "github.com/openshift/configuration-anomaly-detection/pkg/aws/mock"
	"github.com/openshift/configuration-anomaly-detection/pkg/backplane"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/investigation"
	k8sclient "github.com/openshift/configuration-anomaly-detection/pkg/k8s"
	"github.com/openshift/configuration-anomaly-detection/pkg/networkverifier"
	"github.com/openshift/configuration-anomaly-detection/pkg/notewriter"
	"github.com/openshift/configuration-anomaly-detection/pkg/ocm"
	hivev1 "github.com/openshift/hive/apis/hive/v1"
	"go.uber.org/mock/gomock"
	"gotest.tools/v3/assert"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

const (
	actionSilence   = "silence_incident"
	actionEscalate  = "escalate_incident"
	failModeUnknown = "unknown"
	lbTypeNLB       = "NLB"
	lbTypeClassic   = "Classic"
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

// newAWSTestClusterWithDNS creates a test cluster with AWS provider, DNS, InfraID, and optional PrivateLink.
func newAWSTestClusterWithDNS(id, machineCIDR, consoleURL, domainPrefix, baseDomain string, privateLink bool) *cmv1.Cluster {
	builder := cmv1.NewCluster().
		ID(id).
		InfraID(id + "-infra").
		Network(cmv1.NewNetwork().MachineCIDR(machineCIDR)).
		CloudProvider(cmv1.NewCloudProvider().ID("aws")).
		DomainPrefix(domainPrefix).
		DNS(cmv1.NewDNS().BaseDomain(baseDomain)).
		AWS(cmv1.NewAWS().PrivateLink(privateLink))
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

var testServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
	http.Error(w, "not found", http.StatusNotFound)
}))

// testRestConfig returns a dummy backplane.RestConfig for tests that need r.RestConfig to be set.
func testRestConfig() *backplane.RestConfig {
	return &backplane.RestConfig{Config: rest.Config{Host: testServer.URL}}
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

// mockProbeHistoryChecker implements probeHistoryChecker for testing.
type mockProbeHistoryChecker struct {
	output string
	err    error
}

func (m *mockProbeHistoryChecker) queryProbeHistory(_ context.Context, _ k8sclient.Client, _ *rest.Config, _ string) (string, error) {
	return m.output, m.err
}

func noopProbeHistoryChecker() *mockProbeHistoryChecker {
	return &mockProbeHistoryChecker{output: allSucceedingHistoryResponse}
}

const (
	allSucceedingHistoryResponse       = `{"data":{"result":[{"values":[[1700000000,"1"],[1700000060,"1"],[1700000120,"1"]]}]}}`
	persistentFailureHistoryResponse   = `{"data":{"result":[{"values":[[1700000000,"0"],[1700000060,"0"],[1700000120,"0"]]}]}}`
	intermittentFailureHistoryResponse = `{"data":{"result":[{"values":[[1700000000,"1"],[1700000060,"0"],[1700000120,"1"],[1700000180,"0"]]}]}}`
	emptyHistoryResponse               = `{"data":{"result":[]}}`
)

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

// checkProbeHistory unit tests

func TestCheckProbeHistory_Persistent(t *testing.T) {
	notes := newTestNotes()
	inv := &Investigation{probeHistoryCheck: &mockProbeHistoryChecker{output: persistentFailureHistoryResponse}}
	r := &investigation.Resources{RestConfig: testRestConfig(), K8sClient: newFakeClient()}

	inv.checkProbeHistory(context.Background(), r, "https://console.test.example.com", notes)

	output := notes.String()
	if !strings.Contains(output, "consistently failing") {
		t.Errorf("expected persistent failure message, got: %s", output)
	}
	if !strings.Contains(output, "3 data points") {
		t.Errorf("expected '3 data points' in notes, got: %s", output)
	}
}

func TestCheckProbeHistory_Intermittent(t *testing.T) {
	notes := newTestNotes()
	inv := &Investigation{probeHistoryCheck: &mockProbeHistoryChecker{output: intermittentFailureHistoryResponse}}
	r := &investigation.Resources{RestConfig: testRestConfig(), K8sClient: newFakeClient()}

	inv.checkProbeHistory(context.Background(), r, "https://console.test.example.com", notes)

	output := notes.String()
	if !strings.Contains(output, "intermittently failing") {
		t.Errorf("expected intermittent failure message, got: %s", output)
	}
	if !strings.Contains(output, "2/4") {
		t.Errorf("expected '2/4' failure count in notes, got: %s", output)
	}
}

func TestCheckProbeHistory_AllSucceeding(t *testing.T) {
	notes := newTestNotes()
	inv := &Investigation{probeHistoryCheck: &mockProbeHistoryChecker{output: allSucceedingHistoryResponse}}
	r := &investigation.Resources{RestConfig: testRestConfig(), K8sClient: newFakeClient()}

	inv.checkProbeHistory(context.Background(), r, "https://console.test.example.com", notes)

	output := notes.String()
	if !strings.Contains(output, "succeeding for all") {
		t.Errorf("expected all-succeeding message, got: %s", output)
	}
	if !strings.Contains(output, "3 data points") {
		t.Errorf("expected '3 data points' in notes, got: %s", output)
	}
}

func TestCheckProbeHistory_NoData(t *testing.T) {
	notes := newTestNotes()
	inv := &Investigation{probeHistoryCheck: &mockProbeHistoryChecker{output: emptyHistoryResponse}}
	r := &investigation.Resources{RestConfig: testRestConfig(), K8sClient: newFakeClient()}

	inv.checkProbeHistory(context.Background(), r, "https://console.test.example.com", notes)

	if !strings.Contains(notes.String(), "no probe_success data found") {
		t.Errorf("expected no-data warning, got: %s", notes.String())
	}
}

func TestCheckProbeHistory_QueryFails(t *testing.T) {
	notes := newTestNotes()
	inv := &Investigation{probeHistoryCheck: &mockProbeHistoryChecker{err: fmt.Errorf("exec timeout")}}
	r := &investigation.Resources{RestConfig: testRestConfig(), K8sClient: newFakeClient()}

	inv.checkProbeHistory(context.Background(), r, "https://console.test.example.com", notes)

	if !strings.Contains(notes.String(), "unable to query Prometheus") {
		t.Errorf("expected exec error warning, got: %s", notes.String())
	}
}

func TestCheckProbeHistory_BadJSON(t *testing.T) {
	notes := newTestNotes()
	inv := &Investigation{probeHistoryCheck: &mockProbeHistoryChecker{output: "not json"}}
	r := &investigation.Resources{RestConfig: testRestConfig(), K8sClient: newFakeClient()}

	inv.checkProbeHistory(context.Background(), r, "https://console.test.example.com", notes)

	if !strings.Contains(notes.String(), "failed to parse Prometheus response") {
		t.Errorf("expected parse error warning, got: %s", notes.String())
	}
}

// checkPodHealth unit tests (Router)

var (
	routerMatchLabels  = client.MatchingLabels{"ingresscontroller.operator.openshift.io/deployment-ingresscontroller": "default"}
	consoleMatchLabels = client.MatchingLabels{"app": "console", "component": "ui"}
)

func newRouterPod(name string, phase corev1.PodPhase, containers []corev1.ContainerStatus) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "openshift-ingress",
			Labels:    map[string]string{"ingresscontroller.operator.openshift.io/deployment-ingresscontroller": "default"},
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

	inv.checkPodHealth(context.Background(), k8sClient, "openshift-ingress", "Router", routerMatchLabels, notes)

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

	inv.checkPodHealth(context.Background(), k8sClient, "openshift-ingress", "Router", routerMatchLabels, notes)

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

	inv.checkPodHealth(context.Background(), k8sClient, "openshift-ingress", "Router", routerMatchLabels, notes)

	output := notes.String()
	if !strings.Contains(output, "not ready") {
		t.Errorf("expected 'not ready' in notes, got: %s", output)
	}
}

func TestCheckPodHealth_Router_NoPods(t *testing.T) {
	k8sClient := newFakeClient()
	notes := newTestNotes()
	inv := &Investigation{}

	inv.checkPodHealth(context.Background(), k8sClient, "openshift-ingress", "Router", routerMatchLabels, notes)

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
		LastTimestamp:  metav1.NewTime(time.Now().Add(-5 * time.Minute)),
	}
	k8sClient := newFakeClient(pod, event)
	notes := newTestNotes()
	inv := &Investigation{}

	inv.checkPodHealth(context.Background(), k8sClient, "openshift-ingress", "Router", routerMatchLabels, notes)

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

	inv.checkPodHealth(context.Background(), k8sClient, "openshift-ingress", "Router", routerMatchLabels, notes)

	output := notes.String()
	if !strings.Contains(output, "5 restarts") {
		t.Errorf("expected '5 restarts' in notes, got: %s", output)
	}
}

func TestCheckPodHealth_Router_AllUnhealthy_SuggestsRestart(t *testing.T) {
	pod1 := newRouterPod("router-default-abc", corev1.PodFailed, nil)
	pod2 := newRouterPod("router-default-def", corev1.PodRunning, []corev1.ContainerStatus{
		{Name: "router", Ready: false, RestartCount: 10, State: corev1.ContainerState{
			Waiting: &corev1.ContainerStateWaiting{Reason: "CrashLoopBackOff"},
		}},
	})
	k8sClient := newFakeClient(pod1, pod2)
	notes := newTestNotes()
	inv := &Investigation{}

	inv.checkPodHealth(context.Background(), k8sClient, "openshift-ingress", "Router", routerMatchLabels, notes)

	output := notes.String()
	if !strings.Contains(output, "no healthy router pods present") {
		t.Errorf("expected restart suggestion in notes, got: %s", output)
	}
	if !strings.Contains(output, "rollout restart deploy/router-default") {
		t.Errorf("expected rollout restart command in notes, got: %s", output)
	}
}

func TestCheckPodHealth_Router_SomeHealthy_NoRestartSuggestion(t *testing.T) {
	pod1 := newRouterPod("router-default-abc", corev1.PodRunning, []corev1.ContainerStatus{
		{Name: "router", Ready: true, RestartCount: 0},
	})
	pod2 := newRouterPod("router-default-def", corev1.PodFailed, nil)
	k8sClient := newFakeClient(pod1, pod2)
	notes := newTestNotes()
	inv := &Investigation{}

	inv.checkPodHealth(context.Background(), k8sClient, "openshift-ingress", "Router", routerMatchLabels, notes)

	output := notes.String()
	if strings.Contains(output, "no healthy router pods present") {
		t.Errorf("should not suggest restart when some pods are healthy, got: %s", output)
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
			Labels:    map[string]string{"app": "console", "component": "ui"},
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

	inv.checkPodHealth(context.Background(), k8sClient, "openshift-console", "Console", consoleMatchLabels, notes)

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

func nodeHealthResources(k8sClient k8sclient.Client) *investigation.Resources {
	return &investigation.Resources{
		K8sClient:  k8sClient,
		RestConfig: testRestConfig(),
	}
}

func TestCheckNodeHealth_AllHealthy(t *testing.T) {
	consolePod := newConsolePod("console-abc", "node-1")
	node := newTestNode("node-1", healthyNodeConditions(), false)
	k8sClient := newFakeClient(consolePod, node)
	notes := newTestNotes()
	inv := &Investigation{}

	inv.checkNodeHealth(context.Background(), nodeHealthResources(k8sClient), notes)

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

	inv.checkNodeHealth(context.Background(), nodeHealthResources(k8sClient), notes)

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

	inv.checkNodeHealth(context.Background(), nodeHealthResources(k8sClient), notes)

	output := notes.String()
	if !strings.Contains(output, "DiskPressure") {
		t.Errorf("expected 'DiskPressure' in notes, got: %s", output)
	}
}

func TestCheckNodeHealth_NoConsolePods(t *testing.T) {
	k8sClient := newFakeClient()
	notes := newTestNotes()
	inv := &Investigation{}

	inv.checkNodeHealth(context.Background(), nodeHealthResources(k8sClient), notes)

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

	inv.checkNodeHealth(context.Background(), nodeHealthResources(k8sClient), notes)

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

	inv.checkNodeHealth(context.Background(), nodeHealthResources(k8sClient), notes)

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

	inv.checkNodeHealth(context.Background(), nodeHealthResources(k8sClient), notes)

	output := notes.String()
	if !strings.Contains(output, "MemoryPressure") {
		t.Errorf("expected 'MemoryPressure' in notes, got: %s", output)
	}
	if !strings.Contains(output, "node-2") {
		t.Errorf("expected 'node-2' in notes, got: %s", output)
	}
}

func TestCheckNodeHealth_MetricsUnavailable(t *testing.T) {
	consolePod := newConsolePod("console-abc", "node-1")
	node := newTestNode("node-1", healthyNodeConditions(), false)
	k8sClient := newFakeClient(consolePod, node)
	notes := newTestNotes()
	inv := &Investigation{}

	inv.checkNodeHealth(context.Background(), nodeHealthResources(k8sClient), notes)

	output := notes.String()
	// Node health conditions should still be reported.
	if !strings.Contains(output, "1 node(s) running console pods are healthy") {
		t.Errorf("expected healthy node message, got: %s", output)
	}
	// Metrics API should fail gracefully.
	if !strings.Contains(output, "Node Utilization: unable to query metrics API") {
		t.Errorf("expected metrics API unavailable warning, got: %s", output)
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

	inv := &Investigation{consoleChecker: healthyConsoleChecker(), blackboxProber: healthyBlackboxProber(), probeHistoryCheck: noopProbeHistoryChecker()}
	result, err := inv.Run(rb)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should escalate (no root cause found), not silence
	hasSilence := false
	hasEscalate := false
	for _, a := range result.Actions {
		if a.Type() == actionSilence {
			hasSilence = true
		}
		if a.Type() == actionEscalate {
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

	inv := &Investigation{consoleChecker: healthyConsoleChecker(), blackboxProber: healthyBlackboxProber(), probeHistoryCheck: noopProbeHistoryChecker()}
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
		case actionSilence:
			hasSilence = true
		case actionEscalate:
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

	inv := &Investigation{consoleChecker: healthyConsoleChecker(), blackboxProber: healthyBlackboxProber(), probeHistoryCheck: noopProbeHistoryChecker()}
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
		case actionSilence:
			hasSilence = true
		case actionEscalate:
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
		if a.Type() == actionEscalate {
			hasEscalate = true
		}
	}
	if !hasEscalate {
		t.Error("expected escalate action for cluster access error")
	}
}

func TestRun_NonAWSCluster_SkipsAWSChecks(t *testing.T) {
	// Cluster with no CloudProvider set; AWS section should be skipped entirely.
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

	inv := &Investigation{consoleChecker: healthyConsoleChecker(), blackboxProber: healthyBlackboxProber(), probeHistoryCheck: noopProbeHistoryChecker()}
	result, err := inv.Run(rb)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	hasEscalate := false
	for _, a := range result.Actions {
		if a.Type() == actionEscalate {
			hasEscalate = true
		}
	}
	if !hasEscalate {
		t.Error("expected escalate action")
	}
}

func TestRun_AWSCluster_AWSChecksRun(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockAws := awsmock.NewMockClient(ctrl)

	// Route53 check expects: FindHostedZone (private + public), HasResourceRecordSet (private + public)
	mockAws.EXPECT().FindHostedZone(gomock.Any(), "msaary-test.4t01.s1.devshift.org", true).Return("Z1234PRIVATE", nil)
	mockAws.EXPECT().HasResourceRecordSet(gomock.Any(), "Z1234PRIVATE", "\\052.apps.msaary-test.4t01.s1.devshift.org.", "A").Return(true, nil)
	mockAws.EXPECT().FindHostedZone(gomock.Any(), "4t01.s1.devshift.org", false).Return("Z5678PUBLIC", nil)
	mockAws.EXPECT().HasResourceRecordSet(gomock.Any(), "Z5678PUBLIC", "\\052.apps.msaary-test.4t01.s1.devshift.org.", "A").Return(true, nil)

	// DHCP check expects: GetVpcDhcpConfiguration (classic cluster, not HCP)
	mockAws.EXPECT().GetVpcDhcpConfiguration(gomock.Any(), "test-cluster-infra").Return([]string{"AmazonProvidedDNS"}, nil)

	// LB health check expects: FindCLBByDNSName (IC has no ProviderParameters → defaults to Classic)
	mockAws.EXPECT().FindCLBByDNSName(gomock.Any(), "test-elb-123456.us-east-1.elb.amazonaws.com").Return("test-elb", []string{"sg-clb"}, nil)
	mockAws.EXPECT().GetCLBInstanceHealth(gomock.Any(), "test-elb").Return([]aws.CLBInstanceHealth{
		{InstanceID: "i-001", State: "InService"},
		{InstanceID: "i-002", State: "InService"},
	}, nil)
	mockAws.EXPECT().GetSecurityGroupRules(gomock.Any(), []string{"sg-clb"}).
		Return([]ec2v2types.SecurityGroup{testSGAllowTCP443("sg-clb")}, nil)

	ic := newDefaultIngressController([]operatorv1.CIDR{"10.0.0.0/8"})
	dns := newDefaultDNS([]operatorv1.Upstream{{Type: operatorv1.SystemResolveConfType}})
	routerPod := newRouterPod("router-default-abc", corev1.PodRunning, []corev1.ContainerStatus{
		{Name: "router", Ready: true, RestartCount: 0},
	})
	routerSvc := newRouterService("test-elb-123456.us-east-1.elb.amazonaws.com")
	consolePod := newConsolePod("console-abc", "node-1")
	node := newTestNode("node-1", healthyNodeConditions(), false)
	k8sClient := newFakeClient(ic, dns, routerPod, routerSvc, consolePod, node)
	cluster := newAWSTestClusterWithDNS("test-cluster", "10.0.0.0/16",
		"https://console.test.example.com", "msaary-test", "4t01.s1.devshift.org", false)

	rb := &investigation.ResourceBuilderMock{
		Resources: &investigation.Resources{
			Cluster:           cluster,
			K8sClient:         k8sClient,
			AwsClient:         mockAws,
			IsHCP:             false,
			RestConfig:        testRestConfig(),
			ClusterDeployment: &hivev1.ClusterDeployment{},
		},
	}

	inv := &Investigation{
		consoleChecker:    healthyConsoleChecker(),
		blackboxProber:    healthyBlackboxProber(),
		probeHistoryCheck: noopProbeHistoryChecker(),
		egressVerifier:    successEgressVerifier(),
	}
	result, err := inv.Run(rb)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	hasEscalate := false
	for _, a := range result.Actions {
		if a.Type() == actionEscalate {
			hasEscalate = true
		}
	}
	if !hasEscalate {
		t.Error("expected escalate action")
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
	if pr.failureMode != failModeUnknown {
		t.Errorf("expected failureMode='unknown', got %q", pr.failureMode)
	}
}

func TestParseProbeResponse_EmptyResponse(t *testing.T) {
	pr := parseProbeResponse("")
	if pr.success {
		t.Error("expected success=false for empty response")
	}
	if pr.failureMode != failModeUnknown {
		t.Errorf("expected failureMode='unknown' for empty response, got %q", pr.failureMode)
	}
}

// checkBlackboxProbe unit tests

func TestCheckBlackboxProbe_Success(t *testing.T) {
	cluster := newTestCluster("test-cluster", "10.0.0.0/16", "https://console.test.example.com")
	k8sClient := newFakeClient()
	notes := newTestNotes()
	inv := &Investigation{blackboxProber: healthyBlackboxProber(), probeHistoryCheck: noopProbeHistoryChecker()}

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
	inv := &Investigation{blackboxProber: &mockBlackboxProber{output: dnsFailureProbeResponse}, probeHistoryCheck: noopProbeHistoryChecker()}

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

// checkRoute53DNS unit tests

func TestCheckRoute53DNS_AllRecordsExist(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockAws := awsmock.NewMockClient(ctrl)

	mockAws.EXPECT().FindHostedZone(gomock.Any(), "myprefix.example.com", true).Return("ZPRIVATE", nil)
	mockAws.EXPECT().HasResourceRecordSet(gomock.Any(), "ZPRIVATE", "\\052.apps.myprefix.example.com.", "A").Return(true, nil)
	mockAws.EXPECT().FindHostedZone(gomock.Any(), "example.com", false).Return("ZPUBLIC", nil)
	mockAws.EXPECT().HasResourceRecordSet(gomock.Any(), "ZPUBLIC", "\\052.apps.myprefix.example.com.", "A").Return(true, nil)

	cluster := newAWSTestClusterWithDNS("test-cluster", "10.0.0.0/16", "", "myprefix", "example.com", false)
	notes := newTestNotes()
	inv := &Investigation{}

	r := &investigation.Resources{Cluster: cluster, AwsClient: mockAws}
	result := inv.checkRoute53DNS(context.Background(), r, notes)

	if result {
		t.Error("expected false (no missing records)")
	}
	output := notes.String()
	if !strings.Contains(output, "verified in private and public hosted zones") {
		t.Errorf("expected success message about both zones, got: %s", output)
	}
}

func TestCheckRoute53DNS_MissingPrivateRecord(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockAws := awsmock.NewMockClient(ctrl)

	mockAws.EXPECT().FindHostedZone(gomock.Any(), "myprefix.example.com", true).Return("ZPRIVATE", nil)
	mockAws.EXPECT().HasResourceRecordSet(gomock.Any(), "ZPRIVATE", "\\052.apps.myprefix.example.com.", "A").Return(false, nil)
	// Public zone is still checked (both zones are evaluated before reporting).
	mockAws.EXPECT().FindHostedZone(gomock.Any(), "example.com", false).Return("ZPUBLIC", nil)
	mockAws.EXPECT().HasResourceRecordSet(gomock.Any(), "ZPUBLIC", "\\052.apps.myprefix.example.com.", "A").Return(true, nil)

	cluster := newAWSTestClusterWithDNS("test-cluster", "10.0.0.0/16", "", "myprefix", "example.com", false)
	notes := newTestNotes()
	inv := &Investigation{}

	r := &investigation.Resources{Cluster: cluster, AwsClient: mockAws}
	result := inv.checkRoute53DNS(context.Background(), r, notes)

	if !result {
		t.Error("expected true (missing private record)")
	}
	output := notes.String()
	if !strings.Contains(output, "missing from private hosted zone") {
		t.Errorf("expected warning about missing private record, got: %s", output)
	}
}

func TestCheckRoute53DNS_MissingPublicRecord(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockAws := awsmock.NewMockClient(ctrl)

	mockAws.EXPECT().FindHostedZone(gomock.Any(), "myprefix.example.com", true).Return("ZPRIVATE", nil)
	mockAws.EXPECT().HasResourceRecordSet(gomock.Any(), "ZPRIVATE", "\\052.apps.myprefix.example.com.", "A").Return(true, nil)
	mockAws.EXPECT().FindHostedZone(gomock.Any(), "example.com", false).Return("ZPUBLIC", nil)
	mockAws.EXPECT().HasResourceRecordSet(gomock.Any(), "ZPUBLIC", "\\052.apps.myprefix.example.com.", "A").Return(false, nil)

	cluster := newAWSTestClusterWithDNS("test-cluster", "10.0.0.0/16", "", "myprefix", "example.com", false)
	notes := newTestNotes()
	inv := &Investigation{}

	r := &investigation.Resources{Cluster: cluster, AwsClient: mockAws}
	result := inv.checkRoute53DNS(context.Background(), r, notes)

	if !result {
		t.Error("expected true (missing public record)")
	}
	output := notes.String()
	if !strings.Contains(output, "missing from public hosted zone") {
		t.Errorf("expected warning about missing public record, got: %s", output)
	}
}

func TestCheckRoute53DNS_BothMissing(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockAws := awsmock.NewMockClient(ctrl)

	mockAws.EXPECT().FindHostedZone(gomock.Any(), "myprefix.example.com", true).Return("ZPRIVATE", nil)
	mockAws.EXPECT().HasResourceRecordSet(gomock.Any(), "ZPRIVATE", "\\052.apps.myprefix.example.com.", "A").Return(false, nil)
	mockAws.EXPECT().FindHostedZone(gomock.Any(), "example.com", false).Return("ZPUBLIC", nil)
	mockAws.EXPECT().HasResourceRecordSet(gomock.Any(), "ZPUBLIC", "\\052.apps.myprefix.example.com.", "A").Return(false, nil)

	cluster := newAWSTestClusterWithDNS("test-cluster", "10.0.0.0/16", "", "myprefix", "example.com", false)
	notes := newTestNotes()
	inv := &Investigation{}

	r := &investigation.Resources{Cluster: cluster, AwsClient: mockAws}
	result := inv.checkRoute53DNS(context.Background(), r, notes)

	if !result {
		t.Error("expected true (both records missing)")
	}
	output := notes.String()
	if !strings.Contains(output, "BOTH private and public") {
		t.Errorf("expected warning about both zones missing, got: %s", output)
	}
}

func TestCheckRoute53DNS_PrivateLink_SkipsPublic(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockAws := awsmock.NewMockClient(ctrl)

	// Only private zone should be checked... no public zone calls expected.
	mockAws.EXPECT().FindHostedZone(gomock.Any(), "myprefix.example.com", true).Return("ZPRIVATE", nil)
	mockAws.EXPECT().HasResourceRecordSet(gomock.Any(), "ZPRIVATE", "\\052.apps.myprefix.example.com.", "A").Return(true, nil)

	cluster := newAWSTestClusterWithDNS("test-cluster", "10.0.0.0/16", "", "myprefix", "example.com", true)
	notes := newTestNotes()
	inv := &Investigation{}

	r := &investigation.Resources{Cluster: cluster, AwsClient: mockAws}
	result := inv.checkRoute53DNS(context.Background(), r, notes)

	if result {
		t.Error("expected false (private record exists, public skipped)")
	}
	output := notes.String()
	if !strings.Contains(output, "verified in private hosted zone") {
		t.Errorf("expected success message about private zone only, got: %s", output)
	}
}

func TestCheckRoute53DNS_ZoneNotFound(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockAws := awsmock.NewMockClient(ctrl)

	mockAws.EXPECT().FindHostedZone(gomock.Any(), "myprefix.example.com", true).Return("", nil)

	cluster := newAWSTestClusterWithDNS("test-cluster", "10.0.0.0/16", "", "myprefix", "example.com", false)
	notes := newTestNotes()
	inv := &Investigation{}

	r := &investigation.Resources{Cluster: cluster, AwsClient: mockAws}
	result := inv.checkRoute53DNS(context.Background(), r, notes)

	if result {
		t.Error("expected false (zone not found is not a definitive missing-record finding)")
	}
	output := notes.String()
	if !strings.Contains(output, "no private hosted zone found") {
		t.Errorf("expected warning about zone not found, got: %s", output)
	}
}

func TestCheckRoute53DNS_APIError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockAws := awsmock.NewMockClient(ctrl)

	mockAws.EXPECT().FindHostedZone(gomock.Any(), "myprefix.example.com", true).Return("", fmt.Errorf("access denied"))

	cluster := newAWSTestClusterWithDNS("test-cluster", "10.0.0.0/16", "", "myprefix", "example.com", false)
	notes := newTestNotes()
	inv := &Investigation{}

	r := &investigation.Resources{Cluster: cluster, AwsClient: mockAws}
	result := inv.checkRoute53DNS(context.Background(), r, notes)

	if result {
		t.Error("expected false (API error is not a definitive finding)")
	}
	output := notes.String()
	if !strings.Contains(output, "error looking up private hosted zone") {
		t.Errorf("expected warning about API error, got: %s", output)
	}
}

func TestCheckRoute53DNS_EmptyDomain(t *testing.T) {
	// Cluster with empty DomainPrefix — should warn and return false, no AWS calls.
	cluster := newAWSTestClusterWithDNS("test-cluster", "10.0.0.0/16", "", "", "example.com", false)
	notes := newTestNotes()
	inv := &Investigation{}

	r := &investigation.Resources{Cluster: cluster}
	result := inv.checkRoute53DNS(context.Background(), r, notes)

	if result {
		t.Error("expected false (empty domain)")
	}
	output := notes.String()
	if !strings.Contains(output, "unable to determine cluster domain") {
		t.Errorf("expected warning about missing domain info, got: %s", output)
	}
}

// checkDHCPOptions unit tests

func TestCheckDHCPOptions_AmazonDNSOnly(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockAws := awsmock.NewMockClient(ctrl)

	mockAws.EXPECT().GetVpcDhcpConfiguration(gomock.Any(), "test-cluster-infra").Return([]string{"AmazonProvidedDNS"}, nil)

	cluster := newAWSTestClusterWithDNS("test-cluster", "10.0.0.0/16", "", "myprefix", "example.com", false)
	notes := newTestNotes()
	inv := &Investigation{}

	r := &investigation.Resources{Cluster: cluster, AwsClient: mockAws}
	inv.checkDHCPOptions(context.Background(), r, notes)

	output := notes.String()
	if !strings.Contains(output, "DHCP: VPC DHCP option set uses AmazonProvidedDNS") {
		t.Errorf("expected success message, got: %s", output)
	}
	if strings.Contains(output, "⚠️") {
		t.Errorf("expected no warning, got: %s", output)
	}
}

func TestCheckDHCPOptions_CustomDNSOnly(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockAws := awsmock.NewMockClient(ctrl)

	mockAws.EXPECT().GetVpcDhcpConfiguration(gomock.Any(), "test-cluster-infra").Return([]string{"10.0.0.2", "10.0.0.3"}, nil)

	cluster := newAWSTestClusterWithDNS("test-cluster", "10.0.0.0/16", "", "myprefix", "example.com", false)
	notes := newTestNotes()
	inv := &Investigation{}

	r := &investigation.Resources{Cluster: cluster, AwsClient: mockAws}
	inv.checkDHCPOptions(context.Background(), r, notes)

	output := notes.String()
	if !strings.Contains(output, "custom DNS servers") {
		t.Errorf("expected warning about custom DNS servers, got: %s", output)
	}
	if !strings.Contains(output, "⚠️") {
		t.Errorf("expected warning emoji, got: %s", output)
	}
}

func TestCheckDHCPOptions_MixedDNS(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockAws := awsmock.NewMockClient(ctrl)

	mockAws.EXPECT().GetVpcDhcpConfiguration(gomock.Any(), "test-cluster-infra").Return([]string{"AmazonProvidedDNS", "10.0.0.2"}, nil)

	cluster := newAWSTestClusterWithDNS("test-cluster", "10.0.0.0/16", "", "myprefix", "example.com", false)
	notes := newTestNotes()
	inv := &Investigation{}

	r := &investigation.Resources{Cluster: cluster, AwsClient: mockAws}
	inv.checkDHCPOptions(context.Background(), r, notes)

	output := notes.String()
	if !strings.Contains(output, "AmazonProvidedDNS alongside custom servers") {
		t.Errorf("expected success message about mixed DNS, got: %s", output)
	}
	if !strings.Contains(output, "✅") {
		t.Errorf("expected success emoji (AmazonProvidedDNS is present), got: %s", output)
	}
}

func TestCheckDHCPOptions_DefaultDHCPNoServersEntry(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockAws := awsmock.NewMockClient(ctrl)

	mockAws.EXPECT().GetVpcDhcpConfiguration(gomock.Any(), "test-cluster-infra").Return([]string{}, nil)

	cluster := newAWSTestClusterWithDNS("test-cluster", "10.0.0.0/16", "", "myprefix", "example.com", false)
	notes := newTestNotes()
	inv := &Investigation{}

	r := &investigation.Resources{Cluster: cluster, AwsClient: mockAws}
	inv.checkDHCPOptions(context.Background(), r, notes)

	output := notes.String()
	if !strings.Contains(output, "AWS default DNS") {
		t.Errorf("expected success message about AWS default DNS, got: %s", output)
	}
}

func TestCheckDHCPOptions_EmptyInfraID(t *testing.T) {
	cluster := newTestCluster("test-cluster", "10.0.0.0/16", "")
	notes := newTestNotes()
	inv := &Investigation{}

	r := &investigation.Resources{Cluster: cluster}
	inv.checkDHCPOptions(context.Background(), r, notes)

	output := notes.String()
	if !strings.Contains(output, "unable to determine cluster infrastructure ID") {
		t.Errorf("expected warning about missing infra ID, got: %s", output)
	}
}

func TestCheckDHCPOptions_APIError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockAws := awsmock.NewMockClient(ctrl)

	mockAws.EXPECT().GetVpcDhcpConfiguration(gomock.Any(), "test-cluster-infra").Return(nil, fmt.Errorf("access denied"))

	cluster := newAWSTestClusterWithDNS("test-cluster", "10.0.0.0/16", "", "myprefix", "example.com", false)
	notes := newTestNotes()
	inv := &Investigation{}

	r := &investigation.Resources{Cluster: cluster, AwsClient: mockAws}
	inv.checkDHCPOptions(context.Background(), r, notes)

	output := notes.String()
	if !strings.Contains(output, "unable to check VPC DHCP options") {
		t.Errorf("expected warning about API error, got: %s", output)
	}
	if !strings.Contains(output, "access denied") {
		t.Errorf("expected error message to include 'access denied', got: %s", output)
	}
}

func TestCheckDHCPOptions_NoVPCFound(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockAws := awsmock.NewMockClient(ctrl)

	mockAws.EXPECT().GetVpcDhcpConfiguration(gomock.Any(), "test-cluster-infra").Return(nil, fmt.Errorf("no VPC found with kubernetes.io/cluster/test-cluster-infra tag"))

	cluster := newAWSTestClusterWithDNS("test-cluster", "10.0.0.0/16", "", "myprefix", "example.com", false)
	notes := newTestNotes()
	inv := &Investigation{}

	r := &investigation.Resources{Cluster: cluster, AwsClient: mockAws}
	inv.checkDHCPOptions(context.Background(), r, notes)

	output := notes.String()
	if !strings.Contains(output, "unable to check VPC DHCP options") {
		t.Errorf("expected warning about DHCP check failure, got: %s", output)
	}
	if !strings.Contains(output, "no VPC found") {
		t.Errorf("expected error message about no VPC, got: %s", output)
	}
}

// newRouterService creates a router-default Service in openshift-ingress with the given LB hostname.
func newRouterService(hostname string) *corev1.Service {
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "router-default",
			Namespace: "openshift-ingress",
		},
		Spec: corev1.ServiceSpec{
			Type: corev1.ServiceTypeLoadBalancer,
		},
	}
	if hostname != "" {
		svc.Status = corev1.ServiceStatus{
			LoadBalancer: corev1.LoadBalancerStatus{
				Ingress: []corev1.LoadBalancerIngress{
					{Hostname: hostname},
				},
			},
		}
	}
	return svc
}

// newNLBIngressController creates an IngressController with NLB type.
func newNLBIngressController(allowedSourceRanges []operatorv1.CIDR) *operatorv1.IngressController {
	ic := newDefaultIngressController(allowedSourceRanges)
	if ic.Spec.EndpointPublishingStrategy == nil {
		ic.Spec.EndpointPublishingStrategy = &operatorv1.EndpointPublishingStrategy{}
	}
	ic.Spec.EndpointPublishingStrategy.LoadBalancer = &operatorv1.LoadBalancerStrategy{
		ProviderParameters: &operatorv1.ProviderLoadBalancerParameters{
			Type: operatorv1.AWSLoadBalancerProvider,
			AWS: &operatorv1.AWSLoadBalancerParameters{
				Type: operatorv1.AWSNetworkLoadBalancer,
			},
		},
	}
	if allowedSourceRanges != nil {
		ic.Spec.EndpointPublishingStrategy.LoadBalancer.AllowedSourceRanges = allowedSourceRanges
	}
	return ic
}

// testSGAllowTCP443 creates a SecurityGroup that allows TCP 443 from 0.0.0.0/0.
func testSGAllowTCP443(sgID string) ec2v2types.SecurityGroup {
	return ec2v2types.SecurityGroup{
		GroupId: &sgID,
		IpPermissions: []ec2v2types.IpPermission{
			{
				IpProtocol: strPtr("tcp"),
				FromPort:   int32Ptr(443),
				ToPort:     int32Ptr(443),
				IpRanges:   []ec2v2types.IpRange{{CidrIp: strPtr("0.0.0.0/0")}},
			},
		},
	}
}

// testSGAllowNodePorts creates a SecurityGroup that allows TCP 30000-32767 from 0.0.0.0/0.
func testSGAllowNodePorts(sgID string) ec2v2types.SecurityGroup {
	return ec2v2types.SecurityGroup{
		GroupId: &sgID,
		IpPermissions: []ec2v2types.IpPermission{
			{
				IpProtocol: strPtr("tcp"),
				FromPort:   int32Ptr(30000),
				ToPort:     int32Ptr(32767),
				IpRanges:   []ec2v2types.IpRange{{CidrIp: strPtr("0.0.0.0/0")}},
			},
		},
	}
}

func strPtr(s string) *string { return &s }
func int32Ptr(i int32) *int32 { return &i }

// determineLBType unit tests

func TestDetermineLBType_NLB(t *testing.T) {
	ic := &operatorv1.IngressController{}
	ic.Spec.EndpointPublishingStrategy = &operatorv1.EndpointPublishingStrategy{
		LoadBalancer: &operatorv1.LoadBalancerStrategy{
			ProviderParameters: &operatorv1.ProviderLoadBalancerParameters{
				Type: operatorv1.AWSLoadBalancerProvider,
				AWS: &operatorv1.AWSLoadBalancerParameters{
					Type: operatorv1.AWSNetworkLoadBalancer,
				},
			},
		},
	}
	if determineLBType(ic) != lbTypeNLB {
		t.Errorf("expected NLB, got %s", determineLBType(ic))
	}
}

func TestDetermineLBType_Classic(t *testing.T) {
	ic := &operatorv1.IngressController{}
	ic.Spec.EndpointPublishingStrategy = &operatorv1.EndpointPublishingStrategy{
		LoadBalancer: &operatorv1.LoadBalancerStrategy{
			ProviderParameters: &operatorv1.ProviderLoadBalancerParameters{
				Type: operatorv1.AWSLoadBalancerProvider,
				AWS: &operatorv1.AWSLoadBalancerParameters{
					Type: operatorv1.AWSClassicLoadBalancer,
				},
			},
		},
	}
	if determineLBType(ic) != lbTypeClassic {
		t.Errorf("expected Classic, got %s", determineLBType(ic))
	}
}

func TestDetermineLBType_NilProviderParams(t *testing.T) {
	ic := newDefaultIngressController(nil)
	if determineLBType(ic) != lbTypeClassic {
		t.Errorf("expected Classic (default), got %s", determineLBType(ic))
	}
}

func TestDetermineLBType_StatusFallback(t *testing.T) {
	ic := &operatorv1.IngressController{}
	ic.Status.EndpointPublishingStrategy = &operatorv1.EndpointPublishingStrategy{
		LoadBalancer: &operatorv1.LoadBalancerStrategy{
			ProviderParameters: &operatorv1.ProviderLoadBalancerParameters{
				Type: operatorv1.AWSLoadBalancerProvider,
				AWS: &operatorv1.AWSLoadBalancerParameters{
					Type: operatorv1.AWSNetworkLoadBalancer,
				},
			},
		},
	}
	if determineLBType(ic) != lbTypeNLB {
		t.Errorf("expected NLB from status fallback, got %s", determineLBType(ic))
	}
}

// checkLoadBalancerHealth unit tests

func TestCheckLBHealth_NLB_AllHealthy(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockAws := awsmock.NewMockClient(ctrl)

	mockAws.EXPECT().FindNLBByDNSName(gomock.Any(), "test-nlb-abc123.elb.us-east-1.amazonaws.com").
		Return("arn:aws:elasticloadbalancing:us-east-1:123:loadbalancer/net/test-nlb/abc", "test-nlb", []string{}, nil)
	mockAws.EXPECT().GetNLBTargetHealth(gomock.Any(), "arn:aws:elasticloadbalancing:us-east-1:123:loadbalancer/net/test-nlb/abc").
		Return([]aws.NLBTargetHealth{
			{TargetID: "i-001", Port: 443, State: "healthy"},
			{TargetID: "i-002", Port: 443, State: "healthy"},
		}, nil)
	mockAws.EXPECT().GetInstanceSecurityGroupIDs(gomock.Any(), gomock.Any()).
		Return([]string{"sg-aaa"}, nil)
	mockAws.EXPECT().GetSecurityGroupRules(gomock.Any(), gomock.Any()).
		Return([]ec2v2types.SecurityGroup{testSGAllowNodePorts("sg-aaa")}, nil)

	ic := newNLBIngressController(nil)
	svc := newRouterService("test-nlb-abc123.elb.us-east-1.amazonaws.com")
	k8sClient := newFakeClient(ic, svc)
	cluster := newAWSTestClusterWithDNS("test", "10.0.0.0/16", "", "p", "e.com", false)
	notes := newTestNotes()
	inv := &Investigation{}

	r := &investigation.Resources{Cluster: cluster, K8sClient: k8sClient, AwsClient: mockAws}
	inv.checkLoadBalancerHealth(context.Background(), r, notes)

	output := notes.String()
	if !strings.Contains(output, "all 2 target(s) healthy") {
		t.Errorf("expected all healthy message, got: %s", output)
	}
}

func TestCheckLBHealth_NLB_UnhealthyTarget(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockAws := awsmock.NewMockClient(ctrl)

	mockAws.EXPECT().FindNLBByDNSName(gomock.Any(), "test-nlb-abc123.elb.us-east-1.amazonaws.com").
		Return("arn:nlb", "test-nlb", []string{}, nil)
	mockAws.EXPECT().GetNLBTargetHealth(gomock.Any(), "arn:nlb").
		Return([]aws.NLBTargetHealth{
			{TargetID: "i-001", Port: 443, State: "healthy"},
			{TargetID: "i-002", Port: 443, State: "unhealthy", Reason: "Target.FailedHealthChecks"},
		}, nil)
	mockAws.EXPECT().GetInstanceSecurityGroupIDs(gomock.Any(), gomock.Any()).
		Return([]string{"sg-aaa"}, nil)
	mockAws.EXPECT().GetSecurityGroupRules(gomock.Any(), gomock.Any()).
		Return([]ec2v2types.SecurityGroup{testSGAllowNodePorts("sg-aaa")}, nil)

	ic := newNLBIngressController(nil)
	svc := newRouterService("test-nlb-abc123.elb.us-east-1.amazonaws.com")
	k8sClient := newFakeClient(ic, svc)
	cluster := newAWSTestClusterWithDNS("test", "10.0.0.0/16", "", "p", "e.com", false)
	notes := newTestNotes()
	inv := &Investigation{}

	r := &investigation.Resources{Cluster: cluster, K8sClient: k8sClient, AwsClient: mockAws}
	inv.checkLoadBalancerHealth(context.Background(), r, notes)

	output := notes.String()
	if !strings.Contains(output, "1/2 target(s) unhealthy") {
		t.Errorf("expected unhealthy target message, got: %s", output)
	}
	if !strings.Contains(output, "i-002") {
		t.Errorf("expected unhealthy target ID, got: %s", output)
	}
}

func TestCheckLBHealth_CLB_AllInService(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockAws := awsmock.NewMockClient(ctrl)

	mockAws.EXPECT().FindCLBByDNSName(gomock.Any(), "test-clb-123456.us-east-1.elb.amazonaws.com").
		Return("test-clb", []string{"sg-clb"}, nil)
	mockAws.EXPECT().GetCLBInstanceHealth(gomock.Any(), "test-clb").
		Return([]aws.CLBInstanceHealth{
			{InstanceID: "i-001", State: "InService"},
			{InstanceID: "i-002", State: "InService"},
		}, nil)
	mockAws.EXPECT().GetSecurityGroupRules(gomock.Any(), []string{"sg-clb"}).
		Return([]ec2v2types.SecurityGroup{testSGAllowTCP443("sg-clb")}, nil)

	ic := newDefaultIngressController(nil) // no ProviderParameters → Classic
	svc := newRouterService("test-clb-123456.us-east-1.elb.amazonaws.com")
	k8sClient := newFakeClient(ic, svc)
	cluster := newAWSTestClusterWithDNS("test", "10.0.0.0/16", "", "p", "e.com", false)
	notes := newTestNotes()
	inv := &Investigation{}

	r := &investigation.Resources{Cluster: cluster, K8sClient: k8sClient, AwsClient: mockAws}
	inv.checkLoadBalancerHealth(context.Background(), r, notes)

	output := notes.String()
	if !strings.Contains(output, "all 2 instance(s) InService") {
		t.Errorf("expected all InService message, got: %s", output)
	}
}

func TestCheckLBHealth_CLB_OutOfService(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockAws := awsmock.NewMockClient(ctrl)

	mockAws.EXPECT().FindCLBByDNSName(gomock.Any(), "test-clb-123456.us-east-1.elb.amazonaws.com").
		Return("test-clb", []string{"sg-clb"}, nil)
	mockAws.EXPECT().GetCLBInstanceHealth(gomock.Any(), "test-clb").
		Return([]aws.CLBInstanceHealth{
			{InstanceID: "i-001", State: "InService"},
			{InstanceID: "i-002", State: "OutOfService", Description: "Instance has failed health checks"},
		}, nil)
	mockAws.EXPECT().GetSecurityGroupRules(gomock.Any(), []string{"sg-clb"}).
		Return([]ec2v2types.SecurityGroup{testSGAllowTCP443("sg-clb")}, nil)

	ic := newDefaultIngressController(nil)
	svc := newRouterService("test-clb-123456.us-east-1.elb.amazonaws.com")
	k8sClient := newFakeClient(ic, svc)
	cluster := newAWSTestClusterWithDNS("test", "10.0.0.0/16", "", "p", "e.com", false)
	notes := newTestNotes()
	inv := &Investigation{}

	r := &investigation.Resources{Cluster: cluster, K8sClient: k8sClient, AwsClient: mockAws}
	inv.checkLoadBalancerHealth(context.Background(), r, notes)

	output := notes.String()
	if !strings.Contains(output, "1/2 instance(s) not InService") {
		t.Errorf("expected OutOfService message, got: %s", output)
	}
	if !strings.Contains(output, "i-002") {
		t.Errorf("expected unhealthy instance ID, got: %s", output)
	}
}

func TestCheckLBHealth_NoHostname(t *testing.T) {
	ic := newDefaultIngressController(nil)
	svc := newRouterService("") // no hostname
	k8sClient := newFakeClient(ic, svc)
	cluster := newAWSTestClusterWithDNS("test", "10.0.0.0/16", "", "p", "e.com", false)
	notes := newTestNotes()
	inv := &Investigation{}

	r := &investigation.Resources{Cluster: cluster, K8sClient: k8sClient}
	inv.checkLoadBalancerHealth(context.Background(), r, notes)

	output := notes.String()
	if !strings.Contains(output, "no LoadBalancer hostname assigned") {
		t.Errorf("expected no hostname warning, got: %s", output)
	}
}

func TestCheckLBHealth_LBNotFound(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockAws := awsmock.NewMockClient(ctrl)

	mockAws.EXPECT().FindCLBByDNSName(gomock.Any(), "unknown-lb.us-east-1.elb.amazonaws.com").Return("", nil, nil)

	ic := newDefaultIngressController(nil)
	svc := newRouterService("unknown-lb.us-east-1.elb.amazonaws.com")
	k8sClient := newFakeClient(ic, svc)
	cluster := newAWSTestClusterWithDNS("test", "10.0.0.0/16", "", "p", "e.com", false)
	notes := newTestNotes()
	inv := &Investigation{}

	r := &investigation.Resources{Cluster: cluster, K8sClient: k8sClient, AwsClient: mockAws}
	inv.checkLoadBalancerHealth(context.Background(), r, notes)

	output := notes.String()
	if !strings.Contains(output, "no CLB found matching DNS name") {
		t.Errorf("expected LB not found warning, got: %s", output)
	}
}

func TestCheckLBHealth_APIError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockAws := awsmock.NewMockClient(ctrl)

	mockAws.EXPECT().FindCLBByDNSName(gomock.Any(), "test-clb.us-east-1.elb.amazonaws.com").
		Return("", nil, fmt.Errorf("access denied"))

	ic := newDefaultIngressController(nil)
	svc := newRouterService("test-clb.us-east-1.elb.amazonaws.com")
	k8sClient := newFakeClient(ic, svc)
	cluster := newAWSTestClusterWithDNS("test", "10.0.0.0/16", "", "p", "e.com", false)
	notes := newTestNotes()
	inv := &Investigation{}

	r := &investigation.Resources{Cluster: cluster, K8sClient: k8sClient, AwsClient: mockAws}
	inv.checkLoadBalancerHealth(context.Background(), r, notes)

	output := notes.String()
	if !strings.Contains(output, "failed to look up CLB") {
		t.Errorf("expected API error warning, got: %s", output)
	}
}

func TestCheckLBHealth_ICNotFound(t *testing.T) {
	// No IngressController in fake client.
	svc := newRouterService("test-lb.us-east-1.elb.amazonaws.com")
	k8sClient := newFakeClient(svc)
	cluster := newAWSTestClusterWithDNS("test", "10.0.0.0/16", "", "p", "e.com", false)
	notes := newTestNotes()
	inv := &Investigation{}

	r := &investigation.Resources{Cluster: cluster, K8sClient: k8sClient}
	inv.checkLoadBalancerHealth(context.Background(), r, notes)

	output := notes.String()
	if !strings.Contains(output, "failed to get default IngressController") {
		t.Errorf("expected IC not found warning, got: %s", output)
	}
}

func TestCheckLBHealth_NLB_NoTargets(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockAws := awsmock.NewMockClient(ctrl)

	mockAws.EXPECT().FindNLBByDNSName(gomock.Any(), "test-nlb.elb.us-east-1.amazonaws.com").
		Return("arn:nlb", "test-nlb", []string{}, nil)
	mockAws.EXPECT().GetNLBTargetHealth(gomock.Any(), "arn:nlb").
		Return([]aws.NLBTargetHealth{}, nil)

	ic := newNLBIngressController(nil)
	svc := newRouterService("test-nlb.elb.us-east-1.amazonaws.com")
	k8sClient := newFakeClient(ic, svc)
	cluster := newAWSTestClusterWithDNS("test", "10.0.0.0/16", "", "p", "e.com", false)
	notes := newTestNotes()
	inv := &Investigation{}

	r := &investigation.Resources{Cluster: cluster, K8sClient: k8sClient, AwsClient: mockAws}
	inv.checkLoadBalancerHealth(context.Background(), r, notes)

	output := notes.String()
	if !strings.Contains(output, "no registered targets") {
		t.Errorf("expected no targets warning, got: %s", output)
	}
}

func TestCheckLBHealth_CLB_DefaultType(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockAws := awsmock.NewMockClient(ctrl)

	// IC with nil ProviderParameters defaults to Classic — should call CLB APIs.
	mockAws.EXPECT().FindCLBByDNSName(gomock.Any(), "test-clb.us-east-1.elb.amazonaws.com").
		Return("test-clb", []string{"sg-clb"}, nil)
	mockAws.EXPECT().GetCLBInstanceHealth(gomock.Any(), "test-clb").
		Return([]aws.CLBInstanceHealth{
			{InstanceID: "i-001", State: "InService"},
		}, nil)
	mockAws.EXPECT().GetSecurityGroupRules(gomock.Any(), []string{"sg-clb"}).
		Return([]ec2v2types.SecurityGroup{testSGAllowTCP443("sg-clb")}, nil)

	ic := newDefaultIngressController(nil) // no ProviderParameters
	svc := newRouterService("test-clb.us-east-1.elb.amazonaws.com")
	k8sClient := newFakeClient(ic, svc)
	cluster := newAWSTestClusterWithDNS("test", "10.0.0.0/16", "", "p", "e.com", false)
	notes := newTestNotes()
	inv := &Investigation{}

	r := &investigation.Resources{Cluster: cluster, K8sClient: k8sClient, AwsClient: mockAws}
	inv.checkLoadBalancerHealth(context.Background(), r, notes)

	output := notes.String()
	if !strings.Contains(output, "CLB") {
		t.Errorf("expected CLB in output (default type), got: %s", output)
	}
	if !strings.Contains(output, "all 1 instance(s) InService") {
		t.Errorf("expected all InService, got: %s", output)
	}
}

// Securitygroup check tests

func TestCheckCLBHealth_SGAllowsTCP443(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockAws := awsmock.NewMockClient(ctrl)

	mockAws.EXPECT().FindCLBByDNSName(gomock.Any(), "test-clb.elb.amazonaws.com").Return("test-clb", []string{"sg-123"}, nil)
	mockAws.EXPECT().GetCLBInstanceHealth(gomock.Any(), "test-clb").Return([]aws.CLBInstanceHealth{
		{InstanceID: "i-001", State: "InService"},
	}, nil)
	mockAws.EXPECT().GetSecurityGroupRules(gomock.Any(), []string{"sg-123"}).
		Return([]ec2v2types.SecurityGroup{testSGAllowTCP443("sg-123")}, nil)

	ic := newDefaultIngressController(nil)
	svc := newRouterService("test-clb.elb.amazonaws.com")
	k8sClient := newFakeClient(ic, svc)
	cluster := newAWSTestClusterWithDNS("test", "10.0.0.0/16", "", "p", "e.com", false)
	notes := newTestNotes()
	inv := &Investigation{}

	r := &investigation.Resources{Cluster: cluster, K8sClient: k8sClient, AwsClient: mockAws}
	inv.checkLoadBalancerHealth(context.Background(), r, notes)

	output := notes.String()
	if !strings.Contains(output, "security group allows TCP 443 inbound") {
		t.Errorf("expected SG allows TCP 443 message, got: %s", output)
	}
}

func TestCheckCLBHealth_SGMissingTCP443(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockAws := awsmock.NewMockClient(ctrl)

	mockAws.EXPECT().FindCLBByDNSName(gomock.Any(), "test-clb.elb.amazonaws.com").Return("test-clb", []string{"sg-123"}, nil)
	mockAws.EXPECT().GetCLBInstanceHealth(gomock.Any(), "test-clb").Return([]aws.CLBInstanceHealth{
		{InstanceID: "i-001", State: "InService"},
	}, nil)
	// SG with UDP rule only; no TCP 443.
	mockAws.EXPECT().GetSecurityGroupRules(gomock.Any(), []string{"sg-123"}).
		Return([]ec2v2types.SecurityGroup{{
			GroupId: strPtr("sg-123"),
			IpPermissions: []ec2v2types.IpPermission{
				{
					IpProtocol: strPtr("udp"),
					FromPort:   int32Ptr(443),
					ToPort:     int32Ptr(443),
					IpRanges:   []ec2v2types.IpRange{{CidrIp: strPtr("0.0.0.0/0")}},
				},
			},
		}}, nil)

	ic := newDefaultIngressController(nil)
	svc := newRouterService("test-clb.elb.amazonaws.com")
	k8sClient := newFakeClient(ic, svc)
	cluster := newAWSTestClusterWithDNS("test", "10.0.0.0/16", "", "p", "e.com", false)
	notes := newTestNotes()
	inv := &Investigation{}

	r := &investigation.Resources{Cluster: cluster, K8sClient: k8sClient, AwsClient: mockAws}
	inv.checkLoadBalancerHealth(context.Background(), r, notes)

	output := notes.String()
	if !strings.Contains(output, "does not allow TCP 443 inbound") {
		t.Errorf("expected SG missing TCP 443 warning, got: %s", output)
	}
}

func TestCheckCLBHealth_NoSecurityGroups(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockAws := awsmock.NewMockClient(ctrl)

	mockAws.EXPECT().FindCLBByDNSName(gomock.Any(), "test-clb.elb.amazonaws.com").Return("test-clb", []string{}, nil)
	mockAws.EXPECT().GetCLBInstanceHealth(gomock.Any(), "test-clb").Return([]aws.CLBInstanceHealth{
		{InstanceID: "i-001", State: "InService"},
	}, nil)

	ic := newDefaultIngressController(nil)
	svc := newRouterService("test-clb.elb.amazonaws.com")
	k8sClient := newFakeClient(ic, svc)
	cluster := newAWSTestClusterWithDNS("test", "10.0.0.0/16", "", "p", "e.com", false)
	notes := newTestNotes()
	inv := &Investigation{}

	r := &investigation.Resources{Cluster: cluster, K8sClient: k8sClient, AwsClient: mockAws}
	inv.checkLoadBalancerHealth(context.Background(), r, notes)

	if !strings.Contains(notes.String(), "no security groups attached") {
		t.Errorf("expected no SGs warning, got: %s", notes.String())
	}
}

func TestCheckNLBHealth_UnexpectedSGs(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockAws := awsmock.NewMockClient(ctrl)

	mockAws.EXPECT().FindNLBByDNSName(gomock.Any(), "test-nlb.elb.amazonaws.com").
		Return("arn:nlb", "test-nlb", []string{"sg-unexpected"}, nil)
	mockAws.EXPECT().GetNLBTargetHealth(gomock.Any(), "arn:nlb").
		Return([]aws.NLBTargetHealth{
			{TargetID: "i-001", Port: 443, State: "healthy"},
		}, nil)
	mockAws.EXPECT().GetInstanceSecurityGroupIDs(gomock.Any(), gomock.Any()).
		Return([]string{"sg-node"}, nil)
	mockAws.EXPECT().GetSecurityGroupRules(gomock.Any(), gomock.Any()).
		Return([]ec2v2types.SecurityGroup{testSGAllowNodePorts("sg-node")}, nil)

	ic := newNLBIngressController(nil)
	svc := newRouterService("test-nlb.elb.amazonaws.com")
	k8sClient := newFakeClient(ic, svc)
	cluster := newAWSTestClusterWithDNS("test", "10.0.0.0/16", "", "p", "e.com", false)
	notes := newTestNotes()
	inv := &Investigation{}

	r := &investigation.Resources{Cluster: cluster, K8sClient: k8sClient, AwsClient: mockAws}
	inv.checkLoadBalancerHealth(context.Background(), r, notes)

	if !strings.Contains(notes.String(), "has security groups attached (unusual)") {
		t.Errorf("expected unexpected SGs warning, got: %s", notes.String())
	}
}

func TestCheckNLBHealth_NodeSGAllowsNodePorts(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockAws := awsmock.NewMockClient(ctrl)

	mockAws.EXPECT().FindNLBByDNSName(gomock.Any(), "test-nlb.elb.amazonaws.com").
		Return("arn:nlb", "test-nlb", []string{}, nil)
	mockAws.EXPECT().GetNLBTargetHealth(gomock.Any(), "arn:nlb").
		Return([]aws.NLBTargetHealth{
			{TargetID: "i-001", Port: 31174, State: "healthy"},
		}, nil)
	mockAws.EXPECT().GetInstanceSecurityGroupIDs(gomock.Any(), []string{"i-001"}).
		Return([]string{"sg-node"}, nil)
	mockAws.EXPECT().GetSecurityGroupRules(gomock.Any(), gomock.Any()).
		Return([]ec2v2types.SecurityGroup{testSGAllowNodePorts("sg-node")}, nil)

	ic := newNLBIngressController(nil)
	svc := newRouterService("test-nlb.elb.amazonaws.com")
	k8sClient := newFakeClient(ic, svc)
	cluster := newAWSTestClusterWithDNS("test", "10.0.0.0/16", "", "p", "e.com", false)
	notes := newTestNotes()
	inv := &Investigation{}

	r := &investigation.Resources{Cluster: cluster, K8sClient: k8sClient, AwsClient: mockAws}
	inv.checkLoadBalancerHealth(context.Background(), r, notes)

	if !strings.Contains(notes.String(), "infra node security groups allow NodePort traffic") {
		t.Errorf("expected NodePort allowed message, got: %s", notes.String())
	}
}

func TestCheckNLBHealth_NodeSGMissingNodePorts(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockAws := awsmock.NewMockClient(ctrl)

	mockAws.EXPECT().FindNLBByDNSName(gomock.Any(), "test-nlb.elb.amazonaws.com").
		Return("arn:nlb", "test-nlb", []string{}, nil)
	mockAws.EXPECT().GetNLBTargetHealth(gomock.Any(), "arn:nlb").
		Return([]aws.NLBTargetHealth{
			{TargetID: "i-001", Port: 31174, State: "healthy"},
		}, nil)
	mockAws.EXPECT().GetInstanceSecurityGroupIDs(gomock.Any(), []string{"i-001"}).
		Return([]string{"sg-node"}, nil)
	mockAws.EXPECT().GetSecurityGroupRules(gomock.Any(), gomock.Any()).
		Return([]ec2v2types.SecurityGroup{{
			GroupId: strPtr("sg-node"),
			IpPermissions: []ec2v2types.IpPermission{
				{
					IpProtocol: strPtr("tcp"),
					FromPort:   int32Ptr(22),
					ToPort:     int32Ptr(22),
					IpRanges:   []ec2v2types.IpRange{{CidrIp: strPtr("0.0.0.0/0")}},
				},
			},
		}}, nil)

	ic := newNLBIngressController(nil)
	svc := newRouterService("test-nlb.elb.amazonaws.com")
	k8sClient := newFakeClient(ic, svc)
	cluster := newAWSTestClusterWithDNS("test", "10.0.0.0/16", "", "p", "e.com", false)
	notes := newTestNotes()
	inv := &Investigation{}

	r := &investigation.Resources{Cluster: cluster, K8sClient: k8sClient, AwsClient: mockAws}
	inv.checkLoadBalancerHealth(context.Background(), r, notes)

	if !strings.Contains(notes.String(), "do not allow TCP traffic on NodePort range") {
		t.Errorf("expected NodePort blocked warning, got: %s", notes.String())
	}
}

func TestCheckNLBHealth_InstanceSGLookupError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockAws := awsmock.NewMockClient(ctrl)

	mockAws.EXPECT().FindNLBByDNSName(gomock.Any(), "test-nlb.elb.amazonaws.com").
		Return("arn:nlb", "test-nlb", []string{}, nil)
	mockAws.EXPECT().GetNLBTargetHealth(gomock.Any(), "arn:nlb").
		Return([]aws.NLBTargetHealth{
			{TargetID: "i-001", Port: 443, State: "healthy"},
		}, nil)
	mockAws.EXPECT().GetInstanceSecurityGroupIDs(gomock.Any(), []string{"i-001"}).
		Return(nil, fmt.Errorf("access denied")) //nolint:err113

	ic := newNLBIngressController(nil)
	svc := newRouterService("test-nlb.elb.amazonaws.com")
	k8sClient := newFakeClient(ic, svc)
	cluster := newAWSTestClusterWithDNS("test", "10.0.0.0/16", "", "p", "e.com", false)
	notes := newTestNotes()
	inv := &Investigation{}

	r := &investigation.Resources{Cluster: cluster, K8sClient: k8sClient, AwsClient: mockAws}
	inv.checkLoadBalancerHealth(context.Background(), r, notes)

	if !strings.Contains(notes.String(), "failed to get infra node security groups") {
		t.Errorf("expected SG lookup error warning, got: %s", notes.String())
	}
}

// sgAllowsTCPInbound unit tests

func TestSgAllowsTCPInbound_Allows0000(t *testing.T) {
	sgs := []ec2v2types.SecurityGroup{testSGAllowTCP443("sg-1")}
	if !sgAllowsTCPInbound(sgs, 443, 443, "10.0.0.0/16") {
		t.Error("expected true for 0.0.0.0/0 rule")
	}
}

func TestSgAllowsTCPInbound_AllowsMachineCIDR(t *testing.T) {
	sg := ec2v2types.SecurityGroup{
		GroupId: strPtr("sg-1"),
		IpPermissions: []ec2v2types.IpPermission{
			{
				IpProtocol: strPtr("tcp"),
				FromPort:   int32Ptr(443),
				ToPort:     int32Ptr(443),
				IpRanges:   []ec2v2types.IpRange{{CidrIp: strPtr("10.0.0.0/8")}},
			},
		},
	}
	if !sgAllowsTCPInbound([]ec2v2types.SecurityGroup{sg}, 443, 443, "10.0.0.0/16") {
		t.Error("expected true — 10.0.0.0/8 covers 10.0.0.0/16")
	}
}

func TestSgAllowsTCPInbound_PortMismatch(t *testing.T) {
	sg := ec2v2types.SecurityGroup{
		GroupId: strPtr("sg-1"),
		IpPermissions: []ec2v2types.IpPermission{
			{
				IpProtocol: strPtr("tcp"),
				FromPort:   int32Ptr(80),
				ToPort:     int32Ptr(80),
				IpRanges:   []ec2v2types.IpRange{{CidrIp: strPtr("0.0.0.0/0")}},
			},
		},
	}
	if sgAllowsTCPInbound([]ec2v2types.SecurityGroup{sg}, 443, 443, "10.0.0.0/16") {
		t.Error("expected false — rule is for port 80, not 443")
	}
}

func TestSgAllowsTCPInbound_NoMatchingRules(t *testing.T) {
	sg := ec2v2types.SecurityGroup{
		GroupId:       strPtr("sg-1"),
		IpPermissions: []ec2v2types.IpPermission{},
	}
	if sgAllowsTCPInbound([]ec2v2types.SecurityGroup{sg}, 443, 443, "10.0.0.0/16") {
		t.Error("expected false — no rules at all")
	}
}

func TestSgAllowsTCPInbound_AllProtocols(t *testing.T) {
	sg := ec2v2types.SecurityGroup{
		GroupId: strPtr("sg-1"),
		IpPermissions: []ec2v2types.IpPermission{
			{
				IpProtocol: strPtr("-1"),
				IpRanges:   []ec2v2types.IpRange{{CidrIp: strPtr("0.0.0.0/0")}},
			},
		},
	}
	if !sgAllowsTCPInbound([]ec2v2types.SecurityGroup{sg}, 443, 443, "10.0.0.0/16") {
		t.Error("expected true — protocol -1 allows all traffic")
	}
}

func TestSgAllowsTCPInbound_EmptyCIDR(t *testing.T) {
	sg := ec2v2types.SecurityGroup{
		GroupId: strPtr("sg-1"),
		IpPermissions: []ec2v2types.IpPermission{
			{
				IpProtocol: strPtr("tcp"),
				FromPort:   int32Ptr(30000),
				ToPort:     int32Ptr(32767),
				IpRanges:   []ec2v2types.IpRange{{CidrIp: strPtr("10.0.0.0/8")}},
			},
		},
	}
	if !sgAllowsTCPInbound([]ec2v2types.SecurityGroup{sg}, 30000, 32767, "") {
		t.Error("expected true — empty CIDR means any source is OK")
	}
}

// mockEgressVerifier is a test mock for the egressVerifier interface.
type mockEgressVerifier struct {
	result  networkverifier.VerifierResult
	failure string
	err     error
	called  bool
}

func (m *mockEgressVerifier) run(r *investigation.Resources) (networkverifier.VerifierResult, string, error) {
	m.called = true
	return m.result, m.failure, m.err
}

func successEgressVerifier() *mockEgressVerifier {
	return &mockEgressVerifier{result: networkverifier.Success}
}

// checkVPCEgress unit tests

func TestCheckVPCEgress_Success(t *testing.T) {
	cluster := newAWSTestClusterWithDNS("test", "10.0.0.0/16", "", "p", "e.com", false)
	notes := newTestNotes()
	inv := &Investigation{egressVerifier: successEgressVerifier()}

	r := &investigation.Resources{
		Cluster:           cluster,
		ClusterDeployment: &hivev1.ClusterDeployment{},
	}
	inv.checkVPCEgress(r, notes)

	output := notes.String()
	if !strings.Contains(output, "network verifier passed") {
		t.Errorf("expected success message, got: %s", output)
	}
}

func TestCheckVPCEgress_Failure(t *testing.T) {
	cluster := newAWSTestClusterWithDNS("test", "10.0.0.0/16", "", "p", "e.com", false)
	notes := newTestNotes()
	inv := &Investigation{egressVerifier: &mockEgressVerifier{
		result:  networkverifier.Failure,
		failure: "nosnch.in unreachable",
	}}

	r := &investigation.Resources{
		Cluster:           cluster,
		ClusterDeployment: &hivev1.ClusterDeployment{},
	}
	inv.checkVPCEgress(r, notes)

	output := notes.String()
	if !strings.Contains(output, "blocked egress") {
		t.Errorf("expected blocked egress warning, got: %s", output)
	}
	if !strings.Contains(output, "nosnch.in unreachable") {
		t.Errorf("expected failure reason, got: %s", output)
	}
}

func TestCheckVPCEgress_Error(t *testing.T) {
	cluster := newAWSTestClusterWithDNS("test", "10.0.0.0/16", "", "p", "e.com", false)
	notes := newTestNotes()
	inv := &Investigation{egressVerifier: &mockEgressVerifier{
		err: fmt.Errorf("failed to initialize validateEgressInput"),
	}}

	r := &investigation.Resources{
		Cluster:           cluster,
		ClusterDeployment: &hivev1.ClusterDeployment{},
	}
	inv.checkVPCEgress(r, notes)

	output := notes.String()
	if !strings.Contains(output, "network verifier error") {
		t.Errorf("expected error warning, got: %s", output)
	}
	if !strings.Contains(output, "failed to initialize") {
		t.Errorf("expected error detail, got: %s", output)
	}
}

func TestCheckVPCEgress_Undefined(t *testing.T) {
	cluster := newAWSTestClusterWithDNS("test", "10.0.0.0/16", "", "p", "e.com", false)
	notes := newTestNotes()
	inv := &Investigation{egressVerifier: &mockEgressVerifier{
		result: networkverifier.Undefined,
	}}

	r := &investigation.Resources{
		Cluster:           cluster,
		ClusterDeployment: &hivev1.ClusterDeployment{},
	}
	inv.checkVPCEgress(r, notes)

	output := notes.String()
	if !strings.Contains(output, "undefined result") {
		t.Errorf("expected undefined result warning, got: %s", output)
	}
}

// Run-level test: PrivateLink cluster skips egress but runs other AWS checks

func TestRun_PrivateLink_SkipsEgress(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockAws := awsmock.NewMockClient(ctrl)

	// Route53 check expects: FindHostedZone (private only for PrivateLink), HasResourceRecordSet
	mockAws.EXPECT().FindHostedZone(gomock.Any(), "msaary-test.4t01.s1.devshift.org", true).Return("Z1234PRIVATE", nil)
	mockAws.EXPECT().HasResourceRecordSet(gomock.Any(), "Z1234PRIVATE", "\\052.apps.msaary-test.4t01.s1.devshift.org.", "A").Return(true, nil)
	// No public zone call for PrivateLink clusters.

	// DHCP check expects: GetVpcDhcpConfiguration (classic cluster, not HCP)
	mockAws.EXPECT().GetVpcDhcpConfiguration(gomock.Any(), "test-cluster-infra").Return([]string{"AmazonProvidedDNS"}, nil)

	// LB health check expects: FindCLBByDNSName (IC defaults to Classic)
	mockAws.EXPECT().FindCLBByDNSName(gomock.Any(), "test-elb-123456.us-east-1.elb.amazonaws.com").Return("test-elb", []string{"sg-clb"}, nil)
	mockAws.EXPECT().GetCLBInstanceHealth(gomock.Any(), "test-elb").Return([]aws.CLBInstanceHealth{
		{InstanceID: "i-001", State: "InService"},
		{InstanceID: "i-002", State: "InService"},
	}, nil)
	mockAws.EXPECT().GetSecurityGroupRules(gomock.Any(), []string{"sg-clb"}).
		Return([]ec2v2types.SecurityGroup{testSGAllowTCP443("sg-clb")}, nil)

	// No egress verifier calls expected — PrivateLink clusters skip egress.

	ic := newDefaultIngressController([]operatorv1.CIDR{"10.0.0.0/8"})
	dns := newDefaultDNS([]operatorv1.Upstream{{Type: operatorv1.SystemResolveConfType}})
	routerPod := newRouterPod("router-default-abc", corev1.PodRunning, []corev1.ContainerStatus{
		{Name: "router", Ready: true, RestartCount: 0},
	})
	routerSvc := newRouterService("test-elb-123456.us-east-1.elb.amazonaws.com")
	consolePod := newConsolePod("console-abc", "node-1")
	node := newTestNode("node-1", healthyNodeConditions(), false)
	k8sClient := newFakeClient(ic, dns, routerPod, routerSvc, consolePod, node)
	cluster := newAWSTestClusterWithDNS("test-cluster", "10.0.0.0/16",
		"https://console.test.example.com", "msaary-test", "4t01.s1.devshift.org", true) // PrivateLink=true

	rb := &investigation.ResourceBuilderMock{
		Resources: &investigation.Resources{
			Cluster:    cluster,
			K8sClient:  k8sClient,
			AwsClient:  mockAws,
			IsHCP:      false,
			RestConfig: testRestConfig(),
		},
	}

	egressMock := successEgressVerifier()
	inv := &Investigation{
		consoleChecker:    healthyConsoleChecker(),
		blackboxProber:    healthyBlackboxProber(),
		probeHistoryCheck: noopProbeHistoryChecker(),
		egressVerifier:    egressMock,
	}
	result, err := inv.Run(rb)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify egress was skipped — mock should not have been called.
	if egressMock.called {
		t.Error("expected egress check to be skipped for PrivateLink cluster")
	}

	// Verify escalation still happens (other checks ran).
	hasEscalate := false
	for _, a := range result.Actions {
		if a.Type() == actionEscalate {
			hasEscalate = true
		}
	}
	if !hasEscalate {
		t.Error("expected escalate action")
	}
}

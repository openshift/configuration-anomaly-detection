package clusterhealthcheck

import (
	"context"
	"fmt"
	"strings"
	"testing"

	cmv1 "github.com/openshift-online/ocm-sdk-go/clustersmgmt/v1"
	configv1 "github.com/openshift/api/config/v1"
	mcfgv1 "github.com/openshift/api/machineconfiguration/v1"
	"github.com/openshift/configuration-anomaly-detection/pkg/backplane"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/investigation"
	k8sclient "github.com/openshift/configuration-anomaly-detection/pkg/k8s"
	"github.com/openshift/configuration-anomaly-detection/pkg/notewriter"

	certsv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// testScheme returns a scheme with all the types the health check needs.
func testScheme() *runtime.Scheme {
	s := runtime.NewScheme()
	_ = corev1.AddToScheme(s)
	_ = configv1.Install(s)
	_ = mcfgv1.Install(s)
	_ = certsv1.AddToScheme(s)
	_ = policyv1.AddToScheme(s)
	return s
}

// clientImpl wraps a controller-runtime client to satisfy k8sclient.Client
type clientImpl struct {
	client.Client
}

func newFakeClient(objs ...client.Object) client.Client {
	return fake.NewClientBuilder().WithScheme(testScheme()).WithObjects(objs...).Build()
}

func newTestCluster(id string) *cmv1.Cluster {
	cluster, _ := cmv1.NewCluster().ID(id).Build()
	return cluster
}

func newTestNotes() *notewriter.NoteWriter {
	return notewriter.New("clusterhealthcheck", nil)
}

// --- Mock implementations ---

type mockAlertsFetcher struct {
	alerts []firingAlert
	err    error
}

func (m *mockAlertsFetcher) fetchFiringAlerts(_ context.Context, _ k8sclient.Client, _ *rest.Config) ([]firingAlert, error) {
	return m.alerts, m.err
}

type mockEtcdHealthChecker struct {
	output string
	err    error
}

func (m *mockEtcdHealthChecker) checkEtcdHealth(_ context.Context, _ k8sclient.Client, _ *rest.Config, _ string) (string, error) {
	return m.output, m.err
}

type mockAPIHealthChecker struct {
	result apiHealthResult
	err    error
}

func (m *mockAPIHealthChecker) checkHealth(_ context.Context, _ *rest.Config) (apiHealthResult, error) {
	return m.result, m.err
}

// --- Investigation interface tests ---

func TestName(t *testing.T) {
	inv := &Investigation{}
	if inv.Name() != "clusterhealthcheck" {
		t.Errorf("expected name 'clusterhealthcheck', got %q", inv.Name())
	}
}

func TestAlertTitle(t *testing.T) {
	inv := &Investigation{}
	if inv.AlertTitle() != "" {
		t.Errorf("expected empty alert title, got %q", inv.AlertTitle())
	}
}

func TestIsExperimental(t *testing.T) {
	inv := &Investigation{}
	if !inv.IsExperimental() {
		t.Error("expected IsExperimental to return true")
	}
}

func TestDescription(t *testing.T) {
	inv := &Investigation{}
	if inv.Description() == "" {
		t.Error("expected non-empty description")
	}
}

// --- Run tests ---

func TestRun_HealthyCluster(t *testing.T) {
	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "worker-1", Labels: map[string]string{"node-role.kubernetes.io/worker": ""}},
		Status: corev1.NodeStatus{
			Conditions:  []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue}},
			Capacity:    corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("4"), corev1.ResourceMemory: resource.MustParse("16Gi")},
			Allocatable: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("3500m"), corev1.ResourceMemory: resource.MustParse("15Gi")},
		},
	}

	co := &configv1.ClusterOperator{
		ObjectMeta: metav1.ObjectMeta{Name: "monitoring"},
		Status: configv1.ClusterOperatorStatus{
			Conditions: []configv1.ClusterOperatorStatusCondition{
				{Type: configv1.OperatorAvailable, Status: configv1.ConditionTrue},
				{Type: configv1.OperatorDegraded, Status: configv1.ConditionFalse},
				{Type: configv1.OperatorProgressing, Status: configv1.ConditionFalse},
			},
		},
	}

	cv := &configv1.ClusterVersion{
		ObjectMeta: metav1.ObjectMeta{Name: "version"},
		Status: configv1.ClusterVersionStatus{
			History: []configv1.UpdateHistory{{State: configv1.CompletedUpdate, Version: "4.16.5"}},
		},
	}

	mcp := &mcfgv1.MachineConfigPool{
		ObjectMeta: metav1.ObjectMeta{Name: "worker"},
		Status: mcfgv1.MachineConfigPoolStatus{
			MachineCount:        2,
			UpdatedMachineCount: 2,
			Conditions: []mcfgv1.MachineConfigPoolCondition{
				{Type: mcfgv1.MachineConfigPoolUpdated, Status: corev1.ConditionTrue},
				{Type: mcfgv1.MachineConfigPoolDegraded, Status: corev1.ConditionFalse},
			},
		},
	}

	fakeK8s := newFakeClient(node, co, cv, mcp)

	rb := &investigation.ResourceBuilderMock{
		Resources: &investigation.Resources{
			Cluster:   newTestCluster("test-cluster"),
			K8sClient: clientImpl{fakeK8s},
			Params:    map[string]string{},
		},
	}

	inv := &Investigation{
		alertsFetcher:    &mockAlertsFetcher{alerts: nil},
		etcdChecker:      &mockEtcdHealthChecker{output: "endpoint health: healthy"},
		apiHealthChecker: &mockAPIHealthChecker{result: apiHealthResult{healthz: "ok", livez: "ok", readyz: "ok"}},
	}

	result, err := inv.Run(rb)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.Actions) != 2 {
		t.Fatalf("expected 2 actions (backplane report + PD note), got %d", len(result.Actions))
	}
}

func TestRun_HCPCluster(t *testing.T) {
	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "worker-1"},
		Status: corev1.NodeStatus{
			Conditions:  []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue}},
			Capacity:    corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("4"), corev1.ResourceMemory: resource.MustParse("16Gi")},
			Allocatable: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("3500m"), corev1.ResourceMemory: resource.MustParse("15Gi")},
		},
	}

	co := &configv1.ClusterOperator{
		ObjectMeta: metav1.ObjectMeta{Name: "monitoring"},
		Status: configv1.ClusterOperatorStatus{
			Conditions: []configv1.ClusterOperatorStatusCondition{
				{Type: configv1.OperatorAvailable, Status: configv1.ConditionTrue},
			},
		},
	}

	cv := &configv1.ClusterVersion{
		ObjectMeta: metav1.ObjectMeta{Name: "version"},
		Status: configv1.ClusterVersionStatus{
			History: []configv1.UpdateHistory{{State: configv1.CompletedUpdate, Version: "4.16.5"}},
		},
	}

	fakeK8s := newFakeClient(node, co, cv)

	rb := &investigation.ResourceBuilderMock{
		Resources: &investigation.Resources{
			Cluster:   newTestCluster("test-hcp-cluster"),
			K8sClient: clientImpl{fakeK8s},
			IsHCP:     true,
			Params:    map[string]string{},
		},
	}

	inv := &Investigation{
		alertsFetcher:    &mockAlertsFetcher{alerts: nil},
		etcdChecker:      &mockEtcdHealthChecker{output: "healthy"},
		apiHealthChecker: &mockAPIHealthChecker{result: apiHealthResult{healthz: "ok", livez: "ok", readyz: "ok"}},
	}

	result, err := inv.Run(rb)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.Actions) == 0 {
		t.Fatal("expected actions to be returned")
	}
}

func TestRun_ClusterAccessError(t *testing.T) {
	rb := &investigation.ResourceBuilderMock{
		BuildError: investigation.RestConfigError{
			ClusterID: "test-cluster",
			Err:       fmt.Errorf("cannot create remediations on hive, management or service clusters"),
		},
	}

	inv := &Investigation{}

	result, err := inv.Run(rb)
	if err != nil {
		t.Fatalf("cluster access errors should not return an error, got: %v", err)
	}

	if len(result.Actions) == 0 {
		t.Fatal("expected a note action for cluster access error")
	}
}

func TestRun_BuildError(t *testing.T) {
	rb := &investigation.ResourceBuilderMock{
		BuildError: fmt.Errorf("some unexpected infrastructure error"),
	}

	inv := &Investigation{}

	_, err := inv.Run(rb)
	if err == nil {
		t.Fatal("expected an error for non-cluster-access build failures")
	}
}

// --- Individual check tests ---

func TestCheckClusterOperators_AllHealthy(t *testing.T) {
	co1 := &configv1.ClusterOperator{
		ObjectMeta: metav1.ObjectMeta{Name: "monitoring"},
		Status: configv1.ClusterOperatorStatus{
			Conditions: []configv1.ClusterOperatorStatusCondition{
				{Type: configv1.OperatorAvailable, Status: configv1.ConditionTrue},
				{Type: configv1.OperatorDegraded, Status: configv1.ConditionFalse},
				{Type: configv1.OperatorProgressing, Status: configv1.ConditionFalse},
			},
		},
	}
	co2 := &configv1.ClusterOperator{
		ObjectMeta: metav1.ObjectMeta{Name: "ingress"},
		Status: configv1.ClusterOperatorStatus{
			Conditions: []configv1.ClusterOperatorStatusCondition{
				{Type: configv1.OperatorAvailable, Status: configv1.ConditionTrue},
				{Type: configv1.OperatorDegraded, Status: configv1.ConditionFalse},
			},
		},
	}

	k8s := newFakeClient(co1, co2)
	notes := newTestNotes()

	inv := &Investigation{}
	inv.checkClusterOperators(context.Background(), clientImpl{k8s}, notes)

	output := notes.String()
	if !strings.Contains(output, "all 2 operators are healthy") {
		t.Errorf("expected healthy message, got:\n%s", output)
	}
}

func TestCheckClusterOperators_Degraded(t *testing.T) {
	co := &configv1.ClusterOperator{
		ObjectMeta: metav1.ObjectMeta{Name: "monitoring"},
		Status: configv1.ClusterOperatorStatus{
			Conditions: []configv1.ClusterOperatorStatusCondition{
				{Type: configv1.OperatorDegraded, Status: configv1.ConditionTrue, Reason: "UserConfigError"},
				{Type: configv1.OperatorAvailable, Status: configv1.ConditionFalse, Reason: "ComponentUnavailable"},
			},
		},
	}

	k8s := newFakeClient(co)
	notes := newTestNotes()

	inv := &Investigation{}
	inv.checkClusterOperators(context.Background(), clientImpl{k8s}, notes)

	output := notes.String()
	if !strings.Contains(output, "degraded") {
		t.Errorf("expected degraded warning, got:\n%s", output)
	}
	if !strings.Contains(output, "unavailable") {
		t.Errorf("expected unavailable warning, got:\n%s", output)
	}
}

func TestCheckClusterOperators_Progressing(t *testing.T) {
	co := &configv1.ClusterOperator{
		ObjectMeta: metav1.ObjectMeta{Name: "kube-apiserver"},
		Status: configv1.ClusterOperatorStatus{
			Conditions: []configv1.ClusterOperatorStatusCondition{
				{Type: configv1.OperatorProgressing, Status: configv1.ConditionTrue, Reason: "Updating"},
				{Type: configv1.OperatorAvailable, Status: configv1.ConditionTrue},
				{Type: configv1.OperatorDegraded, Status: configv1.ConditionFalse},
			},
		},
	}

	k8s := newFakeClient(co)
	notes := newTestNotes()

	inv := &Investigation{}
	inv.checkClusterOperators(context.Background(), clientImpl{k8s}, notes)

	output := notes.String()
	if !strings.Contains(output, "progressing") {
		t.Errorf("expected progressing warning, got:\n%s", output)
	}
}

func TestCheckClusterOperators_None(t *testing.T) {
	k8s := newFakeClient()
	notes := newTestNotes()

	inv := &Investigation{}
	inv.checkClusterOperators(context.Background(), clientImpl{k8s}, notes)

	output := notes.String()
	if !strings.Contains(output, "none found") {
		t.Errorf("expected 'none found' warning, got:\n%s", output)
	}
}

func TestCheckAPIServerHealth_AllOK(t *testing.T) {
	notes := newTestNotes()
	inv := &Investigation{
		apiHealthChecker: &mockAPIHealthChecker{
			result: apiHealthResult{healthz: "ok", livez: "ok", readyz: "ok"},
		},
	}

	r := &investigation.Resources{
		K8sClient:  clientImpl{newFakeClient()},
		RestConfig: &backplane.RestConfig{},
	}
	inv.checkAPIServerHealth(context.Background(), r, notes)

	output := notes.String()
	if !strings.Contains(output, "all endpoints healthy") {
		t.Errorf("expected healthy message, got:\n%s", output)
	}
}

func TestCheckAPIServerHealth_Unhealthy(t *testing.T) {
	notes := newTestNotes()
	inv := &Investigation{
		apiHealthChecker: &mockAPIHealthChecker{
			result: apiHealthResult{healthz: "ok", livez: "error: connection refused", readyz: "ok"},
		},
	}

	r := &investigation.Resources{
		K8sClient:  clientImpl{newFakeClient()},
		RestConfig: &backplane.RestConfig{},
	}
	inv.checkAPIServerHealth(context.Background(), r, notes)

	output := notes.String()
	if !strings.Contains(output, "livez=error") {
		t.Errorf("expected unhealthy livez in output, got:\n%s", output)
	}
}

func TestCheckAPIServerHealth_Error(t *testing.T) {
	notes := newTestNotes()
	inv := &Investigation{
		apiHealthChecker: &mockAPIHealthChecker{
			err: fmt.Errorf("connection refused"),
		},
	}

	r := &investigation.Resources{
		K8sClient:  clientImpl{newFakeClient()},
		RestConfig: &backplane.RestConfig{},
	}
	inv.checkAPIServerHealth(context.Background(), r, notes)

	output := notes.String()
	if !strings.Contains(output, "check failed") {
		t.Errorf("expected check failed warning, got:\n%s", output)
	}
}

func TestCheckMachineConfigPools_Healthy(t *testing.T) {
	mcp := &mcfgv1.MachineConfigPool{
		ObjectMeta: metav1.ObjectMeta{Name: "worker"},
		Status: mcfgv1.MachineConfigPoolStatus{
			MachineCount:        3,
			UpdatedMachineCount: 3,
			Conditions: []mcfgv1.MachineConfigPoolCondition{
				{Type: mcfgv1.MachineConfigPoolUpdated, Status: corev1.ConditionTrue},
				{Type: mcfgv1.MachineConfigPoolDegraded, Status: corev1.ConditionFalse},
			},
		},
	}

	k8s := newFakeClient(mcp)
	notes := newTestNotes()

	inv := &Investigation{}
	inv.checkMachineConfigPools(context.Background(), clientImpl{k8s}, false, notes)

	output := notes.String()
	if !strings.Contains(output, "all 1 pools are healthy") {
		t.Errorf("expected healthy MCP message, got:\n%s", output)
	}
}

func TestCheckMachineConfigPools_Degraded(t *testing.T) {
	mcp := &mcfgv1.MachineConfigPool{
		ObjectMeta: metav1.ObjectMeta{Name: "worker"},
		Status: mcfgv1.MachineConfigPoolStatus{
			MachineCount:        3,
			UpdatedMachineCount: 1,
			Conditions: []mcfgv1.MachineConfigPoolCondition{
				{Type: mcfgv1.MachineConfigPoolDegraded, Status: corev1.ConditionTrue, Reason: "NodeFailing", Message: "node worker-2 is failing"},
			},
		},
	}

	k8s := newFakeClient(mcp)
	notes := newTestNotes()

	inv := &Investigation{}
	inv.checkMachineConfigPools(context.Background(), clientImpl{k8s}, false, notes)

	output := notes.String()
	if !strings.Contains(output, "degraded") {
		t.Errorf("expected degraded MCP warning, got:\n%s", output)
	}
}

func TestCheckMachineConfigPools_Updating(t *testing.T) {
	mcp := &mcfgv1.MachineConfigPool{
		ObjectMeta: metav1.ObjectMeta{Name: "master"},
		Status: mcfgv1.MachineConfigPoolStatus{
			MachineCount:        3,
			UpdatedMachineCount: 1,
			Conditions: []mcfgv1.MachineConfigPoolCondition{
				{Type: mcfgv1.MachineConfigPoolUpdating, Status: corev1.ConditionTrue},
			},
		},
	}

	k8s := newFakeClient(mcp)
	notes := newTestNotes()

	inv := &Investigation{}
	inv.checkMachineConfigPools(context.Background(), clientImpl{k8s}, false, notes)

	output := notes.String()
	if !strings.Contains(output, "updating") {
		t.Errorf("expected updating MCP warning, got:\n%s", output)
	}
	if !strings.Contains(output, "1/3 updated") {
		t.Errorf("expected update count in output, got:\n%s", output)
	}
}

func TestCheckMachineConfigPools_HCP(t *testing.T) {
	k8s := newFakeClient()
	notes := newTestNotes()

	inv := &Investigation{}
	inv.checkMachineConfigPools(context.Background(), clientImpl{k8s}, true, notes)

	output := notes.String()
	if !strings.Contains(output, "skipped") {
		t.Errorf("expected skipped message for HCP, got:\n%s", output)
	}
}

func TestCheckPendingCSRs_None(t *testing.T) {
	csr := &certsv1.CertificateSigningRequest{
		ObjectMeta: metav1.ObjectMeta{Name: "csr-1"},
		Spec:       certsv1.CertificateSigningRequestSpec{SignerName: "kubernetes.io/kubelet-serving", Username: "system:node:worker-1"},
		Status: certsv1.CertificateSigningRequestStatus{
			Conditions: []certsv1.CertificateSigningRequestCondition{
				{Type: certsv1.CertificateApproved},
			},
		},
	}

	k8s := newFakeClient(csr)
	notes := newTestNotes()

	inv := &Investigation{}
	inv.checkPendingCSRs(context.Background(), clientImpl{k8s}, notes)

	output := notes.String()
	if !strings.Contains(output, "Pending CSRs: none") {
		t.Errorf("expected no pending CSRs, got:\n%s", output)
	}
}

func TestCheckPendingCSRs_Pending(t *testing.T) {
	csr := &certsv1.CertificateSigningRequest{
		ObjectMeta: metav1.ObjectMeta{Name: "csr-pending", CreationTimestamp: metav1.Now()},
		Spec:       certsv1.CertificateSigningRequestSpec{SignerName: "kubernetes.io/kubelet-serving", Username: "system:node:worker-1"},
		Status:     certsv1.CertificateSigningRequestStatus{},
	}

	k8s := newFakeClient(csr)
	notes := newTestNotes()

	inv := &Investigation{}
	inv.checkPendingCSRs(context.Background(), clientImpl{k8s}, notes)

	output := notes.String()
	if !strings.Contains(output, "1 pending") {
		t.Errorf("expected 1 pending CSR, got:\n%s", output)
	}
}

func TestCheckNodeStatus_AllReady(t *testing.T) {
	node1 := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "worker-1"},
		Status: corev1.NodeStatus{
			Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue}},
		},
	}
	node2 := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "worker-2"},
		Status: corev1.NodeStatus{
			Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue}},
		},
	}

	k8s := newFakeClient(node1, node2)
	notes := newTestNotes()

	inv := &Investigation{}
	inv.checkNodeStatus(context.Background(), clientImpl{k8s}, notes)

	output := notes.String()
	if !strings.Contains(output, "all 2 nodes are Ready and healthy") {
		t.Errorf("expected all nodes ready, got:\n%s", output)
	}
}

func TestCheckNodeStatus_NotReady(t *testing.T) {
	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "worker-1"},
		Status: corev1.NodeStatus{
			Conditions: []corev1.NodeCondition{
				{Type: corev1.NodeReady, Status: corev1.ConditionFalse, Reason: "KubeletNotReady"},
			},
		},
	}

	k8s := newFakeClient(node)
	notes := newTestNotes()

	inv := &Investigation{}
	inv.checkNodeStatus(context.Background(), clientImpl{k8s}, notes)

	output := notes.String()
	if !strings.Contains(output, "not ready") {
		t.Errorf("expected not ready warning, got:\n%s", output)
	}
	if !strings.Contains(output, "KubeletNotReady") {
		t.Errorf("expected reason in output, got:\n%s", output)
	}
}

func TestCheckNodeStatus_Unschedulable(t *testing.T) {
	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "worker-1"},
		Spec:       corev1.NodeSpec{Unschedulable: true},
		Status: corev1.NodeStatus{
			Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue}},
		},
	}

	k8s := newFakeClient(node)
	notes := newTestNotes()

	inv := &Investigation{}
	inv.checkNodeStatus(context.Background(), clientImpl{k8s}, notes)

	output := notes.String()
	if !strings.Contains(output, "scheduling disabled") {
		t.Errorf("expected scheduling disabled warning, got:\n%s", output)
	}
}

func TestCheckNodeStatus_MemoryPressure(t *testing.T) {
	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "worker-1"},
		Status: corev1.NodeStatus{
			Conditions: []corev1.NodeCondition{
				{Type: corev1.NodeReady, Status: corev1.ConditionTrue},
				{Type: corev1.NodeMemoryPressure, Status: corev1.ConditionTrue},
			},
		},
	}

	k8s := newFakeClient(node)
	notes := newTestNotes()

	inv := &Investigation{}
	inv.checkNodeStatus(context.Background(), clientImpl{k8s}, notes)

	output := notes.String()
	if !strings.Contains(output, "MemoryPressure") {
		t.Errorf("expected MemoryPressure condition, got:\n%s", output)
	}
}

func TestCheckNodeStatus_DiskPressure(t *testing.T) {
	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "worker-1"},
		Status: corev1.NodeStatus{
			Conditions: []corev1.NodeCondition{
				{Type: corev1.NodeReady, Status: corev1.ConditionTrue},
				{Type: corev1.NodeDiskPressure, Status: corev1.ConditionTrue},
			},
		},
	}

	k8s := newFakeClient(node)
	notes := newTestNotes()

	inv := &Investigation{}
	inv.checkNodeStatus(context.Background(), clientImpl{k8s}, notes)

	output := notes.String()
	if !strings.Contains(output, "DiskPressure") {
		t.Errorf("expected DiskPressure condition, got:\n%s", output)
	}
}

func TestCheckNodeStatus_Tainted(t *testing.T) {
	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "master-1"},
		Spec: corev1.NodeSpec{
			Taints: []corev1.Taint{
				{Key: "node-role.kubernetes.io/master", Effect: corev1.TaintEffectNoSchedule},
			},
		},
		Status: corev1.NodeStatus{
			Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue}},
		},
	}

	k8s := newFakeClient(node)
	notes := newTestNotes()

	inv := &Investigation{}
	inv.checkNodeStatus(context.Background(), clientImpl{k8s}, notes)

	output := notes.String()
	if !strings.Contains(output, "Node Taints") {
		t.Errorf("expected taint report, got:\n%s", output)
	}
	if !strings.Contains(output, "NoSchedule") {
		t.Errorf("expected NoSchedule taint, got:\n%s", output)
	}
}

func TestCheckNodeStatus_None(t *testing.T) {
	k8s := newFakeClient()
	notes := newTestNotes()

	inv := &Investigation{}
	inv.checkNodeStatus(context.Background(), clientImpl{k8s}, notes)

	output := notes.String()
	if !strings.Contains(output, "none found") {
		t.Errorf("expected 'none found' warning, got:\n%s", output)
	}
}

func TestCheckCapacity(t *testing.T) {
	node1 := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "worker-1"},
		Status: corev1.NodeStatus{
			Capacity:    corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("4"), corev1.ResourceMemory: resource.MustParse("16Gi")},
			Allocatable: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("3500m"), corev1.ResourceMemory: resource.MustParse("15Gi")},
		},
	}
	node2 := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "worker-2"},
		Status: corev1.NodeStatus{
			Capacity:    corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("4"), corev1.ResourceMemory: resource.MustParse("16Gi")},
			Allocatable: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("3500m"), corev1.ResourceMemory: resource.MustParse("15Gi")},
		},
	}

	k8s := newFakeClient(node1, node2)
	notes := newTestNotes()

	inv := &Investigation{}
	r := &investigation.Resources{K8sClient: clientImpl{k8s}}
	inv.checkCapacity(context.Background(), r, notes)

	output := notes.String()
	if !strings.Contains(output, "less than 80%") {
		t.Errorf("expected threshold message in output, got:\n%s", output)
	}
	if !strings.Contains(output, "worker-1: CPU") {
		t.Errorf("expected per-node info for worker-1, got:\n%s", output)
	}
	if !strings.Contains(output, "worker-2: CPU") {
		t.Errorf("expected per-node info for worker-2, got:\n%s", output)
	}
}

func TestCheckCapacity_OverThreshold(t *testing.T) {
	// Node with very high reservation (only 500m of 4 CPU allocatable = 87% reserved)
	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "overloaded-1"},
		Status: corev1.NodeStatus{
			Capacity:    corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("4"), corev1.ResourceMemory: resource.MustParse("16Gi")},
			Allocatable: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("500m"), corev1.ResourceMemory: resource.MustParse("2Gi")},
		},
	}

	k8s := newFakeClient(node)
	notes := newTestNotes()

	inv := &Investigation{}
	r := &investigation.Resources{K8sClient: clientImpl{k8s}}
	inv.checkCapacity(context.Background(), r, notes)

	output := notes.String()
	if !strings.Contains(output, ">=80%") {
		t.Errorf("expected over-threshold warning, got:\n%s", output)
	}
}

func TestCheckClusterVersion_Healthy(t *testing.T) {
	cv := &configv1.ClusterVersion{
		ObjectMeta: metav1.ObjectMeta{Name: "version"},
		Status: configv1.ClusterVersionStatus{
			History: []configv1.UpdateHistory{
				{State: configv1.CompletedUpdate, Version: "4.16.5"},
			},
		},
	}

	k8s := newFakeClient(cv)
	notes := newTestNotes()

	inv := &Investigation{}
	inv.checkClusterVersion(context.Background(), clientImpl{k8s}, notes)

	output := notes.String()
	if !strings.Contains(output, "4.16.5") {
		t.Errorf("expected version 4.16.5, got:\n%s", output)
	}
}

func TestCheckClusterVersion_Failing(t *testing.T) {
	cv := &configv1.ClusterVersion{
		ObjectMeta: metav1.ObjectMeta{Name: "version"},
		Status: configv1.ClusterVersionStatus{
			History: []configv1.UpdateHistory{
				{State: configv1.CompletedUpdate, Version: "4.16.5"},
			},
			Conditions: []configv1.ClusterOperatorStatusCondition{
				{Type: "Failing", Status: configv1.ConditionTrue, Message: "upgrade is stuck"},
			},
		},
	}

	k8s := newFakeClient(cv)
	notes := newTestNotes()

	inv := &Investigation{}
	inv.checkClusterVersion(context.Background(), clientImpl{k8s}, notes)

	output := notes.String()
	if !strings.Contains(output, "Failing") {
		t.Errorf("expected Failing condition in output, got:\n%s", output)
	}
}

func TestCheckClusterVersion_Progressing(t *testing.T) {
	cv := &configv1.ClusterVersion{
		ObjectMeta: metav1.ObjectMeta{Name: "version"},
		Status: configv1.ClusterVersionStatus{
			History: []configv1.UpdateHistory{
				{State: configv1.CompletedUpdate, Version: "4.15.0"},
			},
			Conditions: []configv1.ClusterOperatorStatusCondition{
				{Type: "Progressing", Status: configv1.ConditionTrue, Message: "Working towards 4.16.0"},
			},
		},
	}

	k8s := newFakeClient(cv)
	notes := newTestNotes()

	inv := &Investigation{}
	inv.checkClusterVersion(context.Background(), clientImpl{k8s}, notes)

	output := notes.String()
	if !strings.Contains(output, "Progressing") {
		t.Errorf("expected Progressing condition in output, got:\n%s", output)
	}
}

func TestCheckClusterVersion_EOL(t *testing.T) {
	cv := &configv1.ClusterVersion{
		ObjectMeta: metav1.ObjectMeta{Name: "version"},
		Status: configv1.ClusterVersionStatus{
			Desired: configv1.Release{Version: "4.18.0"},
			History: []configv1.UpdateHistory{
				{State: configv1.CompletedUpdate, Version: "4.14.5"},
			},
		},
	}

	k8s := newFakeClient(cv)
	notes := newTestNotes()

	inv := &Investigation{}
	inv.checkClusterVersion(context.Background(), clientImpl{k8s}, notes)

	output := notes.String()
	if !strings.Contains(output, "EOL") {
		t.Errorf("expected EOL warning for 4.14 vs 4.18, got:\n%s", output)
	}
}

func TestCheckClusterVersion_NotEOL(t *testing.T) {
	cv := &configv1.ClusterVersion{
		ObjectMeta: metav1.ObjectMeta{Name: "version"},
		Status: configv1.ClusterVersionStatus{
			Desired: configv1.Release{Version: "4.16.5"},
			History: []configv1.UpdateHistory{
				{State: configv1.CompletedUpdate, Version: "4.15.0"},
			},
		},
	}

	k8s := newFakeClient(cv)
	notes := newTestNotes()

	inv := &Investigation{}
	inv.checkClusterVersion(context.Background(), clientImpl{k8s}, notes)

	output := notes.String()
	if strings.Contains(output, "EOL") {
		t.Errorf("should not report EOL for 4.15 vs 4.16, got:\n%s", output)
	}
}

func TestParseMinorVersion(t *testing.T) {
	tests := []struct {
		input    string
		expected int
	}{
		{"4.16.5", 16},
		{"4.14.0", 14},
		{"4.21.10", 21},
		{"4.0.0", 0},
		{"invalid", -1},
		{"4", -1},
	}
	for _, tt := range tests {
		result := parseMinorVersion(tt.input)
		if result != tt.expected {
			t.Errorf("parseMinorVersion(%q) = %d, want %d", tt.input, result, tt.expected)
		}
	}
}

func TestCheckFailingPods_None(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "healthy-pod", Namespace: "default"},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning},
	}

	k8s := newFakeClient(pod)
	notes := newTestNotes()

	inv := &Investigation{}
	inv.checkFailingPods(context.Background(), clientImpl{k8s}, notes)

	output := notes.String()
	if !strings.Contains(output, "Failing Pods: none") {
		t.Errorf("expected no failing pods, got:\n%s", output)
	}
}

func TestCheckFailingPods_Failed(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "failed-pod", Namespace: "default"},
		Status:     corev1.PodStatus{Phase: corev1.PodFailed, Reason: "OOMKilled"},
	}

	k8s := newFakeClient(pod)
	notes := newTestNotes()

	inv := &Investigation{}
	inv.checkFailingPods(context.Background(), clientImpl{k8s}, notes)

	output := notes.String()
	if !strings.Contains(output, "1 pod(s) with issues") {
		t.Errorf("expected 1 failing pod, got:\n%s", output)
	}
	if !strings.Contains(output, "OOMKilled") {
		t.Errorf("expected OOMKilled reason, got:\n%s", output)
	}
}

func TestCheckFailingPods_HighRestarts(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "crashloop-pod", Namespace: "openshift-monitoring"},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
			ContainerStatuses: []corev1.ContainerStatus{
				{Name: "prometheus", RestartCount: 15},
			},
		},
	}

	k8s := newFakeClient(pod)
	notes := newTestNotes()

	inv := &Investigation{}
	inv.checkFailingPods(context.Background(), clientImpl{k8s}, notes)

	output := notes.String()
	if !strings.Contains(output, "15 restarts") {
		t.Errorf("expected restart count in output, got:\n%s", output)
	}
}

func TestCheckFailingPods_CrashLoopBackOff(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "crash-pod", Namespace: "test-ns"},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
			ContainerStatuses: []corev1.ContainerStatus{
				{
					Name:         "app",
					RestartCount: 3,
					State: corev1.ContainerState{
						Waiting: &corev1.ContainerStateWaiting{Reason: "CrashLoopBackOff"},
					},
				},
			},
		},
	}

	k8s := newFakeClient(pod)
	notes := newTestNotes()

	inv := &Investigation{}
	inv.checkFailingPods(context.Background(), clientImpl{k8s}, notes)

	output := notes.String()
	if !strings.Contains(output, "CrashLoopBackOff") {
		t.Errorf("expected CrashLoopBackOff in output, got:\n%s", output)
	}
}

func TestCheckFailingPods_SkipsSucceeded(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "completed-job", Namespace: "default"},
		Status:     corev1.PodStatus{Phase: corev1.PodSucceeded},
	}

	k8s := newFakeClient(pod)
	notes := newTestNotes()

	inv := &Investigation{}
	inv.checkFailingPods(context.Background(), clientImpl{k8s}, notes)

	output := notes.String()
	if !strings.Contains(output, "Failing Pods: none") {
		t.Errorf("expected no failing pods (succeeded should be skipped), got:\n%s", output)
	}
}

func TestCheckRestrictivePDBs_None(t *testing.T) {
	maxUnavail := intstr.FromInt32(1)
	pdb := &policyv1.PodDisruptionBudget{
		ObjectMeta: metav1.ObjectMeta{Name: "normal-pdb", Namespace: "default"},
		Spec:       policyv1.PodDisruptionBudgetSpec{MaxUnavailable: &maxUnavail},
	}

	k8s := newFakeClient(pdb)
	notes := newTestNotes()

	inv := &Investigation{}
	inv.checkRestrictivePDBs(context.Background(), clientImpl{k8s}, notes)

	output := notes.String()
	if !strings.Contains(output, "Restrictive PDBs: none") {
		t.Errorf("expected no restrictive PDBs, got:\n%s", output)
	}
}

func TestCheckRestrictivePDBs_NotBlockingDisruptions(t *testing.T) {
	maxUnavail := intstr.FromInt32(0)
	pdb := &policyv1.PodDisruptionBudget{
		ObjectMeta: metav1.ObjectMeta{Name: "not-blocking-pdb", Namespace: "app-ns"},
		Spec:       policyv1.PodDisruptionBudgetSpec{MaxUnavailable: &maxUnavail},
		Status:     policyv1.PodDisruptionBudgetStatus{DisruptionsAllowed: 1},
	}

	k8s := newFakeClient(pdb)
	notes := newTestNotes()

	inv := &Investigation{}
	inv.checkRestrictivePDBs(context.Background(), clientImpl{k8s}, notes)

	output := notes.String()
	if !strings.Contains(output, "Restrictive PDBs: none") {
		t.Errorf("PDB with disruptionsAllowed>0 should not be flagged, got:\n%s", output)
	}
}

func TestCheckRestrictivePDBs_MaxUnavailableZero(t *testing.T) {
	maxUnavail := intstr.FromInt32(0)
	pdb := &policyv1.PodDisruptionBudget{
		ObjectMeta: metav1.ObjectMeta{Name: "restrictive-pdb", Namespace: "app-ns"},
		Spec:       policyv1.PodDisruptionBudgetSpec{MaxUnavailable: &maxUnavail},
		Status:     policyv1.PodDisruptionBudgetStatus{DisruptionsAllowed: 0},
	}

	k8s := newFakeClient(pdb)
	notes := newTestNotes()

	inv := &Investigation{}
	inv.checkRestrictivePDBs(context.Background(), clientImpl{k8s}, notes)

	output := notes.String()
	if !strings.Contains(output, "maxUnavailable=0") {
		t.Errorf("expected maxUnavailable=0 warning, got:\n%s", output)
	}
}

func TestCheckRestrictivePDBs_MinAvailable100Percent(t *testing.T) {
	minAvail := intstr.FromString("100%")
	pdb := &policyv1.PodDisruptionBudget{
		ObjectMeta: metav1.ObjectMeta{Name: "full-min-pdb", Namespace: "app-ns"},
		Spec:       policyv1.PodDisruptionBudgetSpec{MinAvailable: &minAvail},
		Status:     policyv1.PodDisruptionBudgetStatus{DisruptionsAllowed: 0, ExpectedPods: 3},
	}

	k8s := newFakeClient(pdb)
	notes := newTestNotes()

	inv := &Investigation{}
	inv.checkRestrictivePDBs(context.Background(), clientImpl{k8s}, notes)

	output := notes.String()
	if !strings.Contains(output, "minAvailable=100%") {
		t.Errorf("expected minAvailable=100%% warning, got:\n%s", output)
	}
}

func TestCheckNonNormalEvents_None(t *testing.T) {
	event := &corev1.Event{
		ObjectMeta:     metav1.ObjectMeta{Name: "normal-event", Namespace: "default"},
		Type:           corev1.EventTypeNormal,
		Reason:         "Scheduled",
		Message:        "Successfully assigned pod to node",
		InvolvedObject: corev1.ObjectReference{Kind: "Pod", Name: "test-pod"},
	}

	k8s := newFakeClient(event)
	notes := newTestNotes()

	inv := &Investigation{}
	inv.checkNonNormalEvents(context.Background(), clientImpl{k8s}, notes)

	output := notes.String()
	if !strings.Contains(output, "no non-normal events") {
		t.Errorf("expected no non-normal events, got:\n%s", output)
	}
}

func TestCheckNonNormalEvents_Warning(t *testing.T) {
	event := &corev1.Event{
		ObjectMeta:     metav1.ObjectMeta{Name: "warning-event", Namespace: "default"},
		Type:           "Warning",
		Reason:         "FailedMount",
		Message:        "MountVolume.SetUp failed",
		Count:          3,
		InvolvedObject: corev1.ObjectReference{Kind: "Pod", Name: "app-pod"},
	}

	k8s := newFakeClient(event)
	notes := newTestNotes()

	inv := &Investigation{}
	inv.checkNonNormalEvents(context.Background(), clientImpl{k8s}, notes)

	output := notes.String()
	if !strings.Contains(output, "1 non-normal event") {
		t.Errorf("expected 1 non-normal event, got:\n%s", output)
	}
	if !strings.Contains(output, "FailedMount") {
		t.Errorf("expected FailedMount in output, got:\n%s", output)
	}
	if !strings.Contains(output, "(x3)") {
		t.Errorf("expected count (x3) in output, got:\n%s", output)
	}
}

func TestCheckFiringAlerts_None(t *testing.T) {
	notes := newTestNotes()
	inv := &Investigation{
		alertsFetcher: &mockAlertsFetcher{alerts: nil},
	}

	r := &investigation.Resources{
		K8sClient:  clientImpl{newFakeClient()},
		RestConfig: &backplane.RestConfig{},
	}
	inv.checkFiringAlerts(context.Background(), r, notes)

	output := notes.String()
	if !strings.Contains(output, "Firing Alerts: none") {
		t.Errorf("expected no firing alerts, got:\n%s", output)
	}
}

func TestCheckFiringAlerts_WithAlerts(t *testing.T) {
	notes := newTestNotes()
	inv := &Investigation{
		alertsFetcher: &mockAlertsFetcher{
			alerts: []firingAlert{
				{Name: "HighMemoryUsage", Severity: "critical", State: "firing", Summary: "Memory > 90%"},
				{Name: "DiskAlmostFull", Severity: "warning", State: "firing", Summary: "Disk > 85%"},
			},
		},
	}

	r := &investigation.Resources{
		K8sClient:  clientImpl{newFakeClient()},
		RestConfig: &backplane.RestConfig{},
	}
	inv.checkFiringAlerts(context.Background(), r, notes)

	output := notes.String()
	if !strings.Contains(output, "2 firing alert(s)") {
		t.Errorf("expected 2 firing alerts, got:\n%s", output)
	}
	if !strings.Contains(output, "[critical] HighMemoryUsage") {
		t.Errorf("expected critical alert in output, got:\n%s", output)
	}
	if !strings.Contains(output, "[warning] DiskAlmostFull") {
		t.Errorf("expected warning alert in output, got:\n%s", output)
	}
}

func TestCheckFiringAlerts_FetchError(t *testing.T) {
	notes := newTestNotes()
	inv := &Investigation{
		alertsFetcher: &mockAlertsFetcher{err: fmt.Errorf("connection refused")},
	}

	r := &investigation.Resources{
		K8sClient:  clientImpl{newFakeClient()},
		RestConfig: &backplane.RestConfig{},
	}
	inv.checkFiringAlerts(context.Background(), r, notes)

	output := notes.String()
	if !strings.Contains(output, "failed to fetch") {
		t.Errorf("expected fetch error warning, got:\n%s", output)
	}
}

func TestCheckFiringAlerts_NoPod(t *testing.T) {
	fakeK8s := newFakeClient()
	notes := newTestNotes()

	inv := &Investigation{
		alertsFetcher: &mockAlertsFetcher{},
	}

	r := &investigation.Resources{
		K8sClient: clientImpl{fakeK8s},
	}
	inv.checkFiringAlerts(context.Background(), r, notes)

	output := notes.String()
	if !strings.Contains(output, "Firing Alerts") {
		t.Errorf("expected Firing Alerts in output, got:\n%s", output)
	}
}

func TestCheckEtcdStatus_Healthy(t *testing.T) {
	notes := newTestNotes()

	inv := &Investigation{
		etcdChecker: &mockEtcdHealthChecker{
			output: "https://10.0.0.1:2379 is healthy: successfully committed proposal",
		},
	}

	r := &investigation.Resources{
		K8sClient: clientImpl{newFakeClient()},
		IsHCP:     false,
	}
	inv.checkEtcdStatus(context.Background(), r, notes)

	output := notes.String()
	// fake client doesn't have rest config, so it will warn
	if !strings.Contains(output, "ETCD Status") {
		t.Errorf("expected ETCD Status in output, got:\n%s", output)
	}
}

func TestCheckEtcdStatus_HCP(t *testing.T) {
	notes := newTestNotes()

	inv := &Investigation{
		etcdChecker: &mockEtcdHealthChecker{output: "healthy"},
	}

	r := &investigation.Resources{
		K8sClient: clientImpl{newFakeClient()},
		IsHCP:     true,
	}
	inv.checkEtcdStatus(context.Background(), r, notes)

	output := notes.String()
	if !strings.Contains(output, "skipped") {
		t.Errorf("expected skipped message for HCP, got:\n%s", output)
	}
}

func TestCheckEtcdStatus_Error(t *testing.T) {
	notes := newTestNotes()

	inv := &Investigation{
		etcdChecker: &mockEtcdHealthChecker{err: fmt.Errorf("etcd cluster is unhealthy")},
	}

	r := &investigation.Resources{
		K8sClient: clientImpl{newFakeClient()},
		IsHCP:     false,
	}
	inv.checkEtcdStatus(context.Background(), r, notes)

	output := notes.String()
	// Fake client won't have rest config, so error is from GetRestConfig, not from etcdChecker
	if !strings.Contains(output, "ETCD Status") {
		t.Errorf("expected ETCD Status in output, got:\n%s", output)
	}
}

func TestCheckFailingPods_Truncation(t *testing.T) {
	var pods []client.Object
	for i := 0; i < 55; i++ {
		pods = append(pods, &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("bad-pod-%d", i), Namespace: "default"},
			Status:     corev1.PodStatus{Phase: corev1.PodFailed, Reason: "OOMKilled"},
		})
	}

	k8s := fake.NewClientBuilder().WithScheme(testScheme()).WithObjects(pods...).Build()
	notes := newTestNotes()

	inv := &Investigation{}
	inv.checkFailingPods(context.Background(), clientImpl{k8s}, notes)

	output := notes.String()
	if !strings.Contains(output, "55 pod(s) with issues") {
		t.Errorf("expected 55 pods count, got:\n%s", output)
	}
	if !strings.Contains(output, "... and 5 more") {
		t.Errorf("expected truncation message, got:\n%s", output)
	}
}

func TestCheckNonNormalEvents_Truncation(t *testing.T) {
	var events []client.Object
	for i := 0; i < 55; i++ {
		events = append(events, &corev1.Event{
			ObjectMeta:     metav1.ObjectMeta{Name: fmt.Sprintf("warn-event-%d", i), Namespace: "default"},
			Type:           "Warning",
			Reason:         "BackOff",
			Message:        "Back-off restarting failed container",
			InvolvedObject: corev1.ObjectReference{Kind: "Pod", Name: fmt.Sprintf("pod-%d", i)},
		})
	}

	k8s := fake.NewClientBuilder().WithScheme(testScheme()).WithObjects(events...).Build()
	notes := newTestNotes()

	inv := &Investigation{}
	inv.checkNonNormalEvents(context.Background(), clientImpl{k8s}, notes)

	output := notes.String()
	if !strings.Contains(output, "55 non-normal event") {
		t.Errorf("expected 55 events count, got:\n%s", output)
	}
	if !strings.Contains(output, "... and 5 more") {
		t.Errorf("expected truncation message, got:\n%s", output)
	}
}

func TestCheckNonNormalEvents_LongMessage(t *testing.T) {
	longMsg := strings.Repeat("x", 200)
	event := &corev1.Event{
		ObjectMeta:     metav1.ObjectMeta{Name: "long-event", Namespace: "default"},
		Type:           "Warning",
		Reason:         "FailedMount",
		Message:        longMsg,
		InvolvedObject: corev1.ObjectReference{Kind: "Pod", Name: "test-pod"},
	}

	k8s := newFakeClient(event)
	notes := newTestNotes()

	inv := &Investigation{}
	inv.checkNonNormalEvents(context.Background(), clientImpl{k8s}, notes)

	output := notes.String()
	if !strings.Contains(output, "...") {
		t.Errorf("expected truncated message with '...', got:\n%s", output)
	}
	if strings.Contains(output, longMsg) {
		t.Errorf("expected message to be truncated, but found full message in output")
	}
}

func TestFormatBytes(t *testing.T) {
	tests := []struct {
		input    int64
		expected string
	}{
		{1024, "1Ki"},
		{1024 * 1024, "1Mi"},
		{1024 * 1024 * 1024, "1Gi"},
		{2 * 1024 * 1024 * 1024, "2Gi"},
		{512 * 1024, "512Ki"},
		{256 * 1024 * 1024, "256Mi"},
	}

	for _, tt := range tests {
		result := formatBytes(tt.input)
		if result != tt.expected {
			t.Errorf("formatBytes(%d) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

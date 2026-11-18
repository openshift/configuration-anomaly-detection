package infranodesneedresizingsre

import (
	"testing"

	cmv1 "github.com/openshift-online/ocm-sdk-go/clustersmgmt/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/openshift/configuration-anomaly-detection/pkg/executor"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/investigation"
	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
	"github.com/openshift/configuration-anomaly-detection/pkg/notewriter"
	"github.com/openshift/configuration-anomaly-detection/pkg/types"
)

func testScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(s))
	return s
}

func newFakeClient(t *testing.T, objs ...client.Object) client.Client {
	t.Helper()
	return fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(objs...).Build()
}

func hasAction(actions []types.Action, actionType executor.ActionType) bool {
	for _, a := range actions {
		if a.Type() == string(actionType) {
			return true
		}
	}
	return false
}

func infraNode(name, cpu, mem string) *corev1.Node {
	return &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: name, Labels: map[string]string{infraRoleLabel: ""}},
		Status: corev1.NodeStatus{Allocatable: corev1.ResourceList{
			corev1.ResourceCPU:    resource.MustParse(cpu),
			corev1.ResourceMemory: resource.MustParse(mem),
		}},
	}
}

func workerNode(name string) *corev1.Node {
	return &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: map[string]string{"node-role.kubernetes.io/worker": ""}}}
}

func podReq(namespace, name, node, cpu, mem string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
		Spec: corev1.PodSpec{NodeName: node, Containers: []corev1.Container{{
			Name: "c",
			Resources: corev1.ResourceRequirements{Requests: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse(cpu),
				corev1.ResourceMemory: resource.MustParse(mem),
			}},
		}}},
	}
}

func completedPod(namespace, name, node string) *corev1.Pod {
	p := podReq(namespace, name, node, "1", "1Gi")
	p.Status.Phase = corev1.PodSucceeded
	return p
}

func runWith(t *testing.T, res *investigation.Resources) (investigation.InvestigationResult, string) {
	t.Helper()
	cluster, err := cmv1.NewCluster().ID("test-123").Build()
	require.NoError(t, err)
	res.Cluster = cluster
	res.Notes = notewriter.New(investigationName, logging.RawLogger)

	result, err := (&Investigation{}).Run(&investigation.ResourceBuilderMock{Resources: res})
	require.NoError(t, err)
	return result, res.Notes.String()
}

func TestNameMatchesPackage(t *testing.T) {
	assert.Equal(t, "infranodesneedresizingsre", (&Investigation{}).Name())
	assert.Equal(t, "InfraNodesNeedResizingSRE", (&Investigation{}).AlertTitle())
}

func TestRun_InfrastructureClusterStopsChain(t *testing.T) {
	result, notes := runWith(t, &investigation.Resources{IsInfrastructureCluster: true})

	assert.True(t, hasAction(result.Actions, executor.ActionTypeEscalateIncident))
	assert.Error(t, result.StopInvestigations)
	assert.Contains(t, notes, "management/service cluster")
}

func TestRun_NoInfraNodesEscalates(t *testing.T) {
	result, notes := runWith(t, &investigation.Resources{K8sClient: newFakeClient(t, workerNode("worker-1"))})

	assert.True(t, hasAction(result.Actions, executor.ActionTypeEscalateIncident))
	assert.Contains(t, notes, "No infra nodes found")
}

func TestRun_SummarisesAndRanks(t *testing.T) {
	k8s := newFakeClient(t,
		infraNode("infra-1", "4", "16Gi"),
		podReq("openshift-monitoring", "prometheus", "infra-1", "2", "8Gi"),
		podReq("openshift-ingress", "router", "infra-1", "500m", "1Gi"),
		completedPod("openshift-batch", "job", "infra-1"),      // completed: ignored
		podReq("customer-app", "web", "worker-1", "3", "10Gi"), // not on an infra node: ignored
	)

	result, notes := runWith(t, &investigation.Resources{K8sClient: k8s})

	assert.True(t, hasAction(result.Actions, executor.ActionTypeEscalateIncident))
	assert.False(t, hasAction(result.Actions, executor.ActionTypeSilenceIncident), "informing mode must not silence")
	assert.Contains(t, notes, "infra-1")
	assert.Contains(t, notes, "openshift-monitoring")
	assert.Contains(t, notes, "openshift-ingress")
	assert.NotContains(t, notes, "customer-app", "pods on non-infra nodes must be excluded")
	assert.NotContains(t, notes, "openshift-batch", "completed pods must be excluded")
}

func TestRun_SaturatedRecommendsResize(t *testing.T) {
	k8s := newFakeClient(t,
		infraNode("infra-1", "2", "4Gi"),
		podReq("openshift-monitoring", "prometheus", "infra-1", "1900m", "3800Mi"),
	)

	result, notes := runWith(t, &investigation.Resources{K8sClient: k8s})

	assert.True(t, hasAction(result.Actions, executor.ActionTypeEscalateIncident))
	assert.Contains(t, notes, "Recommend resizing the infra machine pool")
}

func TestRun_BelowThresholdSuggestsMetricsCheck(t *testing.T) {
	k8s := newFakeClient(t,
		infraNode("infra-1", "8", "32Gi"),
		podReq("openshift-monitoring", "prometheus", "infra-1", "500m", "2Gi"),
	)

	_, notes := runWith(t, &investigation.Resources{K8sClient: k8s})

	assert.Contains(t, notes, "below")
	assert.Contains(t, notes, "metrics")
}

func TestPodRequests(t *testing.T) {
	cpu, mem := podRequests(*podReq("ns", "p", "n", "250m", "512Mi"))
	assert.Equal(t, int64(250), cpu)
	assert.Equal(t, int64(512*1024*1024), mem)
}

func TestRankNamespaces_DeterministicOrder(t *testing.T) {
	ranked := rankNamespaces(map[string]*componentUsage{
		"b-small": {Namespace: "b-small", CPUMilli: 100, MemBytes: 100},
		"a-big":   {Namespace: "a-big", CPUMilli: 1000, MemBytes: 100},
		"c-mid":   {Namespace: "c-mid", CPUMilli: 500, MemBytes: 100},
	})
	require.Len(t, ranked, 3)
	assert.Equal(t, "a-big", ranked[0].Namespace)
	assert.Equal(t, "c-mid", ranked[1].Namespace)
	assert.Equal(t, "b-small", ranked[2].Namespace)
}

func TestNodePressureRatios_GuardZeroAllocatable(t *testing.T) {
	p := nodePressure{CPUMilli: 500, MemBytes: 1 << 30}
	assert.Equal(t, 0.0, p.cpuRatio())
	assert.Equal(t, 0.0, p.memRatio())
}

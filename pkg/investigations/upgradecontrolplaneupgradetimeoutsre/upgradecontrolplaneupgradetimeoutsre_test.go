package upgradecontrolplaneupgradetimeoutsre

import (
	"context"
	"testing"
	"time"

	cmv1 "github.com/openshift-online/ocm-sdk-go/clustersmgmt/v1"
	configv1 "github.com/openshift/api/config/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
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

const (
	fromVersion = "4.19.10"
	toVersion   = "4.20.2"
)

func testScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(s))
	require.NoError(t, policyv1.AddToScheme(s))
	require.NoError(t, configv1.Install(s))
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

func serviceLog(actions []types.Action) *executor.ServiceLogAction {
	for _, a := range actions {
		if sl, ok := a.(*executor.ServiceLogAction); ok {
			return sl
		}
	}
	return nil
}

func clusterVersion(desired string, completed bool) *configv1.ClusterVersion {
	state := configv1.PartialUpdate
	if completed {
		state = configv1.CompletedUpdate
	}
	return &configv1.ClusterVersion{
		ObjectMeta: metav1.ObjectMeta{Name: "version"},
		Status: configv1.ClusterVersionStatus{
			Desired: configv1.Release{Version: desired},
			History: []configv1.UpdateHistory{
				{State: state, Version: desired},
				{State: configv1.CompletedUpdate, Version: fromVersion},
			},
		},
	}
}

func cordonedNode(name string, since time.Duration) *corev1.Node {
	added := metav1.NewTime(time.Now().Add(-since))
	return &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: name, Labels: map[string]string{"node-role.kubernetes.io/master": ""}},
		Spec: corev1.NodeSpec{
			Unschedulable: true,
			Taints: []corev1.Taint{{
				Key:       corev1.TaintNodeUnschedulable,
				Effect:    corev1.TaintEffectNoSchedule,
				TimeAdded: &added,
			}},
		},
	}
}

func pod(namespace, name, node string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name, Labels: map[string]string{"app": name}},
		Spec:       corev1.PodSpec{NodeName: node},
	}
}

func cordonedWorker(name string, since time.Duration) *corev1.Node {
	n := cordonedNode(name, since)
	n.Labels = map[string]string{"node-role.kubernetes.io/worker": ""}
	return n
}

func completedPod(namespace, name, node string) *corev1.Pod {
	p := pod(namespace, name, node)
	p.Status.Phase = corev1.PodSucceeded
	return p
}

func pdb(namespace, app string, disruptionsAllowed int32) *policyv1.PodDisruptionBudget {
	return &policyv1.PodDisruptionBudget{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: app + "-pdb"},
		Spec:       policyv1.PodDisruptionBudgetSpec{Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": app}}},
		Status:     policyv1.PodDisruptionBudgetStatus{DisruptionsAllowed: disruptionsAllowed},
	}
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
	assert.Equal(t, "upgradecontrolplaneupgradetimeoutsre", (&Investigation{}).Name())
	assert.Equal(t, "UpgradeControlPlaneUpgradeTimeoutSRE", (&Investigation{}).AlertTitle())
}

func TestRun_InfrastructureClusterStopsChain(t *testing.T) {
	result, notes := runWith(t, &investigation.Resources{IsInfrastructureCluster: true})

	assert.True(t, hasAction(result.Actions, executor.ActionTypeEscalateIncident))
	assert.Error(t, result.StopInvestigations)
	assert.Contains(t, notes, "management/service cluster")
}

func TestRun_HCPEscalates(t *testing.T) {
	result, _ := runWith(t, &investigation.Resources{IsHCP: true})

	assert.True(t, hasAction(result.Actions, executor.ActionTypeEscalateIncident))
	assert.NoError(t, result.StopInvestigations)
}

func TestRun_MissingClusterVersionEscalates(t *testing.T) {
	result, notes := runWith(t, &investigation.Resources{K8sClient: newFakeClient(t)})

	assert.True(t, hasAction(result.Actions, executor.ActionTypeEscalateIncident))
	assert.False(t, hasAction(result.Actions, executor.ActionTypeSilenceIncident))
	assert.Contains(t, notes, "ClusterVersion: failed to get")
}

func TestRun_CompletedUpgradeSilences(t *testing.T) {
	result, notes := runWith(t, &investigation.Resources{K8sClient: newFakeClient(t, clusterVersion(toVersion, true))})

	assert.True(t, hasAction(result.Actions, executor.ActionTypeSilenceIncident))
	assert.False(t, hasAction(result.Actions, executor.ActionTypeEscalateIncident))
	assert.Nil(t, serviceLog(result.Actions))
	assert.Contains(t, notes, "upgrade to 4.20.2 has completed")
}

// MUO can fire before ClusterVersion status has observed the new desiredUpdate,
// so a status still describing the previous completed release must not be silenced.
func TestRun_StaleCompletedStatusIsNotSilenced(t *testing.T) {
	cv := clusterVersion(fromVersion, true)
	cv.Generation = 3
	cv.Status.ObservedGeneration = 2

	result, _ := runWith(t, &investigation.Resources{K8sClient: newFakeClient(t, cv)})

	assert.False(t, hasAction(result.Actions, executor.ActionTypeSilenceIncident))
	assert.True(t, hasAction(result.Actions, executor.ActionTypeEscalateIncident))
}

func TestRun_CustomerPDBSendsServiceLogAndSilences(t *testing.T) {
	k8s := newFakeClient(t,
		clusterVersion(toVersion, false),
		cordonedNode("master-1", 30*time.Minute),
		pod("customer-app", "web", "master-1"),
		pdb("customer-app", "web", 0),
	)

	result, notes := runWith(t, &investigation.Resources{K8sClient: k8s})

	sl := serviceLog(result.Actions)
	require.NotNil(t, sl, "customer PDB must send a service log")
	assert.Equal(t, "Action required: Pod Disruption Budget(s) preventing Node Drain", sl.ServiceLog.Summary)
	assert.Contains(t, sl.ServiceLog.Description, "`master-1`")
	assert.Contains(t, sl.ServiceLog.Description, "`customer-app/web`")
	assert.True(t, hasAction(result.Actions, executor.ActionTypeSilenceIncident))
	assert.False(t, hasAction(result.Actions, executor.ActionTypeEscalateIncident))
	assert.Contains(t, notes, "Customer-managed PDB(s) blocking node drain: customer-app/web-pdb")
}

func TestRun_PlatformPDBEscalatesWithoutServiceLog(t *testing.T) {
	k8s := newFakeClient(t,
		clusterVersion(toVersion, false),
		cordonedNode("master-1", 30*time.Minute),
		pod("customer-app", "web", "master-1"),
		pdb("customer-app", "web", 0),
		pod("openshift-etcd", "guard", "master-1"),
		pdb("openshift-etcd", "guard", 0),
	)

	result, notes := runWith(t, &investigation.Resources{K8sClient: k8s})

	assert.Nil(t, serviceLog(result.Actions), "never notify the customer while a platform PDB is also blocking")
	assert.True(t, hasAction(result.Actions, executor.ActionTypeEscalateIncident))
	assert.False(t, hasAction(result.Actions, executor.ActionTypeSilenceIncident))
	assert.Contains(t, notes, "Platform-managed PDB(s) blocking node drain: openshift-etcd/guard-pdb")
}

func TestRun_NoActionableCauseEscalates(t *testing.T) {
	tests := []struct {
		name string
		objs []client.Object
	}{
		{"no cordoned nodes", []client.Object{clusterVersion(toVersion, false), pod("customer-app", "web", "worker-1"), pdb("customer-app", "web", 0)}},
		{"recently cordoned node", []client.Object{clusterVersion(toVersion, false), cordonedNode("master-1", 2*time.Minute), pod("customer-app", "web", "master-1"), pdb("customer-app", "web", 0)}},
		{"PDB allows disruptions", []client.Object{clusterVersion(toVersion, false), cordonedNode("master-1", 30*time.Minute), pod("customer-app", "web", "master-1"), pdb("customer-app", "web", 1)}},
		{"only a completed pod on the stalled node", []client.Object{clusterVersion(toVersion, false), cordonedNode("master-1", 30*time.Minute), completedPod("customer-app", "web", "master-1"), pdb("customer-app", "web", 0)}},
		{"cordoned worker node", []client.Object{clusterVersion(toVersion, false), cordonedWorker("worker-1", 30*time.Minute), pod("customer-app", "web", "worker-1"), pdb("customer-app", "web", 0)}},
		{"PDB pod on another node", []client.Object{clusterVersion(toVersion, false), cordonedNode("master-1", 30*time.Minute), pod("customer-app", "web", "worker-1"), pdb("customer-app", "web", 0)}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, notes := runWith(t, &investigation.Resources{K8sClient: newFakeClient(t, tt.objs...)})

			assert.True(t, hasAction(result.Actions, executor.ActionTypeEscalateIncident))
			assert.Nil(t, serviceLog(result.Actions))
			assert.False(t, hasAction(result.Actions, executor.ActionTypeSilenceIncident))
			assert.Contains(t, notes, "No automated action")
		})
	}
}

func TestIsStalledDrain(t *testing.T) {
	now := time.Now()
	assert.True(t, isStalledDrain(*cordonedNode("a", 15*time.Minute), now))
	assert.False(t, isStalledDrain(*cordonedNode("b", time.Minute), now))
	assert.True(t, isStalledDrain(corev1.Node{Spec: corev1.NodeSpec{Taints: []corev1.Taint{{Key: corev1.TaintNodeUnschedulable, Effect: corev1.TaintEffectNoSchedule}}}}, now), "taint with no recorded time")
	assert.False(t, isStalledDrain(corev1.Node{Spec: corev1.NodeSpec{Unschedulable: true}}, now), "spec.unschedulable without the taint yet")
	assert.False(t, isStalledDrain(corev1.Node{}, now))
}

func TestIsControlPlaneNode(t *testing.T) {
	assert.True(t, isControlPlaneNode(corev1.Node{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"node-role.kubernetes.io/master": ""}}}))
	assert.True(t, isControlPlaneNode(corev1.Node{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"node-role.kubernetes.io/control-plane": ""}}}))
	assert.False(t, isControlPlaneNode(corev1.Node{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"node-role.kubernetes.io/worker": ""}}}))
}

func TestIsPlatformNamespace(t *testing.T) {
	for ns, want := range map[string]bool{
		"openshift":       true,
		"openshift-etcd":  true,
		"kube-system":     true,
		"customer-app":    false,
		"openshiftfoobar": false,
	} {
		assert.Equal(t, want, isPlatformNamespace(ns), ns)
	}
}

func TestFindBlockingPDBs_ListErrorIsReturned(t *testing.T) {
	// No policy/v1 in the scheme, so listing PDBs fails after a stalled node is found.
	s := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(s))
	k8s := fake.NewClientBuilder().WithScheme(s).WithObjects(cordonedNode("master-1", 30*time.Minute)).Build()

	_, err := findBlockingPDBs(context.Background(), k8s, time.Now())
	assert.Error(t, err)
}

package upgradecontrolplaneupgradetimeoutsre

import (
	"context"
	"strings"
	"testing"

	cmv1 "github.com/openshift-online/ocm-sdk-go/clustersmgmt/v1"
	configv1 "github.com/openshift/api/config/v1"
	mcfgv1 "github.com/openshift/api/machineconfiguration/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
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

func testScheme() *runtime.Scheme {
	s := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{corev1.AddToScheme, configv1.Install, mcfgv1.Install} {
		if err := add(s); err != nil {
			panic(err)
		}
	}
	return s
}

func newFakeClient(objs ...client.Object) client.Client {
	return fake.NewClientBuilder().WithScheme(testScheme()).WithObjects(objs...).Build()
}

func newNotes() *notewriter.NoteWriter {
	return notewriter.New(investigationName, logging.RawLogger)
}

func hasAction(actions []types.Action, actionType executor.ActionType) bool {
	for _, a := range actions {
		if a.Type() == string(actionType) {
			return true
		}
	}
	return false
}

func clusterVersion(desired string, completed bool, conds ...configv1.ClusterOperatorStatusCondition) *configv1.ClusterVersion {
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
			Conditions: conds,
		},
	}
}

func cvCondition(condType string, status configv1.ConditionStatus, msg string) configv1.ClusterOperatorStatusCondition {
	return configv1.ClusterOperatorStatusCondition{
		Type:    configv1.ClusterStatusConditionType(condType),
		Status:  status,
		Message: msg,
	}
}

func clusterOperator(name, version string, conds ...configv1.ClusterOperatorStatusCondition) *configv1.ClusterOperator {
	return &configv1.ClusterOperator{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Status: configv1.ClusterOperatorStatus{
			Versions:   []configv1.OperandVersion{{Name: operatorOperand, Version: version}},
			Conditions: conds,
		},
	}
}

func coCondition(condType configv1.ClusterStatusConditionType, status configv1.ConditionStatus, reason, msg string) configv1.ClusterOperatorStatusCondition {
	return configv1.ClusterOperatorStatusCondition{Type: condType, Status: status, Reason: reason, Message: msg}
}

func pool(name string, machines, updated, degraded int32, updating, isDegraded bool, msg string) *mcfgv1.MachineConfigPool {
	var conds []mcfgv1.MachineConfigPoolCondition
	if updating {
		conds = append(conds, mcfgv1.MachineConfigPoolCondition{Type: mcfgv1.MachineConfigPoolUpdating, Status: corev1.ConditionTrue})
	}
	if isDegraded {
		conds = append(conds, mcfgv1.MachineConfigPoolCondition{Type: mcfgv1.MachineConfigPoolDegraded, Status: corev1.ConditionTrue, Message: msg})
	}
	return &mcfgv1.MachineConfigPool{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Status: mcfgv1.MachineConfigPoolStatus{
			MachineCount:         machines,
			UpdatedMachineCount:  updated,
			DegradedMachineCount: degraded,
			Conditions:           conds,
		},
	}
}

func runWith(t *testing.T, res *investigation.Resources) (investigation.InvestigationResult, string) {
	t.Helper()
	cluster, err := cmv1.NewCluster().ID("test-123").Build()
	require.NoError(t, err)
	res.Cluster = cluster
	res.Notes = newNotes()

	result, err := (&Investigation{}).Run(&investigation.ResourceBuilderMock{Resources: res})
	require.NoError(t, err)
	return result, res.Notes.String()
}

// --- metadata ---

func TestNameMatchesPackage(t *testing.T) {
	assert.Equal(t, "upgradecontrolplaneupgradetimeoutsre", (&Investigation{}).Name())
	assert.Equal(t, "UpgradeControlPlaneUpgradeTimeoutSRE", (&Investigation{}).AlertTitle())
}

// --- Run: gates ---

func TestRun_InfrastructureClusterStopsChain(t *testing.T) {
	result, notes := runWith(t, &investigation.Resources{IsInfrastructureCluster: true})

	assert.True(t, hasAction(result.Actions, executor.ActionTypeEscalateIncident))
	assert.Error(t, result.StopInvestigations, "infra cluster must stop the chain so later investigations do not run")
	assert.Contains(t, notes, "management/service cluster")
}

func TestRun_HCPEscalates(t *testing.T) {
	result, notes := runWith(t, &investigation.Resources{IsHCP: true})

	assert.True(t, hasAction(result.Actions, executor.ActionTypeEscalateIncident))
	assert.NoError(t, result.StopInvestigations)
	assert.Contains(t, notes, "Classic (MUO) alert")
}

// --- Run: classic, read-only ---

func TestRun_NeverMutates(t *testing.T) {
	k8s := newFakeClient(clusterVersion(toVersion, false), pool(masterPool, 3, 1, 0, true, false, ""))
	result, _ := runWith(t, &investigation.Resources{K8sClient: k8s})

	assert.True(t, hasAction(result.Actions, executor.ActionTypeEscalateIncident), "informing stage always escalates")
	assert.False(t, hasAction(result.Actions, executor.ActionTypeSilenceIncident), "informing stage must not silence")
	assert.False(t, hasAction(result.Actions, executor.ActionTypeServiceLog), "informing stage must not send a service log")
	assert.False(t, hasAction(result.Actions, executor.ActionTypeLimitedSupport), "informing stage must not set limited support")
}

func TestRun_MasterPoolStalledPointsAtDrain(t *testing.T) {
	k8s := newFakeClient(
		clusterVersion(toVersion, false, cvCondition("Progressing", configv1.ConditionTrue, "Working towards 4.20.2: 790 of 900 done")),
		clusterOperator("kube-apiserver", toVersion),
		clusterOperator("machine-config", fromVersion),
		pool(masterPool, 3, 1, 0, true, false, ""),
		pool("worker", 3, 3, 0, false, false, ""),
	)
	_, notes := runWith(t, &investigation.Resources{K8sClient: k8s})

	assert.Contains(t, notes, "Likely blocker: master MachineConfigPool rollout stalled at 1/3 nodes")
	assert.Contains(t, notes, "pdbblockingnodedrain")
	assert.Contains(t, notes, "machine-config (at 4.19.10)")
}

func TestRun_CVOFailingWins(t *testing.T) {
	k8s := newFakeClient(
		clusterVersion(toVersion, false, cvCondition("Failing", configv1.ConditionTrue, "Cluster operator authentication is degraded")),
		clusterOperator("authentication", fromVersion, coCondition(configv1.OperatorDegraded, configv1.ConditionTrue, "OAuthServerDeploymentDegraded", "pods not ready")),
		pool(masterPool, 3, 1, 0, true, false, ""),
	)
	_, notes := runWith(t, &investigation.Resources{K8sClient: k8s})

	assert.Contains(t, notes, "Likely blocker: CVO reports Failing: Cluster operator authentication is degraded")
	assert.Contains(t, notes, "authentication (OAuthServerDeploymentDegraded)")
	assert.NotContains(t, notes, "pods not ready", "operator condition messages are not written to the note")
}

func TestRun_CompletedUpgrade(t *testing.T) {
	k8s := newFakeClient(
		clusterVersion(toVersion, true),
		clusterOperator("kube-apiserver", toVersion),
		pool(masterPool, 3, 3, 0, false, false, ""),
	)
	_, notes := runWith(t, &investigation.Resources{K8sClient: k8s})

	assert.Contains(t, notes, "Likely blocker: none: upgrade to 4.20.2 has completed")
}

// A failed MCP list must not be reported as "no blocker found".
func TestRun_MCPReadErrorIsInconclusive(t *testing.T) {
	noMCPScheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(noMCPScheme))
	require.NoError(t, configv1.Install(noMCPScheme))
	k8s := fake.NewClientBuilder().WithScheme(noMCPScheme).WithObjects(
		clusterVersion(toVersion, false),
		clusterOperator("kube-apiserver", toVersion),
	).Build()

	_, notes := runWith(t, &investigation.Resources{K8sClient: k8s})

	assert.Contains(t, notes, "MachineConfigPools: failed to list")
	assert.Contains(t, notes, "Likely blocker: inconclusive: could not read MachineConfigPools")
}

func TestRun_MissingClusterVersion(t *testing.T) {
	result, notes := runWith(t, &investigation.Resources{K8sClient: newFakeClient()})

	assert.True(t, hasAction(result.Actions, executor.ActionTypeEscalateIncident))
	assert.Contains(t, notes, "ClusterVersion: failed to get")
	assert.Contains(t, notes, "Likely blocker: could not read ClusterVersion")
}

// --- checks ---

func TestCheckClusterOperators_LaggingAndUnavailable(t *testing.T) {
	k8s := newFakeClient(
		clusterOperator("kube-apiserver", toVersion),
		clusterOperator("network", fromVersion),
		clusterOperator("ingress", fromVersion, coCondition(configv1.OperatorAvailable, configv1.ConditionFalse, "IngressUnavailable", "router pods\n  pending")),
	)
	state := upgradeState{DesiredVersion: toVersion}
	notes := newNotes()

	(&Investigation{}).checkClusterOperators(context.Background(), k8s, toVersion, &state, notes)

	assert.ElementsMatch(t, []string{"network (at 4.19.10)", "ingress (at 4.19.10)"}, state.LaggingOperators)
	require.Len(t, state.UnavailableOperators, 1)
	assert.Equal(t, "ingress (IngressUnavailable)", state.UnavailableOperators[0], "reason only, no raw message")
	assert.Empty(t, state.DegradedOperators)
}

func TestCheckMachineConfigPools_DegradedMaster(t *testing.T) {
	k8s := newFakeClient(
		pool(masterPool, 3, 2, 1, true, true, "Node master-2 is reporting: unexpected on-disk state"),
		pool("worker", 3, 3, 0, false, false, ""),
	)
	state := upgradeState{}
	notes := newNotes()

	(&Investigation{}).checkMachineConfigPools(context.Background(), k8s, &state, notes)

	require.NotNil(t, state.MasterPool)
	assert.True(t, state.MasterPool.IsDegraded)
	assert.NotContains(t, notes.String(), "worker:", "healthy non-master pools are not listed")
	assert.Contains(t, notes.String(), "master: 2/3 updated, DEGRADED (1 machine(s))")
}

func TestCheckMachineConfigPools_PausedAndNotUpdated(t *testing.T) {
	paused := pool(masterPool, 3, 1, 0, false, false, "")
	paused.Spec.Paused = true
	paused.Status.Conditions = append(paused.Status.Conditions,
		mcfgv1.MachineConfigPoolCondition{Type: mcfgv1.MachineConfigPoolUpdated, Status: corev1.ConditionFalse})
	notUpdated := pool("worker", 3, 2, 0, false, false, "")
	notUpdated.Status.Conditions = append(notUpdated.Status.Conditions,
		mcfgv1.MachineConfigPoolCondition{Type: mcfgv1.MachineConfigPoolUpdated, Status: corev1.ConditionFalse})

	state := upgradeState{}
	notes := newNotes()
	(&Investigation{}).checkMachineConfigPools(context.Background(), newFakeClient(paused, notUpdated), &state, notes)

	require.NotNil(t, state.MasterPool)
	assert.True(t, state.MasterPool.IsPaused)
	assert.Contains(t, notes.String(), "rollout not finished")
	assert.Contains(t, notes.String(), "master: 1/3 updated, PAUSED")
	assert.Contains(t, notes.String(), "worker: 2/3 updated, not progressing")
	assert.NotContains(t, notes.String(), "all 2 pools updated")
}

// --- classify ---

func TestClassify(t *testing.T) {
	master := func(updating, degraded bool) *poolState {
		return &poolState{Name: masterPool, Machines: 3, Updated: 1, IsUpdating: updating, IsDegraded: degraded, DegradedReason: "bad disk"}
	}

	tests := []struct {
		name  string
		state upgradeState
		want  string
	}{
		{"no clusterversion", upgradeState{}, "could not read ClusterVersion"},
		{"completed", upgradeState{DesiredVersion: toVersion, Completed: true, CVOFailing: "ignored"}, "none: upgrade to 4.20.2 has completed"},
		{"cvo failing", upgradeState{DesiredVersion: toVersion, CVOFailing: "x", DegradedOperators: []string{"y"}}, "CVO reports Failing: x"},
		{"unavailable before degraded", upgradeState{DesiredVersion: toVersion, UnavailableOperators: []string{"a"}, DegradedOperators: []string{"b"}}, "unavailable operator(s): a"},
		{"degraded", upgradeState{DesiredVersion: toVersion, DegradedOperators: []string{"b"}, MasterPool: master(true, true)}, "degraded operator(s): b"},
		{"master degraded", upgradeState{DesiredVersion: toVersion, MasterPool: master(true, true)}, "master MachineConfigPool degraded: bad disk"},
		{"master paused", upgradeState{DesiredVersion: toVersion, MasterPool: &poolState{Name: masterPool, Machines: 3, Updated: 1, IsPaused: true, NotUpdated: true}}, "master MachineConfigPool is paused at 1/3"},
		{"master not updated, not progressing", upgradeState{DesiredVersion: toVersion, MasterPool: &poolState{Name: masterPool, Machines: 3, Updated: 2, NotUpdated: true}}, "master MachineConfigPool not updated (Updated=False) and not progressing at 2/3"},
		{"master updating", upgradeState{DesiredVersion: toVersion, MasterPool: master(true, false)}, "master MachineConfigPool rollout stalled at 1/3"},
		{"read error beats lagging", upgradeState{DesiredVersion: toVersion, ReadErrors: []string{"MachineConfigPools"}, LaggingOperators: []string{"a"}}, "inconclusive: could not read MachineConfigPools"},
		{"slow", upgradeState{DesiredVersion: toVersion, LaggingOperators: []string{"a", "b"}}, "2 operator(s) not yet at 4.20.2"},
		{"nothing", upgradeState{DesiredVersion: toVersion}, "no blocker found"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classify(tt.state)
			assert.True(t, strings.HasPrefix(got, tt.want), "got %q, want prefix %q", got, tt.want)
		})
	}
}

func TestOneLine(t *testing.T) {
	assert.Equal(t, "a b c", oneLine("a\n  b\tc "))
	long := strings.Repeat("x", 400)
	assert.Len(t, oneLine(long), 303)
}

func TestCheckClusterVersion_ProgressingMessageOnlyWhenTrue(t *testing.T) {
	tests := []struct {
		name string
		cond configv1.ClusterOperatorStatusCondition
		want string
	}{
		{"progressing true", cvCondition("Progressing", configv1.ConditionTrue, "Working towards 4.20.2"), "in progress: Working towards 4.20.2"},
		{"progressing false", cvCondition("Progressing", configv1.ConditionFalse, "Cluster version is 4.19.10"), "not completed and CVO is not reporting Progressing"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state := upgradeState{}
			notes := newNotes()
			(&Investigation{}).checkClusterVersion(context.Background(), newFakeClient(clusterVersion(toVersion, false, tt.cond)), &state, notes)

			assert.Contains(t, notes.String(), tt.want)
			if tt.cond.Status != configv1.ConditionTrue {
				assert.Empty(t, state.CVOProgressing, "Progressing=False message must not be recorded")
			}
		})
	}
}

func TestCheckClusterOperators_NoDesiredVersionSkipsLag(t *testing.T) {
	state := upgradeState{}
	notes := newNotes()
	(&Investigation{}).checkClusterOperators(context.Background(), newFakeClient(clusterOperator("network", fromVersion)), "", &state, notes)

	assert.Empty(t, state.LaggingOperators)
}

func TestRun_StaleClusterVersionIsInconclusive(t *testing.T) {
	cv := clusterVersion(fromVersion, true) // status still describes the previous completed release
	cv.Generation = 3
	cv.Status.ObservedGeneration = 2
	k8s := newFakeClient(cv, clusterOperator("kube-apiserver", fromVersion), pool(masterPool, 3, 3, 0, false, false, ""))

	_, notes := runWith(t, &investigation.Resources{K8sClient: k8s})

	assert.Contains(t, notes, "status not yet updated for the latest spec")
	assert.Contains(t, notes, "Likely blocker: inconclusive: ClusterVersion status is stale (observedGeneration 2, generation 3)")
	assert.NotContains(t, notes, "has completed")
}

func TestCheckMachineConfigPools_PausedButUpdatedIsHealthy(t *testing.T) {
	paused := pool(masterPool, 3, 3, 0, false, false, "")
	paused.Spec.Paused = true
	paused.Status.Conditions = append(paused.Status.Conditions,
		mcfgv1.MachineConfigPoolCondition{Type: mcfgv1.MachineConfigPoolUpdated, Status: corev1.ConditionTrue})

	state := upgradeState{DesiredVersion: toVersion}
	notes := newNotes()
	(&Investigation{}).checkMachineConfigPools(context.Background(), newFakeClient(paused), &state, notes)

	require.NotNil(t, state.MasterPool)
	assert.Contains(t, notes.String(), "all 1 pools updated and not degraded")
	assert.NotContains(t, classify(state), "paused")
}

package pdbblockingnodedrain

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/openshift/configuration-anomaly-detection/pkg/notewriter"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func testScheme() *runtime.Scheme {
	s := runtime.NewScheme()
	_ = corev1.AddToScheme(s)
	_ = policyv1.AddToScheme(s)
	_ = appsv1.AddToScheme(s)
	return s
}

func newFakeClient(objs ...client.Object) client.Client {
	return fake.NewClientBuilder().WithScheme(testScheme()).WithObjects(objs...).Build()
}

func newTestNotes() *notewriter.NoteWriter {
	return notewriter.New("pdbblockingnodedrain", nil)
}

func timePtr(t time.Time) *metav1.Time {
	mt := metav1.NewTime(t)
	return &mt
}

func newNode(name string, taints []corev1.Taint) *corev1.Node {
	return &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec:       corev1.NodeSpec{Taints: taints},
	}
}

func newNodeWithConditions(name string, taints []corev1.Taint, conditions []corev1.NodeCondition) *corev1.Node {
	return &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec:       corev1.NodeSpec{Taints: taints},
		Status:     corev1.NodeStatus{Conditions: conditions},
	}
}

func readyCondition(status corev1.ConditionStatus) corev1.NodeCondition {
	return corev1.NodeCondition{Type: corev1.NodeReady, Status: status}
}

func pressureCondition(condType corev1.NodeConditionType) corev1.NodeCondition {
	return corev1.NodeCondition{Type: condType, Status: corev1.ConditionTrue}
}

func unschedulableTaint(timeAdded *metav1.Time) corev1.Taint {
	return corev1.Taint{
		Key:       corev1.TaintNodeUnschedulable,
		Effect:    corev1.TaintEffectNoSchedule,
		TimeAdded: timeAdded,
	}
}

func newLabeledPod(name, namespace, nodeName string, labels map[string]string, ownerRefs []metav1.OwnerReference) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:            name,
			Namespace:       namespace,
			Labels:          labels,
			OwnerReferences: ownerRefs,
		},
		Spec: corev1.PodSpec{NodeName: nodeName},
	}
}

func newPDB(name, namespace string, selector map[string]string, minAvailable *intstr.IntOrString, maxUnavailable *intstr.IntOrString, disruptionsAllowed, currentHealthy, expectedPods int32) *policyv1.PodDisruptionBudget {
	return &policyv1.PodDisruptionBudget{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: policyv1.PodDisruptionBudgetSpec{
			Selector:       &metav1.LabelSelector{MatchLabels: selector},
			MinAvailable:   minAvailable,
			MaxUnavailable: maxUnavailable,
		},
		Status: policyv1.PodDisruptionBudgetStatus{
			DisruptionsAllowed: disruptionsAllowed,
			CurrentHealthy:     currentHealthy,
			ExpectedPods:       expectedPods,
		},
	}
}

func intstrPtr(val int32) *intstr.IntOrString {
	v := intstr.FromInt32(val)
	return &v
}

func newReplicaSet(name, namespace, deploymentOwner string) *appsv1.ReplicaSet {
	rs := &appsv1.ReplicaSet{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
	}
	if deploymentOwner != "" {
		rs.OwnerReferences = []metav1.OwnerReference{
			{Kind: "Deployment", Name: deploymentOwner, APIVersion: "apps/v1"},
		}
	}
	return rs
}

// --- Interface method tests ---

func TestName(t *testing.T) {
	inv := &Investigation{}
	if inv.Name() != "pdbblockingnodedrain" {
		t.Errorf("expected 'pdbblockingnodedrain', got %q", inv.Name())
	}
}

func TestAlertTitle(t *testing.T) {
	inv := &Investigation{}
	if inv.AlertTitle() != "HCPNodepoolUpgradeDelay" {
		t.Errorf("expected 'HCPNodepoolUpgradeDelay', got %q", inv.AlertTitle())
	}
}

func TestDescription(t *testing.T) {
	inv := &Investigation{}
	if inv.Description() == "" {
		t.Error("expected non-empty description")
	}
}

// --- findUnschedulableTaint tests ---

func TestFindUnschedulableTaint_Present(t *testing.T) {
	node := corev1.Node{
		Spec: corev1.NodeSpec{
			Taints: []corev1.Taint{
				{Key: "other-taint", Effect: corev1.TaintEffectNoSchedule},
				unschedulableTaint(nil),
			},
		},
	}
	taint, found := findUnschedulableTaint(node)
	if !found {
		t.Fatal("expected taint to be found")
	}
	if taint.Key != corev1.TaintNodeUnschedulable {
		t.Errorf("unexpected taint key: %s", taint.Key)
	}
}

func TestFindUnschedulableTaint_Absent(t *testing.T) {
	node := corev1.Node{
		Spec: corev1.NodeSpec{
			Taints: []corev1.Taint{
				{Key: "other-taint", Effect: corev1.TaintEffectNoSchedule},
			},
		},
	}
	_, found := findUnschedulableTaint(node)
	if found {
		t.Error("expected taint to not be found")
	}
}

func TestFindUnschedulableTaint_WrongEffect(t *testing.T) {
	node := corev1.Node{
		Spec: corev1.NodeSpec{
			Taints: []corev1.Taint{
				{Key: corev1.TaintNodeUnschedulable, Effect: corev1.TaintEffectNoExecute},
			},
		},
	}
	_, found := findUnschedulableTaint(node)
	if found {
		t.Error("expected taint with wrong effect to not match")
	}
}

func TestFindUnschedulableTaint_NoTaints(t *testing.T) {
	node := corev1.Node{}
	_, found := findUnschedulableTaint(node)
	if found {
		t.Error("expected no taint found on node with no taints")
	}
}

// --- checkDrainingNodes tests ---

func TestCheckDrainingNodes_NoDrainingNodes(t *testing.T) {
	k8sClient := newFakeClient(
		newNode("node-1", nil),
		newNode("node-2", []corev1.Taint{{Key: "other", Effect: corev1.TaintEffectNoSchedule}}),
	)
	notes := newTestNotes()
	inv := &Investigation{}

	result := inv.checkDrainingNodes(context.Background(), k8sClient, notes)

	if result != nil {
		t.Errorf("expected nil, got %d stalled nodes", len(result))
	}
	if !strings.Contains(notes.String(), "no nodes are currently draining") {
		t.Errorf("expected 'no nodes are currently draining' in notes, got: %s", notes.String())
	}
}

func TestCheckDrainingNodes_AllUnderThreshold(t *testing.T) {
	recentTime := timePtr(time.Now().Add(-5 * time.Minute))
	k8sClient := newFakeClient(
		newNode("node-1", []corev1.Taint{unschedulableTaint(recentTime)}),
	)
	notes := newTestNotes()
	inv := &Investigation{}

	result := inv.checkDrainingNodes(context.Background(), k8sClient, notes)

	if result != nil {
		t.Errorf("expected nil (all under threshold), got %d stalled nodes", len(result))
	}
	if !strings.Contains(notes.String(), "none stalled") {
		t.Errorf("expected 'none stalled' in notes, got: %s", notes.String())
	}
}

func TestCheckDrainingNodes_StalledNode(t *testing.T) {
	stalledTime := timePtr(time.Now().Add(-30 * time.Minute))
	k8sClient := newFakeClient(
		newNode("stalled-node", []corev1.Taint{unschedulableTaint(stalledTime)}),
	)
	notes := newTestNotes()
	inv := &Investigation{}

	result := inv.checkDrainingNodes(context.Background(), k8sClient, notes)

	if len(result) != 1 {
		t.Fatalf("expected 1 stalled node, got %d", len(result))
	}
	if result[0].Node.Name != "stalled-node" {
		t.Errorf("expected 'stalled-node', got %q", result[0].Node.Name)
	}
	if !strings.Contains(notes.String(), "stalled") {
		t.Errorf("expected 'stalled' in notes, got: %s", notes.String())
	}
}

func TestCheckDrainingNodes_MixedStalledAndRecent(t *testing.T) {
	stalledTime := timePtr(time.Now().Add(-20 * time.Minute))
	recentTime := timePtr(time.Now().Add(-3 * time.Minute))
	k8sClient := newFakeClient(
		newNode("stalled-node", []corev1.Taint{unschedulableTaint(stalledTime)}),
		newNode("recent-node", []corev1.Taint{unschedulableTaint(recentTime)}),
		newNode("healthy-node", nil),
	)
	notes := newTestNotes()
	inv := &Investigation{}

	result := inv.checkDrainingNodes(context.Background(), k8sClient, notes)

	if len(result) != 1 {
		t.Fatalf("expected 1 stalled node, got %d", len(result))
	}
	if result[0].Node.Name != "stalled-node" {
		t.Errorf("expected 'stalled-node', got %q", result[0].Node.Name)
	}
	noteStr := notes.String()
	if !strings.Contains(noteStr, "1/2 draining node(s) stalled") {
		t.Errorf("expected '1/2 draining node(s) stalled' in notes, got: %s", noteStr)
	}
	if !strings.Contains(noteStr, "1 node(s) draining within threshold") {
		t.Errorf("expected '1 node(s) draining within threshold' in notes, got: %s", noteStr)
	}
}

func TestCheckDrainingNodes_MultipleStalledNodes(t *testing.T) {
	stalledTime1 := timePtr(time.Now().Add(-15 * time.Minute))
	stalledTime2 := timePtr(time.Now().Add(-45 * time.Minute))
	k8sClient := newFakeClient(
		newNode("stalled-1", []corev1.Taint{unschedulableTaint(stalledTime1)}),
		newNode("stalled-2", []corev1.Taint{unschedulableTaint(stalledTime2)}),
	)
	notes := newTestNotes()
	inv := &Investigation{}

	result := inv.checkDrainingNodes(context.Background(), k8sClient, notes)

	if len(result) != 2 {
		t.Fatalf("expected 2 stalled nodes, got %d", len(result))
	}
	if !strings.Contains(notes.String(), "2/2 draining node(s) stalled") {
		t.Errorf("expected '2/2 draining node(s) stalled' in notes, got: %s", notes.String())
	}
}

// --- checkNodeHealth tests ---

func TestCheckNodeHealth_AllHealthy(t *testing.T) {
	sn := newNodeWithConditions("stalled-node",
		[]corev1.Taint{unschedulableTaint(timePtr(time.Now().Add(-20 * time.Minute)))},
		[]corev1.NodeCondition{readyCondition(corev1.ConditionTrue)})
	healthyNode := newNodeWithConditions("healthy-node", nil,
		[]corev1.NodeCondition{readyCondition(corev1.ConditionTrue)})

	k8sClient := newFakeClient(sn, healthyNode)
	notes := newTestNotes()
	inv := &Investigation{}

	inv.checkNodeHealth(context.Background(), k8sClient, notes)

	noteStr := notes.String()
	if !strings.Contains(noteStr, "all non-draining nodes are Ready") {
		t.Errorf("expected healthy message, got: %s", noteStr)
	}
}

func TestCheckNodeHealth_NotReadyNode(t *testing.T) {
	sn := newNode("stalled-node", []corev1.Taint{unschedulableTaint(timePtr(time.Now().Add(-20 * time.Minute)))})
	notReadyNode := newNodeWithConditions("bad-node", nil,
		[]corev1.NodeCondition{readyCondition(corev1.ConditionFalse)})

	k8sClient := newFakeClient(sn, notReadyNode)
	notes := newTestNotes()
	inv := &Investigation{}

	inv.checkNodeHealth(context.Background(), k8sClient, notes)

	noteStr := notes.String()
	if !strings.Contains(noteStr, "bad-node: NotReady") {
		t.Errorf("expected NotReady warning for bad-node, got: %s", noteStr)
	}
	if !strings.Contains(noteStr, "evicted pods may fail to reschedule") {
		t.Errorf("expected reschedule warning, got: %s", noteStr)
	}
}

func TestCheckNodeHealth_DiskPressure(t *testing.T) {
	sn := newNode("stalled-node", []corev1.Taint{unschedulableTaint(timePtr(time.Now().Add(-20 * time.Minute)))})
	pressureNode := newNodeWithConditions("pressure-node", nil,
		[]corev1.NodeCondition{
			readyCondition(corev1.ConditionTrue),
			pressureCondition(corev1.NodeDiskPressure),
		})

	k8sClient := newFakeClient(sn, pressureNode)
	notes := newTestNotes()
	inv := &Investigation{}

	inv.checkNodeHealth(context.Background(), k8sClient, notes)

	noteStr := notes.String()
	if !strings.Contains(noteStr, "pressure-node: DiskPressure") {
		t.Errorf("expected DiskPressure warning, got: %s", noteStr)
	}
}

func TestCheckNodeHealth_MultipleIssues(t *testing.T) {
	sn := newNode("stalled-node", []corev1.Taint{unschedulableTaint(timePtr(time.Now().Add(-20 * time.Minute)))})
	badNode := newNodeWithConditions("bad-node", nil,
		[]corev1.NodeCondition{
			readyCondition(corev1.ConditionFalse),
			pressureCondition(corev1.NodeMemoryPressure),
			pressureCondition(corev1.NodePIDPressure),
		})

	k8sClient := newFakeClient(sn, badNode)
	notes := newTestNotes()
	inv := &Investigation{}

	inv.checkNodeHealth(context.Background(), k8sClient, notes)

	noteStr := notes.String()
	if !strings.Contains(noteStr, "NotReady") {
		t.Errorf("expected NotReady, got: %s", noteStr)
	}
	if !strings.Contains(noteStr, "MemoryPressure") {
		t.Errorf("expected MemoryPressure, got: %s", noteStr)
	}
	if !strings.Contains(noteStr, "PIDPressure") {
		t.Errorf("expected PIDPressure, got: %s", noteStr)
	}
}

func TestCheckNodeHealth_StalledNodeExcluded(t *testing.T) {
	sn := newNodeWithConditions("stalled-node",
		[]corev1.Taint{unschedulableTaint(timePtr(time.Now().Add(-20 * time.Minute)))},
		[]corev1.NodeCondition{readyCondition(corev1.ConditionFalse)})

	k8sClient := newFakeClient(sn)
	notes := newTestNotes()
	inv := &Investigation{}

	inv.checkNodeHealth(context.Background(), k8sClient, notes)

	noteStr := notes.String()
	if !strings.Contains(noteStr, "all non-draining nodes are Ready") {
		t.Errorf("stalled node should be excluded from health check, got: %s", noteStr)
	}
}

func TestCheckNodeHealth_RecentlyDrainingNodeExcluded(t *testing.T) {
	// A node draining for less than the stall threshold should still be excluded
	// from health checks since it's unschedulable and can't accept rescheduled pods.
	recentDraining := newNodeWithConditions("recent-draining",
		[]corev1.Taint{unschedulableTaint(timePtr(time.Now().Add(-2 * time.Minute)))},
		[]corev1.NodeCondition{readyCondition(corev1.ConditionFalse)})

	k8sClient := newFakeClient(recentDraining)
	notes := newTestNotes()
	inv := &Investigation{}

	inv.checkNodeHealth(context.Background(), k8sClient, notes)

	noteStr := notes.String()
	if !strings.Contains(noteStr, "all non-draining nodes are Ready") {
		t.Errorf("recently-draining node should be excluded from health check, got: %s", noteStr)
	}
}

// --- checkBlockingPDBs tests ---

func TestCheckBlockingPDBs_NoBlockingPDBs(t *testing.T) {
	sn := newNode("stalled-node", nil)
	appLabels := map[string]string{"app": "web"}
	pod := newLabeledPod("web-abc-1", "default", "stalled-node", appLabels, nil)
	pdb := newPDB("web-pdb", "default", appLabels, intstrPtr(1), nil, 1, 2, 2)

	k8sClient := newFakeClient(sn, pod, pdb)
	notes := newTestNotes()
	inv := &Investigation{}

	stalledNodes := []stalledNode{{Node: *sn}}
	result := inv.checkBlockingPDBs(context.Background(), k8sClient, stalledNodes, notes)

	if result != nil {
		t.Errorf("expected nil (PDB allows disruptions), got %d blocking PDBs", len(result))
	}
	if !strings.Contains(notes.String(), "no PDBs with disruptionsAllowed=0") {
		t.Errorf("expected 'no PDBs with disruptionsAllowed=0' in notes, got: %s", notes.String())
	}
}

func TestCheckBlockingPDBs_BlockingPDBWithMinAvailable(t *testing.T) {
	sn := newNode("stalled-node", nil)
	appLabels := map[string]string{"app": "web"}
	pod := newLabeledPod("web-abc-1", "default", "stalled-node", appLabels, nil)
	pdb := newPDB("web-pdb", "default", appLabels, intstrPtr(2), nil, 0, 2, 2)

	k8sClient := newFakeClient(sn, pod, pdb)
	notes := newTestNotes()
	inv := &Investigation{}

	stalledNodes := []stalledNode{{Node: *sn}}
	result := inv.checkBlockingPDBs(context.Background(), k8sClient, stalledNodes, notes)

	if len(result) != 1 {
		t.Fatalf("expected 1 blocking PDB, got %d", len(result))
	}
	bp := result[0]
	if bp.Name != "web-pdb" || bp.Namespace != "default" {
		t.Errorf("expected default/web-pdb, got %s/%s", bp.Namespace, bp.Name)
	}
	if bp.MinAvailable != "2" {
		t.Errorf("expected MinAvailable '2', got %q", bp.MinAvailable)
	}
	if len(bp.MatchingPods) != 1 || bp.MatchingPods[0] != "web-abc-1" {
		t.Errorf("expected matching pod 'web-abc-1', got %v", bp.MatchingPods)
	}
	noteStr := notes.String()
	if !strings.Contains(noteStr, "1 PDB(s) with disruptionsAllowed=0") {
		t.Errorf("expected '1 PDB(s) with disruptionsAllowed=0' in notes, got: %s", noteStr)
	}
	if !strings.Contains(noteStr, "minAvailable: 2") {
		t.Errorf("expected 'minAvailable: 2' in notes, got: %s", noteStr)
	}
}

func TestCheckBlockingPDBs_BlockingPDBWithMaxUnavailable(t *testing.T) {
	sn := newNode("stalled-node", nil)
	appLabels := map[string]string{"app": "db"}
	pod := newLabeledPod("db-0", "prod", "stalled-node", appLabels, nil)
	pdb := newPDB("db-pdb", "prod", appLabels, nil, intstrPtr(0), 0, 3, 3)

	k8sClient := newFakeClient(sn, pod, pdb)
	notes := newTestNotes()
	inv := &Investigation{}

	stalledNodes := []stalledNode{{Node: *sn}}
	result := inv.checkBlockingPDBs(context.Background(), k8sClient, stalledNodes, notes)

	if len(result) != 1 {
		t.Fatalf("expected 1 blocking PDB, got %d", len(result))
	}
	if result[0].MaxUnavailable != "0" {
		t.Errorf("expected MaxUnavailable '0', got %q", result[0].MaxUnavailable)
	}
	if !strings.Contains(notes.String(), "maxUnavailable: 0") {
		t.Errorf("expected 'maxUnavailable: 0' in notes, got: %s", notes.String())
	}
}

func TestCheckBlockingPDBs_PodNotOnStalledNode(t *testing.T) {
	sn := newNode("stalled-node", nil)
	appLabels := map[string]string{"app": "web"}
	pod := newLabeledPod("web-abc-1", "default", "other-node", appLabels, nil)
	pdb := newPDB("web-pdb", "default", appLabels, intstrPtr(2), nil, 0, 2, 2)

	k8sClient := newFakeClient(sn, pod, pdb)
	notes := newTestNotes()
	inv := &Investigation{}

	stalledNodes := []stalledNode{{Node: *sn}}
	result := inv.checkBlockingPDBs(context.Background(), k8sClient, stalledNodes, notes)

	if result != nil {
		t.Errorf("expected nil (pod not on stalled node), got %d blocking PDBs", len(result))
	}
}

func TestCheckBlockingPDBs_LabelMismatch(t *testing.T) {
	sn := newNode("stalled-node", nil)
	pod := newLabeledPod("web-abc-1", "default", "stalled-node", map[string]string{"app": "api"}, nil)
	pdb := newPDB("web-pdb", "default", map[string]string{"app": "web"}, intstrPtr(2), nil, 0, 2, 2)

	k8sClient := newFakeClient(sn, pod, pdb)
	notes := newTestNotes()
	inv := &Investigation{}

	stalledNodes := []stalledNode{{Node: *sn}}
	result := inv.checkBlockingPDBs(context.Background(), k8sClient, stalledNodes, notes)

	if result != nil {
		t.Errorf("expected nil (label mismatch), got %d blocking PDBs", len(result))
	}
}

func TestCheckBlockingPDBs_ResolvesDeploymentOwner(t *testing.T) {
	sn := newNode("stalled-node", nil)
	appLabels := map[string]string{"app": "web"}
	ownerRefs := []metav1.OwnerReference{
		{Kind: "ReplicaSet", Name: "web-deploy-abc", APIVersion: "apps/v1"},
	}
	pod := newLabeledPod("web-deploy-abc-1", "default", "stalled-node", appLabels, ownerRefs)
	rs := newReplicaSet("web-deploy-abc", "default", "web-deploy")
	pdb := newPDB("web-pdb", "default", appLabels, intstrPtr(2), nil, 0, 2, 2)

	k8sClient := newFakeClient(sn, pod, rs, pdb)
	notes := newTestNotes()
	inv := &Investigation{}

	stalledNodes := []stalledNode{{Node: *sn}}
	result := inv.checkBlockingPDBs(context.Background(), k8sClient, stalledNodes, notes)

	if len(result) != 1 {
		t.Fatalf("expected 1 blocking PDB, got %d", len(result))
	}
	if len(result[0].OwnerWorkloads) != 1 || result[0].OwnerWorkloads[0] != "Deployment/web-deploy" {
		t.Errorf("expected owner 'Deployment/web-deploy', got %v", result[0].OwnerWorkloads)
	}
	if !strings.Contains(notes.String(), "Deployment/web-deploy") {
		t.Errorf("expected 'Deployment/web-deploy' in notes, got: %s", notes.String())
	}
}

func TestCheckBlockingPDBs_ResolvesStatefulSetOwner(t *testing.T) {
	sn := newNode("stalled-node", nil)
	appLabels := map[string]string{"app": "db"}
	ownerRefs := []metav1.OwnerReference{
		{Kind: "StatefulSet", Name: "db-sts", APIVersion: "apps/v1"},
	}
	pod := newLabeledPod("db-sts-0", "default", "stalled-node", appLabels, ownerRefs)
	pdb := newPDB("db-pdb", "default", appLabels, intstrPtr(2), nil, 0, 2, 2)

	k8sClient := newFakeClient(sn, pod, pdb)
	notes := newTestNotes()
	inv := &Investigation{}

	stalledNodes := []stalledNode{{Node: *sn}}
	result := inv.checkBlockingPDBs(context.Background(), k8sClient, stalledNodes, notes)

	if len(result) != 1 {
		t.Fatalf("expected 1 blocking PDB, got %d", len(result))
	}
	if len(result[0].OwnerWorkloads) != 1 || result[0].OwnerWorkloads[0] != "StatefulSet/db-sts" {
		t.Errorf("expected owner 'StatefulSet/db-sts', got %v", result[0].OwnerWorkloads)
	}
}

func TestCheckBlockingPDBs_NoOwner(t *testing.T) {
	sn := newNode("stalled-node", nil)
	appLabels := map[string]string{"app": "standalone"}
	pod := newLabeledPod("standalone-pod", "default", "stalled-node", appLabels, nil)
	pdb := newPDB("standalone-pdb", "default", appLabels, intstrPtr(1), nil, 0, 1, 1)

	k8sClient := newFakeClient(sn, pod, pdb)
	notes := newTestNotes()
	inv := &Investigation{}

	stalledNodes := []stalledNode{{Node: *sn}}
	result := inv.checkBlockingPDBs(context.Background(), k8sClient, stalledNodes, notes)

	if len(result) != 1 {
		t.Fatalf("expected 1 blocking PDB, got %d", len(result))
	}
	if len(result[0].OwnerWorkloads) != 1 || result[0].OwnerWorkloads[0] != ownerNone {
		t.Errorf("expected owner 'none', got %v", result[0].OwnerWorkloads)
	}
}

func TestCheckBlockingPDBs_MultipleBlockingPDBs(t *testing.T) {
	sn := newNode("stalled-node", nil)
	webLabels := map[string]string{"app": "web"}
	dbLabels := map[string]string{"app": "db"}
	webPod := newLabeledPod("web-1", "default", "stalled-node", webLabels, nil)
	dbPod := newLabeledPod("db-0", "default", "stalled-node", dbLabels, nil)
	webPDB := newPDB("web-pdb", "default", webLabels, intstrPtr(2), nil, 0, 2, 2)
	dbPDB := newPDB("db-pdb", "default", dbLabels, intstrPtr(1), nil, 0, 1, 1)

	k8sClient := newFakeClient(sn, webPod, dbPod, webPDB, dbPDB)
	notes := newTestNotes()
	inv := &Investigation{}

	stalledNodes := []stalledNode{{Node: *sn}}
	result := inv.checkBlockingPDBs(context.Background(), k8sClient, stalledNodes, notes)

	if len(result) != 2 {
		t.Fatalf("expected 2 blocking PDBs, got %d", len(result))
	}
	if !strings.Contains(notes.String(), "2 PDB(s) with disruptionsAllowed=0") {
		t.Errorf("expected '2 PDB(s) with disruptionsAllowed=0' in notes, got: %s", notes.String())
	}
}

// --- isPlatformNamespace tests ---

func TestIsPlatformNamespace(t *testing.T) {
	tests := []struct {
		namespace string
		expected  bool
	}{
		{"openshift-monitoring", true},
		{"openshift-ingress", true},
		{"openshift", true},
		{"kube-system", true},
		{"kube-public", true},
		{"default", false},
		{"my-app", false},
		{"production", false},
		{"openshift-like-app", true},
		{"not-openshift", false},
	}

	for _, tt := range tests {
		t.Run(tt.namespace, func(t *testing.T) {
			result := isPlatformNamespace(tt.namespace)
			if result != tt.expected {
				t.Errorf("isPlatformNamespace(%q) = %v, want %v", tt.namespace, result, tt.expected)
			}
		})
	}
}

// --- checkBlockingPDBs classification tests ---

func TestCheckBlockingPDBs_CustomerManagedClassification(t *testing.T) {
	sn := newNode("stalled-node", nil)
	appLabels := map[string]string{"app": "web"}
	pod := newLabeledPod("web-1", "my-app", "stalled-node", appLabels, nil)
	pdb := newPDB("web-pdb", "my-app", appLabels, intstrPtr(2), nil, 0, 2, 2)

	k8sClient := newFakeClient(sn, pod, pdb)
	notes := newTestNotes()
	inv := &Investigation{}

	stalledNodes := []stalledNode{{Node: *sn}}
	result := inv.checkBlockingPDBs(context.Background(), k8sClient, stalledNodes, notes)

	if len(result) != 1 {
		t.Fatalf("expected 1 blocking PDB, got %d", len(result))
	}
	if result[0].IsPlatformManaged {
		t.Error("expected customer-managed PDB, got platform-managed")
	}
	noteStr := notes.String()
	if !strings.Contains(noteStr, "[customer]") {
		t.Errorf("expected '[customer]' tag in notes, got: %s", noteStr)
	}
	if !strings.Contains(noteStr, "customer-managed PDB(s)") {
		t.Errorf("expected customer remediation guidance in notes, got: %s", noteStr)
	}
}

func TestCheckBlockingPDBs_PlatformManagedClassification(t *testing.T) {
	sn := newNode("stalled-node", nil)
	appLabels := map[string]string{"app": "router"}
	pod := newLabeledPod("router-1", "openshift-ingress", "stalled-node", appLabels, nil)
	pdb := newPDB("router-pdb", "openshift-ingress", appLabels, intstrPtr(1), nil, 0, 1, 1)

	k8sClient := newFakeClient(sn, pod, pdb)
	notes := newTestNotes()
	inv := &Investigation{}

	stalledNodes := []stalledNode{{Node: *sn}}
	result := inv.checkBlockingPDBs(context.Background(), k8sClient, stalledNodes, notes)

	if len(result) != 1 {
		t.Fatalf("expected 1 blocking PDB, got %d", len(result))
	}
	if !result[0].IsPlatformManaged {
		t.Error("expected platform-managed PDB, got customer-managed")
	}
	noteStr := notes.String()
	if !strings.Contains(noteStr, "[platform]") {
		t.Errorf("expected '[platform]' tag in notes, got: %s", noteStr)
	}
	if !strings.Contains(noteStr, "platform-managed PDB(s)") {
		t.Errorf("expected platform remediation guidance in notes, got: %s", noteStr)
	}
}

func TestCheckBlockingPDBs_MixedClassification(t *testing.T) {
	sn := newNode("stalled-node", nil)
	customerLabels := map[string]string{"app": "web"}
	platformLabels := map[string]string{"app": "router"}
	customerPod := newLabeledPod("web-1", "my-app", "stalled-node", customerLabels, nil)
	platformPod := newLabeledPod("router-1", "openshift-ingress", "stalled-node", platformLabels, nil)
	customerPDB := newPDB("web-pdb", "my-app", customerLabels, intstrPtr(2), nil, 0, 2, 2)
	platformPDB := newPDB("router-pdb", "openshift-ingress", platformLabels, intstrPtr(1), nil, 0, 1, 1)

	k8sClient := newFakeClient(sn, customerPod, platformPod, customerPDB, platformPDB)
	notes := newTestNotes()
	inv := &Investigation{}

	stalledNodes := []stalledNode{{Node: *sn}}
	result := inv.checkBlockingPDBs(context.Background(), k8sClient, stalledNodes, notes)

	if len(result) != 2 {
		t.Fatalf("expected 2 blocking PDBs, got %d", len(result))
	}
	noteStr := notes.String()
	if !strings.Contains(noteStr, "customer-managed PDB(s)") {
		t.Errorf("expected customer remediation guidance in notes, got: %s", noteStr)
	}
	if !strings.Contains(noteStr, "platform-managed PDB(s)") {
		t.Errorf("expected platform remediation guidance in notes, got: %s", noteStr)
	}
}

// --- resolveWorkloadOwner tests ---

func TestResolveWorkloadOwner_DeploymentViaReplicaSet(t *testing.T) {
	rs := newReplicaSet("deploy-abc-123", "default", "my-deploy")
	k8sClient := newFakeClient(rs)

	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "deploy-abc-123-xyz",
			Namespace: "default",
			OwnerReferences: []metav1.OwnerReference{
				{Kind: "ReplicaSet", Name: "deploy-abc-123", APIVersion: "apps/v1"},
			},
		},
	}

	owner := resolveWorkloadOwner(context.Background(), k8sClient, pod)
	if owner != "Deployment/my-deploy" {
		t.Errorf("expected 'Deployment/my-deploy', got %q", owner)
	}
}

func TestResolveWorkloadOwner_StandaloneReplicaSet(t *testing.T) {
	rs := newReplicaSet("standalone-rs", "default", "")
	k8sClient := newFakeClient(rs)

	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "standalone-rs-xyz",
			Namespace: "default",
			OwnerReferences: []metav1.OwnerReference{
				{Kind: "ReplicaSet", Name: "standalone-rs", APIVersion: "apps/v1"},
			},
		},
	}

	owner := resolveWorkloadOwner(context.Background(), k8sClient, pod)
	if owner != "ReplicaSet/standalone-rs" {
		t.Errorf("expected 'ReplicaSet/standalone-rs', got %q", owner)
	}
}

func TestResolveWorkloadOwner_StatefulSet(t *testing.T) {
	k8sClient := newFakeClient()

	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "db-0",
			Namespace: "default",
			OwnerReferences: []metav1.OwnerReference{
				{Kind: "StatefulSet", Name: "db", APIVersion: "apps/v1"},
			},
		},
	}

	owner := resolveWorkloadOwner(context.Background(), k8sClient, pod)
	if owner != "StatefulSet/db" {
		t.Errorf("expected 'StatefulSet/db', got %q", owner)
	}
}

func TestResolveWorkloadOwner_NoneWhenNoOwner(t *testing.T) {
	k8sClient := newFakeClient()

	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "standalone", Namespace: "default"},
	}

	owner := resolveWorkloadOwner(context.Background(), k8sClient, pod)
	if owner != ownerNone {
		t.Errorf("expected 'none', got %q", owner)
	}
}

// --- assessScaling tests ---

func TestAssessScaling(t *testing.T) {
	tests := []struct {
		name           string
		bp             blockingPDB
		expectCanScale bool
		expectContains string
	}{
		{
			name: "maxUnavailable=0 integer",
			bp: blockingPDB{
				MaxUnavailable: "0",
				ExpectedPods:   3,
				CurrentHealthy: 3,
			},
			expectCanScale: false,
			expectContains: "maxUnavailable=0 forbids all disruptions",
		},
		{
			name: "maxUnavailable=0%",
			bp: blockingPDB{
				MaxUnavailable: "0%",
				ExpectedPods:   3,
				CurrentHealthy: 3,
			},
			expectCanScale: false,
			expectContains: "maxUnavailable=0 forbids all disruptions",
		},
		{
			name: "maxUnavailable>0 with unhealthy pods",
			bp: blockingPDB{
				MaxUnavailable: "1",
				ExpectedPods:   3,
				CurrentHealthy: 2,
			},
			expectCanScale: false,
			expectContains: "unhealthy pods must recover",
		},
		{
			name: "minAvailable=100%",
			bp: blockingPDB{
				MinAvailable:   "100%",
				ExpectedPods:   3,
				CurrentHealthy: 3,
			},
			expectCanScale: false,
			expectContains: "minAvailable=100%",
		},
		{
			name: "minAvailable all healthy — scaling helps",
			bp: blockingPDB{
				MinAvailable:   "2",
				ExpectedPods:   2,
				CurrentHealthy: 2,
			},
			expectCanScale: true,
			expectContains: "would unblock the drain",
		},
		{
			name: "minAvailable some unhealthy",
			bp: blockingPDB{
				MinAvailable:   "3",
				ExpectedPods:   4,
				CurrentHealthy: 3,
			},
			expectCanScale: true,
			expectContains: "1 of 4 pod(s) currently unhealthy",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, canScale := assessScaling(tt.bp)
			if canScale != tt.expectCanScale {
				t.Errorf("expected canScale=%v, got %v", tt.expectCanScale, canScale)
			}
			if !strings.Contains(result, tt.expectContains) {
				t.Errorf("expected to contain %q, got: %s", tt.expectContains, result)
			}
		})
	}
}

// --- checkScalingAssessment tests ---

func TestCheckScalingAssessment_NoPDBs(t *testing.T) {
	notes := newTestNotes()
	inv := &Investigation{}

	inv.checkScalingAssessment(nil, 0, notes)

	if strings.Contains(notes.String(), "Scaling Assessment") {
		t.Errorf("expected no scaling notes for nil PDBs, got: %s", notes.String())
	}
}

func TestCheckScalingAssessment_ScalableAndNotScalable(t *testing.T) {
	notes := newTestNotes()
	inv := &Investigation{}

	pdbs := []blockingPDB{
		{
			Namespace:      "app-ns",
			Name:           "scalable-pdb",
			MinAvailable:   "2",
			ExpectedPods:   2,
			CurrentHealthy: 2,
		},
		{
			Namespace:      "db-ns",
			Name:           "stuck-pdb",
			MaxUnavailable: "0",
			ExpectedPods:   3,
			CurrentHealthy: 3,
		},
	}

	inv.checkScalingAssessment(pdbs, 0, notes)

	noteStr := notes.String()
	if !strings.Contains(noteStr, "1 PDB(s) can be unblocked by scaling") {
		t.Errorf("expected scalable note, got: %s", noteStr)
	}
	if !strings.Contains(noteStr, "1 PDB(s) cannot be unblocked by scaling") {
		t.Errorf("expected not-scalable note, got: %s", noteStr)
	}
	if !strings.Contains(noteStr, "app-ns/scalable-pdb") {
		t.Errorf("expected scalable PDB name in notes, got: %s", noteStr)
	}
	if !strings.Contains(noteStr, "db-ns/stuck-pdb") {
		t.Errorf("expected stuck PDB name in notes, got: %s", noteStr)
	}
}

func TestCheckScalingAssessment_AllScalable(t *testing.T) {
	notes := newTestNotes()
	inv := &Investigation{}

	pdbs := []blockingPDB{
		{
			Namespace:      "app-ns",
			Name:           "web-pdb",
			MinAvailable:   "3",
			ExpectedPods:   3,
			CurrentHealthy: 3,
		},
	}

	inv.checkScalingAssessment(pdbs, 0, notes)

	noteStr := notes.String()
	if !strings.Contains(noteStr, "1 PDB(s) can be unblocked by scaling") {
		t.Errorf("expected scalable note, got: %s", noteStr)
	}
	if strings.Contains(noteStr, "cannot be unblocked") {
		t.Errorf("did not expect not-scalable note, got: %s", noteStr)
	}
}

func TestCheckScalingAssessment_UnhealthyNodesCaveat(t *testing.T) {
	notes := newTestNotes()
	inv := &Investigation{}

	pdbs := []blockingPDB{
		{
			Namespace:      "app-ns",
			Name:           "web-pdb",
			MinAvailable:   "2",
			ExpectedPods:   2,
			CurrentHealthy: 2,
		},
	}

	inv.checkScalingAssessment(pdbs, 2, notes)

	noteStr := notes.String()
	if !strings.Contains(noteStr, "1 PDB(s) can be unblocked by scaling") {
		t.Errorf("expected scalable note, got: %s", noteStr)
	}
	if !strings.Contains(noteStr, "2 non-draining node(s) are unhealthy") {
		t.Errorf("expected unhealthy node caveat, got: %s", noteStr)
	}
	if !strings.Contains(noteStr, "new replicas may not schedule") {
		t.Errorf("expected scheduling warning, got: %s", noteStr)
	}
}

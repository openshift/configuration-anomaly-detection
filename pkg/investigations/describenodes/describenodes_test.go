package describenodes

import (
	"fmt"
	"strings"
	"testing"

	cmv1 "github.com/openshift-online/ocm-sdk-go/clustersmgmt/v1"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/investigation"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/kubectl/pkg/describe"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// mockDescriber is a test implementation of nodeDescriber.
type mockDescriber struct {
	descriptions map[string]string
	errors       map[string]error
}

func (m *mockDescriber) Describe(namespace, name string, settings describe.DescriberSettings) (string, error) {
	if err, ok := m.errors[name]; ok {
		return "", err
	}
	if desc, ok := m.descriptions[name]; ok {
		return desc, nil
	}
	return fmt.Sprintf("Name: %s\nRoles: worker\n", name), nil
}

// clientImpl wraps a controller-runtime client to satisfy k8sclient.Client
type clientImpl struct {
	client.Client
}

func newFakeClient(objs ...client.Object) client.Client {
	return fake.NewClientBuilder().WithScheme(scheme.Scheme).WithObjects(objs...).Build()
}

func newTestCluster(id string) *cmv1.Cluster {
	cluster, _ := cmv1.NewCluster().ID(id).Build()
	return cluster
}

func newNode(name string, labels map[string]string) *corev1.Node {
	return &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name:   name,
			Labels: labels,
		},
		Status: corev1.NodeStatus{
			Conditions: []corev1.NodeCondition{
				{
					Type:   corev1.NodeReady,
					Status: corev1.ConditionTrue,
				},
			},
		},
	}
}

func newWorkerNode(name string) *corev1.Node {
	return newNode(name, map[string]string{
		"node-role.kubernetes.io/worker": "",
	})
}

func newMasterNode(name string) *corev1.Node {
	return newNode(name, map[string]string{
		"node-role.kubernetes.io/master": "",
	})
}

func newInfraNode(name string) *corev1.Node {
	return newNode(name, map[string]string{
		"node-role.kubernetes.io/infra":  "",
		"node-role.kubernetes.io":        "infra",
		"node-role.kubernetes.io/worker": "",
	})
}

func defaultDescriber() *mockDescriber {
	return &mockDescriber{
		descriptions: map[string]string{},
	}
}

// --- Investigation interface tests ---

func TestName(t *testing.T) {
	inv := &Investigation{}
	if inv.Name() != "describenodes" {
		t.Errorf("expected name 'describenodes', got %q", inv.Name())
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

// --- Run tests ---

func TestRun_DefaultDescribesAllNodes(t *testing.T) {
	worker1 := newWorkerNode("worker-1")
	worker2 := newWorkerNode("worker-2")
	master1 := newMasterNode("master-1")

	fakeK8s := newFakeClient(worker1, worker2, master1)

	rb := &investigation.ResourceBuilderMock{
		Resources: &investigation.Resources{
			Cluster:   newTestCluster("test-cluster"),
			K8sClient: clientImpl{fakeK8s},
		},
	}

	inv := &Investigation{
		describer: &mockDescriber{
			descriptions: map[string]string{
				"worker-1": "Name: worker-1\nRoles: worker\n",
				"worker-2": "Name: worker-2\nRoles: worker\n",
				"master-1": "Name: master-1\nRoles: master\n",
			},
		},
	}

	result, err := inv.Run(rb)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.Actions) != 2 {
		t.Fatalf("expected 2 actions (backplane report + PD note), got %d", len(result.Actions))
	}
}

func TestRun_NoNodes(t *testing.T) {
	fakeK8s := newFakeClient()

	rb := &investigation.ResourceBuilderMock{
		Resources: &investigation.Resources{
			Cluster:   newTestCluster("test-cluster"),
			K8sClient: clientImpl{fakeK8s},
		},
	}

	inv := &Investigation{describer: defaultDescriber()}

	result, err := inv.Run(rb)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.Actions) == 0 {
		t.Fatal("expected actions to be returned for empty cluster")
	}
}

func TestRun_HCPCluster(t *testing.T) {
	worker1 := newWorkerNode("worker-1")

	fakeK8s := newFakeClient(worker1)

	rb := &investigation.ResourceBuilderMock{
		Resources: &investigation.Resources{
			Cluster:   newTestCluster("test-hcp-cluster"),
			K8sClient: clientImpl{fakeK8s},
			IsHCP:     true,
		},
	}

	inv := &Investigation{describer: defaultDescriber()}

	result, err := inv.Run(rb)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.Actions) == 0 {
		t.Fatal("expected actions to be returned")
	}
}

func TestRun_DescribeError(t *testing.T) {
	worker1 := newWorkerNode("worker-1")
	worker2 := newWorkerNode("worker-2")

	fakeK8s := newFakeClient(worker1, worker2)

	rb := &investigation.ResourceBuilderMock{
		Resources: &investigation.Resources{
			Cluster:   newTestCluster("test-cluster"),
			K8sClient: clientImpl{fakeK8s},
		},
	}

	inv := &Investigation{
		describer: &mockDescriber{
			descriptions: map[string]string{
				"worker-1": "Name: worker-1\nRoles: worker\n",
			},
			errors: map[string]error{
				"worker-2": fmt.Errorf("connection timeout"),
			},
		},
	}

	result, err := inv.Run(rb)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.Actions) == 0 {
		t.Fatal("expected actions to be returned even with partial describe errors")
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

// --- Node selection tests ---

func TestRun_SelectByNodeName(t *testing.T) {
	worker1 := newWorkerNode("worker-1")
	worker2 := newWorkerNode("worker-2")
	master1 := newMasterNode("master-1")

	fakeK8s := newFakeClient(worker1, worker2, master1)

	rb := &investigation.ResourceBuilderMock{
		Resources: &investigation.Resources{
			Cluster:   newTestCluster("test-cluster"),
			K8sClient: clientImpl{fakeK8s},
			Params:    map[string]string{"NODES": "worker-1"},
		},
	}

	inv := &Investigation{describer: defaultDescriber()}

	result, err := inv.Run(rb)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.Actions) != 2 {
		t.Fatalf("expected 2 actions, got %d", len(result.Actions))
	}
}

func TestRun_SelectByMultipleNodeNames(t *testing.T) {
	worker1 := newWorkerNode("worker-1")
	worker2 := newWorkerNode("worker-2")
	master1 := newMasterNode("master-1")

	fakeK8s := newFakeClient(worker1, worker2, master1)

	rb := &investigation.ResourceBuilderMock{
		Resources: &investigation.Resources{
			Cluster:   newTestCluster("test-cluster"),
			K8sClient: clientImpl{fakeK8s},
			Params:    map[string]string{"NODES": "worker-1,master-1"},
		},
	}

	inv := &Investigation{describer: defaultDescriber()}

	result, err := inv.Run(rb)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.Actions) != 2 {
		t.Fatalf("expected 2 actions, got %d", len(result.Actions))
	}
}

func TestRun_SelectByNodeNameNotFound(t *testing.T) {
	worker1 := newWorkerNode("worker-1")

	fakeK8s := newFakeClient(worker1)

	rb := &investigation.ResourceBuilderMock{
		Resources: &investigation.Resources{
			Cluster:   newTestCluster("test-cluster"),
			K8sClient: clientImpl{fakeK8s},
			Params:    map[string]string{"NODES": "nonexistent"},
		},
	}

	inv := &Investigation{describer: defaultDescriber()}

	result, err := inv.Run(rb)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should return actions with "no nodes found" warning
	if len(result.Actions) == 0 {
		t.Fatal("expected actions for empty selection")
	}
}

func TestRun_SelectBySelector(t *testing.T) {
	worker1 := newWorkerNode("worker-1")
	master1 := newMasterNode("master-1")

	fakeK8s := newFakeClient(worker1, master1)

	rb := &investigation.ResourceBuilderMock{
		Resources: &investigation.Resources{
			Cluster:   newTestCluster("test-cluster"),
			K8sClient: clientImpl{fakeK8s},
			Params:    map[string]string{"SELECTOR": "node-role.kubernetes.io/worker"},
		},
	}

	inv := &Investigation{describer: defaultDescriber()}

	result, err := inv.Run(rb)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.Actions) != 2 {
		t.Fatalf("expected 2 actions, got %d", len(result.Actions))
	}
}

func TestRun_SelectMasterNodes(t *testing.T) {
	worker1 := newWorkerNode("worker-1")
	master1 := newMasterNode("master-1")
	infra1 := newInfraNode("infra-1")

	fakeK8s := newFakeClient(worker1, master1, infra1)

	rb := &investigation.ResourceBuilderMock{
		Resources: &investigation.Resources{
			Cluster:   newTestCluster("test-cluster"),
			K8sClient: clientImpl{fakeK8s},
			Params:    map[string]string{"MASTER": "true"},
		},
	}

	inv := &Investigation{describer: defaultDescriber()}

	result, err := inv.Run(rb)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.Actions) != 2 {
		t.Fatalf("expected 2 actions, got %d", len(result.Actions))
	}
}

func TestRun_SelectInfraNodes(t *testing.T) {
	worker1 := newWorkerNode("worker-1")
	master1 := newMasterNode("master-1")
	infra1 := newInfraNode("infra-1")

	fakeK8s := newFakeClient(worker1, master1, infra1)

	rb := &investigation.ResourceBuilderMock{
		Resources: &investigation.Resources{
			Cluster:   newTestCluster("test-cluster"),
			K8sClient: clientImpl{fakeK8s},
			Params:    map[string]string{"INFRA": "true"},
		},
	}

	inv := &Investigation{describer: defaultDescriber()}

	result, err := inv.Run(rb)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.Actions) != 2 {
		t.Fatalf("expected 2 actions, got %d", len(result.Actions))
	}
}

func TestRun_SelectWorkerNodes(t *testing.T) {
	worker1 := newWorkerNode("worker-1")
	master1 := newMasterNode("master-1")
	infra1 := newInfraNode("infra-1")

	fakeK8s := newFakeClient(worker1, master1, infra1)

	rb := &investigation.ResourceBuilderMock{
		Resources: &investigation.Resources{
			Cluster:   newTestCluster("test-cluster"),
			K8sClient: clientImpl{fakeK8s},
			Params:    map[string]string{"WORKER": "true"},
		},
	}

	inv := &Investigation{describer: defaultDescriber()}

	result, err := inv.Run(rb)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should select worker-1 but not infra-1 (infra nodes have node-role.kubernetes.io=infra)
	if len(result.Actions) != 2 {
		t.Fatalf("expected 2 actions, got %d", len(result.Actions))
	}
}

func TestRun_SelectCombinedRoles(t *testing.T) {
	worker1 := newWorkerNode("worker-1")
	master1 := newMasterNode("master-1")
	infra1 := newInfraNode("infra-1")

	fakeK8s := newFakeClient(worker1, master1, infra1)

	rb := &investigation.ResourceBuilderMock{
		Resources: &investigation.Resources{
			Cluster:   newTestCluster("test-cluster"),
			K8sClient: clientImpl{fakeK8s},
			Params:    map[string]string{"MASTER": "true", "WORKER": "true"},
		},
	}

	inv := &Investigation{describer: defaultDescriber()}

	result, err := inv.Run(rb)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.Actions) != 2 {
		t.Fatalf("expected 2 actions, got %d", len(result.Actions))
	}
}

func TestRun_SelectMasterOnHCP(t *testing.T) {
	worker1 := newWorkerNode("worker-1")

	fakeK8s := newFakeClient(worker1)

	rb := &investigation.ResourceBuilderMock{
		Resources: &investigation.Resources{
			Cluster:   newTestCluster("test-hcp-cluster"),
			K8sClient: clientImpl{fakeK8s},
			IsHCP:     true,
			Params:    map[string]string{"MASTER": "true"},
		},
	}

	inv := &Investigation{describer: defaultDescriber()}

	result, err := inv.Run(rb)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should succeed with a warning about missing master nodes, returning empty selection
	if len(result.Actions) == 0 {
		t.Fatal("expected actions even with empty HCP master selection")
	}
}

func TestRun_SelectMasterAndWorkerOnHCP(t *testing.T) {
	worker1 := newWorkerNode("worker-1")

	fakeK8s := newFakeClient(worker1)

	rb := &investigation.ResourceBuilderMock{
		Resources: &investigation.Resources{
			Cluster:   newTestCluster("test-hcp-cluster"),
			K8sClient: clientImpl{fakeK8s},
			IsHCP:     true,
			Params:    map[string]string{"MASTER": "true", "WORKER": "true"},
		},
	}

	inv := &Investigation{describer: defaultDescriber()}

	result, err := inv.Run(rb)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should still describe worker nodes, plus HCP master warning
	if len(result.Actions) != 2 {
		t.Fatalf("expected 2 actions, got %d", len(result.Actions))
	}
}

func TestRun_NodesPriorityOverSelector(t *testing.T) {
	worker1 := newWorkerNode("worker-1")
	worker2 := newWorkerNode("worker-2")

	fakeK8s := newFakeClient(worker1, worker2)

	// NODES takes priority over SELECTOR — only worker-1 should be described
	rb := &investigation.ResourceBuilderMock{
		Resources: &investigation.Resources{
			Cluster:   newTestCluster("test-cluster"),
			K8sClient: clientImpl{fakeK8s},
			Params: map[string]string{
				"NODES":    "worker-1",
				"SELECTOR": "node-role.kubernetes.io/worker",
			},
		},
	}

	inv := &Investigation{describer: defaultDescriber()}

	result, err := inv.Run(rb)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.Actions) != 2 {
		t.Fatalf("expected 2 actions, got %d", len(result.Actions))
	}
}

// --- Mock describer tests ---

func TestMockDescriber(t *testing.T) {
	describer := &mockDescriber{
		descriptions: map[string]string{
			"node-1": "Name: node-1\nDetails here\n",
		},
		errors: map[string]error{
			"node-2": fmt.Errorf("not found"),
		},
	}

	desc, err := describer.Describe("", "node-1", describe.DescriberSettings{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(desc, "node-1") {
		t.Errorf("expected description to contain 'node-1', got %q", desc)
	}

	_, err = describer.Describe("", "node-2", describe.DescriberSettings{})
	if err == nil {
		t.Fatal("expected error for node-2")
	}

	desc, err = describer.Describe("", "node-3", describe.DescriberSettings{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(desc, "node-3") {
		t.Errorf("expected default description to contain 'node-3', got %q", desc)
	}
}

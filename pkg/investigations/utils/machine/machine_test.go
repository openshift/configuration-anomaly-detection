package machine

import (
	"context"
	"testing"

	machinev1beta1 "github.com/openshift/api/machine/v1beta1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func Test_HealthcheckRemediationAllowed(t *testing.T) {
	// Test objects
	failingMhc := newFailingMachineHealthCheck()

	// modify the status conditions on this mhc to indicate it's actually working
	workingMhc := newFailingMachineHealthCheck()
	workingMhc.Status.Conditions = []machinev1beta1.Condition{
		{
			Type:   machinev1beta1.RemediationAllowedCondition,
			Status: corev1.ConditionTrue,
		},
	}

	missingConditionMhc := newFailingMachineHealthCheck()
	missingConditionMhc.Status.Conditions = []machinev1beta1.Condition{}

	// Test cases
	tests := []struct {
		name string
		mhc  machinev1beta1.MachineHealthCheck
		want bool
	}{
		{
			name: "failing condition present",
			mhc:  *failingMhc,
			want: false,
		},
		{
			name: "no condition present",
			mhc:  *missingConditionMhc,
			want: false,
		},
		{
			name: "working condition present",
			mhc:  *workingMhc,
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := HealthcheckRemediationAllowed(tt.mhc); got != tt.want {
				t.Errorf("Investigation.healthcheckRemediationAllowed() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_GetMachineRole(t *testing.T) {
	type result struct {
		err  bool
		role string
	}

	tests := []struct {
		name    string
		machine func() *machinev1beta1.Machine
		want    result
	}{
		{
			name: "error when no role label",
			machine: func() *machinev1beta1.Machine {
				machine := newWorkerMachine("role-less")
				machine.Labels = map[string]string{}
				return machine
			},
			want: result{
				err: true,
			},
		},
		{
			name: "role returned when present",
			machine: func() *machinev1beta1.Machine {
				machine := newWorkerMachine("worker")
				machine.Labels = map[string]string{RoleLabelKey: WorkerRoleLabelValue}
				return machine
			},
			want: result{
				err:  false,
				role: WorkerRoleLabelValue,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			machine := tt.machine()
			got, err := GetRole(*machine)

			if (err != nil) != tt.want.err {
				t.Errorf("unexpected test result: wanted err = %t, returned err = %v", tt.want.err, err)
			}
			if got != tt.want.role {
				t.Errorf("unexpected test result: wanted role = %q, got role = %q", tt.want.role, got)
			}
		})
	}
}

func Test_findMatchingNode(t *testing.T) {
	type result struct {
		name  string
		found bool
	}

	tests := []struct {
		name    string
		objects func() (*machinev1beta1.Machine, []corev1.Node)
		want    result
	}{
		{
			name: "false when machine missing noderef",
			objects: func() (*machinev1beta1.Machine, []corev1.Node) {
				machine := newWorkerMachine("no-node")
				machine.Status = machinev1beta1.MachineStatus{}
				return machine, []corev1.Node{}
			},
			want: result{
				found: false,
			},
		},
		{
			name: "false when machine nodeRef has no name",
			objects: func() (*machinev1beta1.Machine, []corev1.Node) {
				machine := newWorkerMachine("no-node")
				machine.Status.NodeRef = &corev1.ObjectReference{
					Name: "",
				}
				return machine, []corev1.Node{}
			},
			want: result{
				found: false,
			},
		},
		{
			name: "false when no matching node exists",
			objects: func() (*machinev1beta1.Machine, []corev1.Node) {
				machine := newWorkerMachine("lonely")
				machine.Status.NodeRef = &corev1.ObjectReference{
					Name: "imaginary",
				}

				nodes := []corev1.Node{*newWorkerNode("node1"), *newWorkerNode("node2")}
				return machine, nodes
			},
			want: result{
				found: false,
			},
		},
		{
			name: "found when node exists",
			objects: func() (*machinev1beta1.Machine, []corev1.Node) {
				machine := newWorkerMachine("machine1")
				machine.Status.NodeRef = &corev1.ObjectReference{
					Name: "node1",
				}

				nodes := []corev1.Node{*newWorkerNode("node1"), *newWorkerNode("node2")}
				return machine, nodes
			},
			want: result{
				found: true,
				name:  "node1",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup
			machine, nodes := tt.objects()
			objects := []client.Object{machine}
			for _, node := range nodes {
				objects = append(objects, &node)
			}

			// Execute test
			got, found := findMatchingNode(*machine, nodes)

			// Validate results
			if found != tt.want.found {
				t.Errorf("unexpected test result: expected found = %t, got = %t", tt.want.found, found)
			}
			if got.Name != tt.want.name {
				t.Errorf("unexpected test result: expected node named = %#v, got = %#v", tt.want.name, got)
			}
		})
	}
}

func Test_GetNodeForMachine(t *testing.T) {
	type result struct {
		err  bool
		name string
	}
	tests := []struct {
		name    string
		objects func() (*machinev1beta1.Machine, []*corev1.Node)
		want    result
	}{
		{
			name: "error when machine missing nodeRef",
			objects: func() (*machinev1beta1.Machine, []*corev1.Node) {
				machine := newWorkerMachine("missing-noderef")
				machine.Status = machinev1beta1.MachineStatus{}
				return machine, []*corev1.Node{}
			},
			want: result{
				err: true,
			},
		},
		{
			name: "error when node does not exist",
			objects: func() (*machinev1beta1.Machine, []*corev1.Node) {
				machine := newWorkerMachine("invalid-noderef")
				machine.Status.NodeRef = &corev1.ObjectReference{
					Name: "missing-node",
				}

				node1 := newWorkerNode("node1")
				node2 := newWorkerNode("node2")
				return machine, []*corev1.Node{node1, node2}
			},
			want: result{
				err: true,
			},
		},
		{
			name: "return node when exists",
			objects: func() (*machinev1beta1.Machine, []*corev1.Node) {
				machine := newWorkerMachine("valid")
				node1 := newWorkerNode("node1")
				node2 := newWorkerNode("node2")
				machine.Status.NodeRef = &corev1.ObjectReference{
					Name: node1.Name,
				}
				return machine, []*corev1.Node{node1, node2}
			},
			want: result{
				err:  false,
				name: "node1",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup test
			machine, nodes := tt.objects()
			objs := []client.Object{machine}
			for _, node := range nodes {
				objs = append(objs, node)
			}

			k8scli, err := newFakeClient(objs...)
			if err != nil {
				t.Errorf("failed to create fake client for testing: %v", err)
			}

			// Execute
			got, err := GetNodeForMachine(context.TODO(), k8scli, *machine)

			// Validate results
			if (err != nil) != tt.want.err {
				t.Errorf("unexpected result in Investigation.getNodeForMachine(): wanted error = %t, returned err = %v", tt.want.err, err)
			}
			if got.Name != tt.want.name {
				t.Errorf("incorrect node returned: expected %q, got %q", tt.want.name, got.Name)
			}
		})
	}
}

func newFailingMachineHealthCheck() *machinev1beta1.MachineHealthCheck {
	mhc := &machinev1beta1.MachineHealthCheck{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-mhc",
			Namespace: MachineNamespace,
		},
		Spec: machinev1beta1.MachineHealthCheckSpec{
			Selector: metav1.LabelSelector{
				MatchLabels: map[string]string{"mhc-name": "test-mhc"},
			},
		},
		Status: machinev1beta1.MachineHealthCheckStatus{
			Conditions: []machinev1beta1.Condition{
				{
					Type:   machinev1beta1.RemediationAllowedCondition,
					Status: corev1.ConditionFalse,
				},
			},
		},
	}
	return mhc
}

func newWorkerMachine(name string) *machinev1beta1.Machine {
	m := &machinev1beta1.Machine{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: MachineNamespace,
			Labels:    map[string]string{"mhc-name": "test-mhc", RoleLabelKey: WorkerRoleLabelValue},
		},
	}
	return m
}

func newWorkerNode(name string) *corev1.Node {
	n := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name:   name,
			Labels: map[string]string{"node-role/kubernetes.io/worker": ""},
		},
	}
	return n
}

func newFakeClient(objs ...client.Object) (client.Client, error) {
	s := scheme.Scheme
	err := machinev1beta1.AddToScheme(s)
	if err != nil {
		return nil, err
	}

	client := fake.NewClientBuilder().WithScheme(s).WithObjects(objs...).Build()
	return client, nil
}

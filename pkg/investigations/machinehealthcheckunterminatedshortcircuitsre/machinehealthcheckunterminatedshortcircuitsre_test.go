package machinehealthcheckunterminatedshortcircuitsre

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	machineutil "github.com/openshift/configuration-anomaly-detection/pkg/investigations/utils/machine"
	nodeutil "github.com/openshift/configuration-anomaly-detection/pkg/investigations/utils/node"
	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
	"github.com/openshift/configuration-anomaly-detection/pkg/notewriter"

	machinev1beta1 "github.com/openshift/api/machine/v1beta1"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestInvestigation_getMachinesFromFailingMHC(t *testing.T) {
	// Test objects
	mhc := newFailingMachineHealthCheck()

	mhcOwnedMachine1 := newWorkerMachine("mhc-owned-1")
	mhcOwnedMachine2 := newWorkerMachine("mhc-owned-2")
	irrelevantMachine := newWorkerMachine("irrelevant")
	// clear the labels from this machine so that it's no longer owned by the mhc
	irrelevantMachine.Labels = map[string]string{}

	tests := []struct {
		name    string
		objects []client.Object
		want    []string
	}{
		// test cases
		{
			name: "one valid machine",
			objects: []client.Object{
				mhc,
				mhcOwnedMachine1,
			},
			want: []string{
				mhcOwnedMachine1.Name,
			},
		},
		{
			name: "no valid machines",
			objects: []client.Object{
				mhc,
			},
			want: []string{},
		},
		{
			name: "two valid machines",
			objects: []client.Object{
				mhc,
				mhcOwnedMachine1,
				mhcOwnedMachine2,
			},
			want: []string{
				mhcOwnedMachine1.Name,
				mhcOwnedMachine2.Name,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup test
			i, err := newTestInvestigation(tt.objects...)
			if err != nil {
				t.Errorf("failed to create test investigation: %v", err)
				return
			}

			// Execute test
			got, err := i.getMachinesFromFailingMHC(context.TODO())
			if err != nil {
				// Never expect error on this test
				t.Errorf("Investigation.getTargetMachines() error = %v, expected no error", err)
				return
			}

			// Check results
			for _, wantedMachineName := range tt.want {
				found := slices.ContainsFunc(got, func(gotMachine machinev1beta1.Machine) bool {
					return gotMachine.Name == wantedMachineName
				})
				if !found {
					t.Errorf("expected machine %q in returned list. Got the following instead: %#v", wantedMachineName, got)
				}
			}
		})
	}
}

func TestInvestigation_investigateFailingMachine(t *testing.T) {
	// Test cases
	type result struct {
		err    bool
		action recommendedAction
		notes  string
	}

	tests := []struct {
		name    string
		machine func() *machinev1beta1.Machine
		want    result
	}{
		{
			name: "investigate when no role",
			machine: func() *machinev1beta1.Machine {
				machine := newWorkerMachine("role-less")
				// clear the machine's labels to unassign it from the worker role
				machine.Labels = map[string]string{}
				return machine
			},
			want: result{
				err:    true,
				action: recommendationInvestigateMachine,
				notes:  "unable to determine machine role",
			},
		},
		{
			name: "investigate when infra failing",
			machine: func() *machinev1beta1.Machine {
				machine := newWorkerMachine("infra")
				machine.Labels[machineutil.RoleLabelKey] = "infra"
				return machine
			},
			want: result{
				err:    false,
				action: recommendationInvestigateMachine,
				notes:  "Red Hat-owned machine in state",
			},
		},
		{
			name: "delete when invalid IP",
			machine: func() *machinev1beta1.Machine {
				machine := newWorkerMachine("bad-ip")
				reason := machinev1beta1.IPAddressInvalidReason
				machine.Status.ErrorReason = &reason
				return machine
			},
			want: result{
				err:    false,
				action: recommendationDeleteMachine,
				notes:  "invalid IP address",
			},
		},
		{
			name: "delete when create failed",
			machine: func() *machinev1beta1.Machine {
				machine := newWorkerMachine("create-failed")
				reason := machinev1beta1.CreateMachineError
				machine.Status.ErrorReason = &reason
				return machine
			},
			want: result{
				err:    false,
				action: recommendationDeleteMachine,
				notes:  "machine failed to create",
			},
		},
		{
			name: "investigate when invalid configuration",
			machine: func() *machinev1beta1.Machine {
				machine := newWorkerMachine("invalid-config")
				reason := machinev1beta1.InvalidConfigurationMachineError
				machine.Status.ErrorReason = &reason
				return machine
			},
			want: result{
				err:    false,
				action: recommendationInvestigateMachine,
				notes:  "machine configuration is invalid",
			},
		},
		{
			name: "investigate when delete failed",
			machine: func() *machinev1beta1.Machine {
				machine := newWorkerMachine("delete-failed")
				reason := machinev1beta1.DeleteMachineError
				machine.Status.ErrorReason = &reason
				return machine
			},
			want: result{
				err:    false,
				action: recommendationInvestigateMachine,
				notes:  "the machine's node could not be gracefully terminated",
			},
		},
		{
			name: "servicelog when insufficient resources",
			machine: func() *machinev1beta1.Machine {
				machine := newWorkerMachine("insufficient-resources")
				reason := machinev1beta1.InsufficientResourcesMachineError
				machine.Status.ErrorReason = &reason
				return machine
			},
			want: result{
				err:    false,
				action: recommendationQuotaServiceLog,
				notes:  "a servicelog should be sent",
			},
		},
		{
			name: "investigate when missing .Status.ErrorReason",
			machine: func() *machinev1beta1.Machine {
				machine := newWorkerMachine("no-status")
				machine.Status = machinev1beta1.MachineStatus{}
				return machine
			},
			want: result{
				err:    false,
				action: recommendationInvestigateMachine,
				notes:  "no .Status.ErrorReason found for machine",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup test
			machine := tt.machine()
			i, err := newTestInvestigation(machine)
			if err != nil {
				t.Errorf("failed to create test investigation: %v", err)
			}

			// Execute test
			err = i.investigateFailingMachine(*machine)

			// Verify results
			if (err != nil) != tt.want.err {
				t.Errorf("unexpected result in Investigation.investigateFailingMachine(): wanted error = %t, returned err = %v", tt.want.err, err)
			}

			recs := i.recommendations[tt.want.action]
			if len(recs) != 1 {
				t.Errorf("expected exactly one recommendation: %q, got %d", tt.want.action, len(recs))
			}
			if !strings.Contains(recs[0].notes, tt.want.notes) {
				t.Errorf("unexpected note in investigation recommendation: expected %q, got %q", tt.want.notes, recs[0].notes)
			}
		})
	}
}

func TestInvestigation_investigateDeletingMachine(t *testing.T) {
	type result struct {
		err    bool
		action recommendedAction
		notes  string
	}

	tests := []struct {
		name    string
		objects func() (*machinev1beta1.Machine, *corev1.Node)
		want    result
	}{
		{
			name: "investigate when no .Status.NodeRef",
			objects: func() (*machinev1beta1.Machine, *corev1.Node) {
				machine := newWorkerMachine("no-noderef")
				machine.Status = machinev1beta1.MachineStatus{}
				return machine, &corev1.Node{}
			},
			want: result{
				err:    false,
				action: recommendationInvestigateMachine,
				notes:  "machine stuck deleting with no node",
			},
		},
		{
			name: "investigate when no node for machine",
			objects: func() (*machinev1beta1.Machine, *corev1.Node) {
				machine := newWorkerMachine("lonely")
				machine.Status.NodeRef = &corev1.ObjectReference{
					Kind: "Node",
					Name: "missing",
				}
				return machine, &corev1.Node{}
			},
			want: result{
				err:    true,
				action: recommendationInvestigateMachine,
				notes:  "machine's node could not be determined",
			},
		},
		{
			name: "investigate when machine deletion reason unknown",
			objects: func() (*machinev1beta1.Machine, *corev1.Node) {
				machine := newWorkerMachine("stuck-deleting")
				node := newWorkerNode("stuck-deleting")
				machine.Status.NodeRef = &corev1.ObjectReference{
					Kind: node.Kind,
					Name: node.Name,
				}
				return machine, node
			},
			want: result{
				err:    false,
				action: recommendationInvestigateMachine,
				notes:  "unable to determine why machine is stuck deleting",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup test
			machine, node := tt.objects()
			i, err := newTestInvestigation(machine, node)
			if err != nil {
				t.Errorf("failed to create test investigation: %v", err)
			}

			// Execute test
			err = i.investigateDeletingMachine(context.TODO(), *machine)

			// Verify results
			if (err != nil) != tt.want.err {
				t.Errorf("unexpected result in Investigation.investigateDeletingMachine(): wanted error = %t, returned err = %v", tt.want.err, err)
			}

			recs := i.recommendations[tt.want.action]
			if len(recs) != 1 {
				t.Errorf("expected exactly one recommendation: %q, got %d", tt.want.action, len(recs))
			}
			if !strings.Contains(recs[0].notes, tt.want.notes) {
				t.Errorf("unexpected note in investigation recommendation: expected %q, got %q", tt.want.notes, recs[0].notes)
			}
		})
	}
}

func Test_checkForStuckDrain(t *testing.T) {
	tests := []struct {
		name  string
		node  func() corev1.Node
		stuck bool
	}{
		{
			name: "not stuck when no taints",
			node: func() corev1.Node {
				node := newWorkerNode("taintless")
				node.Spec.Taints = []corev1.Taint{}
				return *node
			},
			stuck: false,
		},
		{
			name: "not stuck when no NoSchedule taint",
			node: func() corev1.Node {
				node := newWorkerNode("scheduleable")
				node.Spec.Taints = []corev1.Taint{
					{
						Effect: corev1.TaintEffectNoExecute,
					},
					{
						Effect: corev1.TaintEffectPreferNoSchedule,
					},
				}
				return *node
			},
			stuck: false,
		},
		{
			name: "not stuck when short-lived NoSchedule taint",
			node: func() corev1.Node {
				node := newWorkerNode("recently-unscheduleable")
				node.Spec.Taints = []corev1.Taint{
					{
						Effect: corev1.TaintEffectNoSchedule,
						TimeAdded: &metav1.Time{
							Time: time.Now(),
						},
					},
				}
				return *node
			},
			stuck: false,
		},
		{
			name: "stuck when long-lived NoSchedule taint",
			node: func() corev1.Node {
				node := newWorkerNode("actually-stuck")
				node.Spec.Taints = []corev1.Taint{
					{
						Effect: corev1.TaintEffectNoSchedule,
						TimeAdded: &metav1.Time{
							Time: time.Now().Add(-1 * time.Hour),
						},
					},
				}
				return *node
			},
			stuck: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, duration := checkForStuckDrain(tt.node())
			if got != tt.stuck {
				t.Errorf("unexpected result: expected stuck = %t, got %t", tt.stuck, got)
			}
			if got && duration == nil {
				t.Errorf("unexpected result: got stuck = %t, but duration = %v", got, duration)
			}
		})
	}
}

func TestInvestigation_InvestigateNode(t *testing.T) {
	type result struct {
		action recommendedAction
		notes  string
	}

	tests := []struct {
		name string
		node func() *corev1.Node
		want result
	}{
		{
			name: "investigate when no role label",
			node: func() *corev1.Node {
				node := newWorkerNode("labelless")
				node.Labels = map[string]string{}
				return node
			},
			want: result{
				action: recommendationInvestigateNode,
				notes:  "no role label",
			},
		},
		{
			name: "investigate when bad role label",
			node: func() *corev1.Node {
				node := newWorkerNode("infra")
				node.Labels = map[string]string{fmt.Sprintf("%s/infra", nodeutil.RoleLabelPrefix): ""}
				return node
			},
			want: result{
				action: recommendationInvestigateNode,
				notes:  "non-worker node affected",
			},
		},
		{
			name: "investigate when no Ready condition",
			node: func() *corev1.Node {
				node := newWorkerNode("unReady")
				node.Status.Conditions = []corev1.NodeCondition{}
				return node
			},
			want: result{
				action: recommendationInvestigateNode,
				notes:  "found no 'Ready' .Status.Condition",
			},
		},
		{
			name: "investigate when not Ready",
			node: func() *corev1.Node {
				node := newWorkerNode("notReady")
				node.Status.Conditions = []corev1.NodeCondition{
					{
						Type:   corev1.NodeReady,
						Status: corev1.ConditionFalse,
					},
				}
				return node
			},
			want: result{
				action: recommendationInvestigateNode,
				notes:  "node has been",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup test
			node := tt.node()
			i, err := newTestInvestigation(node)
			if err != nil {
				t.Errorf("failed to create new test investigation: %v", err)
			}

			// Execute test
			i.InvestigateNode(*node)

			// Validate results
			recs := i.recommendations[tt.want.action]
			if len(recs) != 1 {
				t.Errorf("expected exactly one recommendation: %q, got %d", tt.want.action, len(recs))
			}
			if !strings.Contains(recs[0].notes, tt.want.notes) {
				t.Errorf("unexpected note in investigation recommendation: expected %q, got %q", tt.want.notes, recs[0].notes)
			}
		})
	}
}

func newFailingMachineHealthCheck() *machinev1beta1.MachineHealthCheck {
	mhc := &machinev1beta1.MachineHealthCheck{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-mhc",
			Namespace: machineutil.MachineNamespace,
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
			Namespace: machineutil.MachineNamespace,
			Labels:    map[string]string{"mhc-name": "test-mhc", machineutil.RoleLabelKey: machineutil.WorkerRoleLabelValue},
		},
	}
	return m
}

func newWorkerNode(name string) *corev1.Node {
	n := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name:   name,
			Labels: map[string]string{fmt.Sprintf("%s/%s", nodeutil.RoleLabelPrefix, nodeutil.WorkerRoleSuffix): ""},
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

type clientImpl struct {
	client.Client
}

func (client clientImpl) Clean() error {
	return nil
}

func newTestInvestigation(testObjects ...client.Object) (Investigation, error) {
	fakeClient, err := newFakeClient(testObjects...)
	if err != nil {
		return Investigation{}, err
	}

	i := Investigation{
		kclient:         clientImpl{fakeClient},
		notes:           notewriter.New("testing", logging.RawLogger),
		recommendations: investigationRecommendations{},
	}
	return i, nil
}

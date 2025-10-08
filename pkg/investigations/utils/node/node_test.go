package node

import (
	"fmt"
	"reflect"
	"slices"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func Test_FindNoScheduleTaint(t *testing.T) {
	type result struct {
		taints []corev1.Taint
		key    string
	}

	tests := []struct {
		name string
		node func() *corev1.Node
		want result
	}{
		{
			name: "false when taint missing",
			node: func() *corev1.Node {
				node := newWorkerNode("taintless")
				node.Spec.Taints = []corev1.Taint{}
				return node
			},
			want: result{
				taints: []corev1.Taint{},
			},
		},
		{
			name: "return taint when it exists",
			node: func() *corev1.Node {
				node := newWorkerNode("tainted")
				node.Spec.Taints = []corev1.Taint{
					{
						Key:    "tainted",
						Effect: corev1.TaintEffectNoSchedule,
					},
				}
				return node
			},
			want: result{
				key: "tainted",
				taints: []corev1.Taint{
					{
						Key:    "tainted",
						Effect: corev1.TaintEffectNoSchedule,
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			node := tt.node()

			got := FindNoScheduleTaints(*node)
			for _, g := range got {
				if !slices.Contains(tt.want.taints, g) {
					t.Errorf("unexpected test result: expected result to contain = %v, got = %v", g, tt.want.taints)
				}
			}
		})
	}
}

func Test_FindNodeReadyCondition(t *testing.T) {
	readyCondition := corev1.NodeCondition{
		Type: corev1.NodeReady,
		LastTransitionTime: metav1.Time{
			Time: time.Now(),
		},
	}

	type result struct {
		found     bool
		condition corev1.NodeCondition
	}

	tests := []struct {
		name string
		node func() *corev1.Node
		want result
	}{
		{
			name: "return false when missing condition",
			node: func() *corev1.Node {
				node := newWorkerNode("not-ready")
				node.Status.Conditions = []corev1.NodeCondition{}
				return node
			},
			want: result{
				found: false,
			},
		},
		{
			name: "return true when Ready",
			node: func() *corev1.Node {
				node := newWorkerNode("ready")
				node.Status.Conditions = []corev1.NodeCondition{readyCondition}
				return node
			},
			want: result{
				found:     true,
				condition: readyCondition,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			node := tt.node()
			got, found := FindReadyCondition(*node)

			if found != tt.want.found {
				t.Errorf("unexpected test result: expected found = %t, got = %t", tt.want.found, found)
			}
			if !reflect.DeepEqual(got, tt.want.condition) {
				t.Errorf("unexpected test result: expected condition = %#v, got = %#v", tt.want.condition, got)
			}
		})
	}
}

func Test_GetNodeRole(t *testing.T) {
	var (
		workerLabel = fmt.Sprintf("%s/%s", RoleLabelPrefix, WorkerRoleSuffix)
		infraLabel  = fmt.Sprintf("%s/infra", RoleLabelPrefix)
	)

	type result struct {
		label string
		found bool
	}
	tests := []struct {
		name string
		node func() *corev1.Node
		want result
	}{
		{
			name: "not found when no role label",
			node: func() *corev1.Node {
				node := newWorkerNode("labelless")
				node.Labels = map[string]string{}
				return node
			},
			want: result{
				found: false,
			},
		},
		{
			name: "label returned when found on worker",
			node: func() *corev1.Node {
				node := newWorkerNode("labelled")
				node.Labels = map[string]string{workerLabel: ""}
				return node
			},
			want: result{
				found: true,
				label: workerLabel,
			},
		},
		{
			name: "label returned when found on non-worker",
			node: func() *corev1.Node {
				node := newWorkerNode("labelled")
				node.Labels = map[string]string{infraLabel: ""}
				return node
			},
			want: result{
				found: true,
				label: infraLabel,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			node := tt.node()
			got, found := GetRole(*node)
			if found != tt.want.found {
				t.Errorf("unexpected test result: expected found = %t, got = %t", tt.want.found, found)
			}
			if got != tt.want.label {
				t.Errorf("unexpected test result: expected label = %q, got = %q", tt.want.label, got)
			}
		})
	}
}

func newWorkerNode(name string) *corev1.Node {
	n := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name:   name,
			Labels: map[string]string{fmt.Sprintf("%s/%s", RoleLabelPrefix, WorkerRoleSuffix): ""},
		},
	}
	return n
}

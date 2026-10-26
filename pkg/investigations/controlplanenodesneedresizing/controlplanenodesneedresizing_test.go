package controlplanenodesneedresizing

import (
	"context"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

type wrap struct{ client.Client }

func TestSummarizeMasterPods(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	master := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "master-0", Labels: map[string]string{masterRoleLabel: ""}}}
	worker := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "worker-0", Labels: map[string]string{"node-role.kubernetes.io/worker": ""}}}
	pods := []*corev1.Pod{
		pod("openshift-kube-apiserver", "kube-apiserver-master-0", "master-0"),
		pod("my-app", "web-0", "master-0"),
		pod("my-app", "web-1", "worker-0"),
	}
	objs := []client.Object{master, worker}
	for _, p := range pods {
		objs = append(objs, p)
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).WithIndex(&corev1.Pod{}, "spec.nodeName", func(obj client.Object) []string {
		return []string{obj.(*corev1.Pod).Spec.NodeName}
	}).Build()

	got, err := summarizeMasterPods(context.Background(), wrap{c})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Control plane nodes: 1", "my-app: 1 pods (customer)", "openshift-kube-apiserver: 1 pods (platform)"} {
		if !strings.Contains(got, want) {
			t.Fatalf("summary missing %q:\n%s", want, got)
		}
	}
}

func pod(ns, name, node string) *corev1.Pod {
	return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns}, Spec: corev1.PodSpec{NodeName: node}}
}

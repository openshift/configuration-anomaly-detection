package machinehealthcheckunterminatedshortcircuitsre

import (
	"context"
	"strings"
	"testing"
	"time"

	servicelogsv1 "github.com/openshift-online/ocm-sdk-go/servicelogs/v1"
	"github.com/openshift/configuration-anomaly-detection/pkg/executor"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/investigation"
	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
	"github.com/openshift/configuration-anomaly-detection/pkg/notewriter"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func Test_findDrainBlockingPDBs(t *testing.T) {
	tests := []struct {
		name         string
		objects      []client.Object
		stalledNodes []corev1.Node
		wantBlockers int
		// wantFields is checked against the first returned blocker, when one is expected
		wantNamespace  string
		wantName       string
		wantConstraint string
		wantPods       []string
		wantOwners     []string
		wantPlatform   bool
	}{
		{
			name:         "no stalled nodes short-circuits",
			objects:      []client.Object{newBlockingPDB("customer", "web-pdb", minAvailable(2))},
			stalledNodes: nil,
			wantBlockers: 0,
		},
		{
			name: "pdb allowing disruptions is not a blocker",
			objects: []client.Object{
				func() client.Object {
					pdb := newBlockingPDB("customer", "web-pdb", minAvailable(2))
					pdb.Status.DisruptionsAllowed = 1
					return pdb
				}(),
				newPod("customer", "web-0", "stalled", map[string]string{"app": "web"}, nil),
			},
			stalledNodes: []corev1.Node{*newDrainingNode("stalled", time.Hour)},
			wantBlockers: 0,
		},
		{
			name: "pdb whose pods are elsewhere is not a blocker",
			objects: []client.Object{
				newBlockingPDB("customer", "web-pdb", minAvailable(2)),
				newPod("customer", "web-0", "some-other-node", map[string]string{"app": "web"}, nil),
			},
			stalledNodes: []corev1.Node{*newDrainingNode("stalled", time.Hour)},
			wantBlockers: 0,
		},
		{
			name: "pdb whose selector does not match the pod is not a blocker",
			objects: []client.Object{
				newBlockingPDB("customer", "web-pdb", minAvailable(2)),
				newPod("customer", "db-0", "stalled", map[string]string{"app": "db"}, nil),
			},
			stalledNodes: []corev1.Node{*newDrainingNode("stalled", time.Hour)},
			wantBlockers: 0,
		},
		{
			name: "customer pdb blocking a stalled node",
			objects: []client.Object{
				newBlockingPDB("customer", "web-pdb", minAvailable(2)),
				newPod("customer", "web-0", "stalled", map[string]string{"app": "web"}, &metav1.OwnerReference{
					Kind: "StatefulSet",
					Name: "web",
				}),
			},
			stalledNodes:   []corev1.Node{*newDrainingNode("stalled", time.Hour)},
			wantBlockers:   1,
			wantNamespace:  "customer",
			wantName:       "web-pdb",
			wantConstraint: "minAvailable: 2",
			wantPods:       []string{"web-0"},
			wantOwners:     []string{"StatefulSet/web"},
			wantPlatform:   false,
		},
		{
			name: "platform pdb is classified as platform-managed",
			objects: []client.Object{
				newBlockingPDB("openshift-monitoring", "prom-pdb", maxUnavailable(0)),
				newPod("openshift-monitoring", "prometheus-k8s-0", "stalled", map[string]string{"app": "web"}, nil),
			},
			stalledNodes:   []corev1.Node{*newDrainingNode("stalled", time.Hour)},
			wantBlockers:   1,
			wantNamespace:  "openshift-monitoring",
			wantName:       "prom-pdb",
			wantConstraint: "maxUnavailable: 0",
			wantPods:       []string{"prometheus-k8s-0"},
			wantOwners:     []string{ownerNone},
			wantPlatform:   true,
		},
		{
			name: "pod owner is resolved through the replicaset to the deployment",
			objects: []client.Object{
				newBlockingPDB("customer", "web-pdb", minAvailable(1)),
				newPod("customer", "web-abc-1", "stalled", map[string]string{"app": "web"}, &metav1.OwnerReference{
					Kind: "ReplicaSet",
					Name: "web-abc",
				}),
				&appsv1.ReplicaSet{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "web-abc",
						Namespace:       "customer",
						OwnerReferences: []metav1.OwnerReference{{Kind: "Deployment", Name: "web"}},
					},
				},
			},
			stalledNodes: []corev1.Node{*newDrainingNode("stalled", time.Hour)},
			wantBlockers: 1,
			wantOwners:   []string{"Deployment/web"},
		},
		{
			name: "one pdb holding two nodes open yields one blocker per node",
			objects: []client.Object{
				newBlockingPDB("customer", "web-pdb", minAvailable(3)),
				newPod("customer", "web-0", "stalled-a", map[string]string{"app": "web"}, nil),
				newPod("customer", "web-1", "stalled-b", map[string]string{"app": "web"}, nil),
			},
			stalledNodes: []corev1.Node{
				*newDrainingNode("stalled-a", time.Hour),
				*newDrainingNode("stalled-b", time.Hour),
			},
			wantBlockers: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fakeClient, err := newFakeClient(tt.objects...)
			if err != nil {
				t.Fatalf("failed to create fake client: %v", err)
			}

			got, err := findDrainBlockingPDBs(context.TODO(), fakeClient, tt.stalledNodes)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if len(got) != tt.wantBlockers {
				t.Fatalf("expected %d blocker(s), got %d: %#v", tt.wantBlockers, len(got), got)
			}
			if tt.wantBlockers == 0 {
				return
			}

			blocker := got[0]
			if tt.wantNamespace != "" && blocker.Namespace != tt.wantNamespace {
				t.Errorf("expected namespace %q, got %q", tt.wantNamespace, blocker.Namespace)
			}
			if tt.wantName != "" && blocker.Name != tt.wantName {
				t.Errorf("expected name %q, got %q", tt.wantName, blocker.Name)
			}
			if tt.wantConstraint != "" && blocker.Constraint != tt.wantConstraint {
				t.Errorf("expected constraint %q, got %q", tt.wantConstraint, blocker.Constraint)
			}
			if tt.wantPods != nil && strings.Join(blocker.Pods, ",") != strings.Join(tt.wantPods, ",") {
				t.Errorf("expected pods %v, got %v", tt.wantPods, blocker.Pods)
			}
			if tt.wantOwners != nil && strings.Join(blocker.OwnerWorkloads, ",") != strings.Join(tt.wantOwners, ",") {
				t.Errorf("expected owners %v, got %v", tt.wantOwners, blocker.OwnerWorkloads)
			}
			if blocker.IsPlatformManaged != tt.wantPlatform {
				t.Errorf("expected IsPlatformManaged = %t, got %t", tt.wantPlatform, blocker.IsPlatformManaged)
			}
		})
	}
}

func TestInvestigation_recommendStuckDrain(t *testing.T) {
	tests := []struct {
		name string
		// setup populates the investigation's cached drain state
		setup          func(i *Investigation)
		node           string
		wantStalled    bool
		wantAction     recommendedAction
		wantNotes      string
		wantServiceLog bool
	}{
		{
			name:        "node that is not draining is left to the caller",
			setup:       func(_ *Investigation) {},
			node:        "healthy",
			wantStalled: false,
		},
		{
			name: "stalled drain with no pdb blames something else",
			setup: func(i *Investigation) {
				i.stalledDrains["stalled"] = time.Hour
			},
			node:        "stalled",
			wantStalled: true,
			wantAction:  recommendationInvestigateNode,
			wantNotes:   "no PodDisruptionBudget with disruptionsAllowed=0 selects a pod on this node",
		},
		{
			name: "customer pdb queues a service log",
			setup: func(i *Investigation) {
				i.stalledDrains["stalled"] = time.Hour
				i.drainBlockers["stalled"] = []drainBlocker{{
					Node:              "stalled",
					Namespace:         "customer",
					Name:              "web-pdb",
					Constraint:        "minAvailable: 2",
					CurrentHealthy:    2,
					ExpectedPods:      2,
					Pods:              []string{"web-0"},
					OwnerWorkloads:    []string{"StatefulSet/web"},
					IsPlatformManaged: false,
				}}
			},
			node:           "stalled",
			wantStalled:    true,
			wantAction:     recommendationCustomerPDBBlockingDrain,
			wantNotes:      "blocked by PodDisruptionBudget customer/web-pdb",
			wantServiceLog: true,
		},
		{
			name: "platform pdb does not queue a service log",
			setup: func(i *Investigation) {
				i.stalledDrains["stalled"] = time.Hour
				i.drainBlockers["stalled"] = []drainBlocker{{
					Node:              "stalled",
					Namespace:         "openshift-monitoring",
					Name:              "prom-pdb",
					Constraint:        "maxUnavailable: 0",
					Pods:              []string{"prometheus-k8s-0"},
					IsPlatformManaged: true,
				}}
			},
			node:           "stalled",
			wantStalled:    true,
			wantAction:     recommendationPlatformPDBBlockingDrain,
			wantNotes:      "blocked by PodDisruptionBudget openshift-monitoring/prom-pdb",
			wantServiceLog: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			i, err := newTestInvestigation()
			if err != nil {
				t.Fatalf("failed to create test investigation: %v", err)
			}
			tt.setup(&i)

			got := i.recommendStuckDrain(tt.node)
			if got != tt.wantStalled {
				t.Fatalf("expected stalled = %t, got %t", tt.wantStalled, got)
			}
			if !tt.wantStalled {
				if len(i.recommendations) != 0 {
					t.Errorf("expected no recommendations for a non-draining node, got %#v", i.recommendations)
				}
				return
			}

			recs := i.recommendations[tt.wantAction]
			if len(recs) != 1 {
				t.Fatalf("expected exactly one %q recommendation, got %d", tt.wantAction, len(recs))
			}
			if !strings.Contains(recs[0].notes, tt.wantNotes) {
				t.Errorf("expected note containing %q, got %q", tt.wantNotes, recs[0].notes)
			}

			if tt.wantServiceLog && len(i.pdbServiceLogs) != 1 {
				t.Errorf("expected one queued service log, got %d", len(i.pdbServiceLogs))
			}
			if !tt.wantServiceLog && len(i.pdbServiceLogs) != 0 {
				t.Errorf("expected no queued service log, got %d", len(i.pdbServiceLogs))
			}
		})
	}
}

// TestInvestigation_Run_PDBInformingPhase verifies the informing-phase contract end to end: a
// customer PDB blocking the drain of a healthcheck-managed node is always described in the
// PagerDuty note, but the corresponding service log is only dispatched once
// CAD_EXPERIMENTAL_ENABLED is set.
func TestInvestigation_Run_PDBInformingPhase(t *testing.T) {
	// A machine that is NOT deleting, to prove the drain check no longer depends on
	// machine.DeletionTimestamp (the `oc scale machineset --replicas=0` scenario).
	machine := newWorkerMachine("scaling-down")
	machine.Status.NodeRef = &corev1.ObjectReference{Kind: "Node", Name: "stalled"}

	objects := []client.Object{
		newFailingMachineHealthCheck(),
		machine,
		newDrainingNode("stalled", time.Hour),
		newBlockingPDB("customer", "web-pdb", minAvailable(2)),
		newPod("customer", "web-0", "stalled", map[string]string{"app": "web"}, &metav1.OwnerReference{
			Kind: "StatefulSet",
			Name: "web",
		}),
	}

	for _, experimental := range []bool{false, true} {
		name := "informing phase sends no service log"
		if experimental {
			name = "actioning phase sends the service log"
		}
		t.Run(name, func(t *testing.T) {
			if experimental {
				t.Setenv("CAD_EXPERIMENTAL_ENABLED", "true")
			} else {
				t.Setenv("CAD_EXPERIMENTAL_ENABLED", "")
			}

			fakeClient, err := newFakeClient(objects...)
			if err != nil {
				t.Fatalf("failed to create fake client: %v", err)
			}

			notes := notewriter.New("testing", logging.RawLogger)
			rb := &investigation.ResourceBuilderMock{
				Resources: &investigation.Resources{
					Cluster:   newTestCluster("test-cluster"),
					K8sClient: clientImpl{fakeClient},
					Notes:     notes,
				},
			}

			i := &Investigation{}
			result, err := i.Run(rb)
			if err != nil {
				t.Fatalf("unexpected error from Run(): %v", err)
			}

			// The blocker itself must always be reported, regardless of phase.
			recs := i.recommendations[recommendationCustomerPDBBlockingDrain]
			if len(recs) != 1 {
				t.Fatalf("expected one customer-PDB recommendation, got %d", len(recs))
			}
			if !strings.Contains(recs[0].notes, "customer/web-pdb") {
				t.Errorf("expected the blocking PDB to be named, got %q", recs[0].notes)
			}
			if !strings.Contains(recs[0].notes, "StatefulSet/web") {
				t.Errorf("expected the owning workload to be named, got %q", recs[0].notes)
			}

			gotServiceLog := hasActionType(result.Actions, executor.ActionTypeServiceLog)
			if gotServiceLog != experimental {
				t.Errorf("expected service log action = %t, got %t", experimental, gotServiceLog)
			}

			noteText := notes.String()
			if !experimental && !strings.Contains(noteText, "INFORMING PHASE") {
				t.Errorf("expected the informing-phase note to state the unsent service log, got:\n%s", noteText)
			}

			// The investigation stays escalate-only either way: no silencing on a PDB finding.
			if !hasActionType(result.Actions, executor.ActionTypeEscalateIncident) {
				t.Errorf("expected the incident to be escalated")
			}
			if hasActionType(result.Actions, executor.ActionTypeSilenceIncident) {
				t.Errorf("did not expect the incident to be silenced")
			}
		})
	}
}

func Test_describeConstraint(t *testing.T) {
	tests := []struct {
		name string
		pdb  policyv1.PodDisruptionBudget
		want string
	}{
		{
			name: "minAvailable int",
			pdb:  *newBlockingPDB("ns", "p", minAvailable(3)),
			want: "minAvailable: 3",
		},
		{
			name: "maxUnavailable int",
			pdb:  *newBlockingPDB("ns", "p", maxUnavailable(0)),
			want: "maxUnavailable: 0",
		},
		{
			name: "minAvailable percentage",
			pdb: *newBlockingPDB("ns", "p", func(pdb *policyv1.PodDisruptionBudget) {
				v := intstr.FromString("100%")
				pdb.Spec.MinAvailable = &v
			}),
			want: "minAvailable: 100%",
		},
		{
			name: "neither field set",
			pdb:  *newBlockingPDB("ns", "p"),
			want: "no minAvailable or maxUnavailable set",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := describeConstraint(tt.pdb); got != tt.want {
				t.Errorf("expected %q, got %q", tt.want, got)
			}
		})
	}
}

func Test_isPlatformNamespace(t *testing.T) {
	tests := map[string]bool{
		"openshift-monitoring":  true,
		"openshift-machine-api": true,
		"kube-system":           true,
		"openshift":             true,
		"default":               false,
		"customer-app":          false,
		"openshiftish":          false,
	}
	for namespace, want := range tests {
		t.Run(namespace, func(t *testing.T) {
			if got := isPlatformNamespace(namespace); got != want {
				t.Errorf("isPlatformNamespace(%q) = %t, want %t", namespace, got, want)
			}
		})
	}
}

func Test_customerPDBServiceLog(t *testing.T) {
	sl := customerPDBServiceLog(drainBlocker{
		Node:      "ip-10-0-1-1.ec2.internal",
		Namespace: "customer",
		Name:      "web-pdb",
		Pods:      []string{"web-0", "web-1"},
	})

	if sl.Severity != servicelogsv1.SeverityImportant {
		t.Errorf("expected severity %q, got %q", servicelogsv1.SeverityImportant, sl.Severity)
	}
	if sl.ServiceName != "SREManualAction" {
		t.Errorf("expected service name SREManualAction, got %q", sl.ServiceName)
	}
	if sl.InternalOnly {
		t.Error("expected a customer-visible service log")
	}
	// The template's NODE, POD and NAMESPACE parameters must all be substituted.
	for _, want := range []string{"ip-10-0-1-1.ec2.internal", "web-0, web-1", "customer"} {
		if !strings.Contains(sl.Description, want) {
			t.Errorf("expected description to contain %q, got %q", want, sl.Description)
		}
	}
}

// newBlockingPDB returns a PDB that allows no disruptions and selects pods labelled app=web
func newBlockingPDB(namespace, name string, opts ...func(*policyv1.PodDisruptionBudget)) *policyv1.PodDisruptionBudget {
	pdb := &policyv1.PodDisruptionBudget{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: policyv1.PodDisruptionBudgetSpec{
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}},
		},
		Status: policyv1.PodDisruptionBudgetStatus{
			DisruptionsAllowed: 0,
			CurrentHealthy:     2,
			ExpectedPods:       2,
		},
	}
	for _, opt := range opts {
		opt(pdb)
	}
	return pdb
}

func minAvailable(n int32) func(*policyv1.PodDisruptionBudget) {
	return func(pdb *policyv1.PodDisruptionBudget) {
		v := intstr.FromInt32(n)
		pdb.Spec.MinAvailable = &v
	}
}

func maxUnavailable(n int32) func(*policyv1.PodDisruptionBudget) {
	return func(pdb *policyv1.PodDisruptionBudget) {
		v := intstr.FromInt32(n)
		pdb.Spec.MaxUnavailable = &v
	}
}

func newPod(namespace, name, nodeName string, labels map[string]string, owner *metav1.OwnerReference) *corev1.Pod {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace, Labels: labels},
		Spec:       corev1.PodSpec{NodeName: nodeName},
	}
	if owner != nil {
		pod.OwnerReferences = []metav1.OwnerReference{*owner}
	}
	return pod
}

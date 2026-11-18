package pdbblockingnodedrain

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	cloudtrailtypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	cmv1 "github.com/openshift-online/ocm-sdk-go/clustersmgmt/v1"
	awsmock "github.com/openshift/configuration-anomaly-detection/pkg/aws/mock"
	"github.com/openshift/configuration-anomaly-detection/pkg/executor"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/investigation"
	pdmock "github.com/openshift/configuration-anomaly-detection/pkg/pagerduty/mock"
	"go.uber.org/mock/gomock"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func stoppedTestMachine(t *testing.T, pool, instanceID string) *unstructured.Unstructured {
	t.Helper()
	machine := &unstructured.Unstructured{}
	machine.SetGroupVersionKind(schema.GroupVersionKind{Group: "infrastructure.cluster.x-k8s.io", Version: "v1beta2", Kind: "AWSMachine"})
	machine.SetNamespace("ocm-test-hcp")
	machine.SetName("worker-1")
	machine.SetLabels(map[string]string{awsMachineNodePoolLabel: "domain-prefix-" + pool})
	if err := unstructured.SetNestedField(machine.Object, instanceID, "spec", "instanceID"); err != nil {
		t.Fatal(err)
	}
	if err := unstructured.SetNestedField(machine.Object, "stopped", "status", "instanceState"); err != nil {
		t.Fatal(err)
	}
	return machine
}

func stoppedTestResources(t *testing.T, machine *unstructured.Unstructured, nodePool, pdPool string) (*investigation.ResourceBuilderMock, *awsmock.MockClient) {
	t.Helper()
	ctrl := gomock.NewController(t)
	pd := pdmock.NewMockClient(ctrl)
	pd.EXPECT().RetrieveNodePoolIDs().Return([]string{pdPool}, nil)
	awsClient := awsmock.NewMockClient(ctrl)
	cluster, err := cmv1.NewCluster().ID("cluster-123").DomainPrefix("domain-prefix").Build()
	if err != nil {
		t.Fatal(err)
	}
	node := newNode("node-1", []corev1.Taint{unschedulableTaint(timePtr(time.Now().Add(-3 * time.Hour)))})
	node.Spec.ProviderID = "aws:///us-east-1a/i-0stopped"
	node.Labels = map[string]string{hostedNodePoolLabel: nodePool}
	pod := newLabeledPod("web-0", "default", "node-1", map[string]string{"app": "web"}, nil)
	pdb := newPDB("web-pdb", "default", map[string]string{"app": "web"}, intstrPtr(2), nil, 0, 2, 2)
	return &investigation.ResourceBuilderMock{Resources: &investigation.Resources{
		IsHCP: true, Cluster: cluster, HCPNamespace: "ocm-test-hcp", HCNamespace: "clusters",
		K8sClient:           newFakeClient(node, pod, pdb),
		ManagementK8sClient: fake.NewClientBuilder().WithObjects(machine).Build(),
		AwsClient:           awsClient, PdClient: pd, Notes: newTestNotes(),
	}}, awsClient
}

func TestStoppedWorkerInAlertedPoolTakesPriorityOverPDB(t *testing.T) {
	rb, awsClient := stoppedTestResources(t, stoppedTestMachine(t, "workers-0", "i-0stopped"), "workers-0", "workers-0")
	stopTime := time.Now().Add(-24 * time.Hour)
	awsClient.EXPECT().GetInstanceByID(gomock.Cond(func(ctx context.Context) bool {
		_, hasDeadline := ctx.Deadline()
		return hasDeadline
	}), "i-0stopped").Return(ec2types.Instance{
		State: &ec2types.InstanceState{Name: ec2types.InstanceStateNameStopped},
	}, nil)
	awsClient.EXPECT().FindInstanceStopEvent(gomock.Cond(func(ctx context.Context) bool {
		_, hasDeadline := ctx.Deadline()
		return hasDeadline
	}), "i-0stopped").Return(&cloudtrailtypes.Event{
		EventName: awsv2.String("StopInstances"), EventTime: &stopTime,
	}, nil)

	result, err := (&Investigation{}).Run(rb)
	if err != nil {
		t.Fatal(err)
	}
	serviceLogs, escalations := 0, 0
	for _, action := range result.Actions {
		switch action.Type() {
		case string(executor.ActionTypeServiceLog):
			serviceLogs++
		case string(executor.ActionTypeEscalateIncident):
			escalations++
		case string(executor.ActionTypeSilenceIncident):
			t.Fatal("the upgrade incident must remain available for SRE review")
		}
	}
	if serviceLogs != 0 || escalations != 1 {
		t.Fatalf("expected a stopped-worker finding for SRE review without a customer service log; got %v", result.Actions)
	}
	if !strings.Contains(rb.Resources.Notes.String(), "CloudTrail StopInstances") {
		t.Fatal("expected stopped-worker evidence in the report")
	}
	if !strings.Contains(rb.Resources.Notes.String(), "if the stop was customer-initiated") {
		t.Fatal("expected a conditional customer-notification recommendation")
	}
	if strings.Contains(rb.Resources.Notes.String(), "Blocking PDBs") {
		t.Fatal("PDB checks must not run after a confirmed stopped worker")
	}
}

func TestStoppedWorkerInOtherPoolDoesNotOverridePDBPath(t *testing.T) {
	rb, _ := stoppedTestResources(t, stoppedTestMachine(t, "workers-1", "i-0stopped"), "workers-1", "workers-0")
	result, err := (&Investigation{}).Run(rb)
	if err != nil {
		t.Fatal(err)
	}
	for _, action := range result.Actions {
		if action.Type() == string(executor.ActionTypeServiceLog) {
			t.Fatal("unrelated stopped worker must not trigger a service log")
		}
	}
	if !strings.Contains(rb.Resources.Notes.String(), "Blocking PDBs: 1 PDB(s)") {
		t.Fatal("expected the usual PDB investigation to run")
	}
}

func TestStopAfterDrainDoesNotReplacePDBFinding(t *testing.T) {
	rb, awsClient := stoppedTestResources(t, stoppedTestMachine(t, "workers-0", "i-0stopped"), "workers-0", "workers-0")
	node := newNode("node-1", []corev1.Taint{unschedulableTaint(timePtr(time.Now().Add(-3 * time.Hour)))})
	node.Spec.ProviderID = "aws:///us-east-1a/i-0stopped"
	node.Labels = map[string]string{hostedNodePoolLabel: "workers-0"}
	pod := newLabeledPod("web-0", "default", "node-1", map[string]string{"app": "web"}, nil)
	pdb := newPDB("web-pdb", "default", map[string]string{"app": "web"}, intstrPtr(2), nil, 0, 2, 2)
	rb.Resources.K8sClient = newFakeClient(node, pod, pdb)
	stopTime := time.Now().Add(-time.Hour)
	awsClient.EXPECT().GetInstanceByID(gomock.Any(), "i-0stopped").Return(ec2types.Instance{
		State: &ec2types.InstanceState{Name: ec2types.InstanceStateNameStopped},
	}, nil)
	awsClient.EXPECT().FindInstanceStopEvent(gomock.Any(), "i-0stopped").Return(&cloudtrailtypes.Event{
		EventName: awsv2.String("StopInstances"), EventTime: &stopTime,
	}, nil)

	result, err := (&Investigation{}).Run(rb)
	if err != nil {
		t.Fatal(err)
	}
	for _, action := range result.Actions {
		if action.Type() == string(executor.ActionTypeServiceLog) {
			t.Fatal("a stop after the drain began must not replace the drain finding")
		}
	}
	if !strings.Contains(rb.Resources.Notes.String(), "after node node-1 began draining") {
		t.Fatal("expected the timeline discrepancy in the report")
	}
	if !strings.Contains(rb.Resources.Notes.String(), "Blocking PDBs: 1 PDB(s)") {
		t.Fatal("a later stop must retain the PDB finding")
	}
}

func TestStoppedWorkerWithoutCloudTrailKeepsManualReview(t *testing.T) {
	rb, awsClient := stoppedTestResources(t, stoppedTestMachine(t, "workers-0", "i-0stopped"), "workers-0", "workers-0")
	awsClient.EXPECT().GetInstanceByID(gomock.Any(), "i-0stopped").Return(ec2types.Instance{
		State: &ec2types.InstanceState{Name: ec2types.InstanceStateNameStopped},
	}, nil)
	awsClient.EXPECT().FindInstanceStopEvent(gomock.Any(), "i-0stopped").Return(nil, nil)

	result, err := (&Investigation{}).Run(rb)
	if err != nil {
		t.Fatal(err)
	}
	for _, action := range result.Actions {
		if action.Type() == string(executor.ActionTypeServiceLog) {
			t.Fatal("an unattributed stop must not trigger a customer service log")
		}
	}
	if !strings.Contains(rb.Resources.Notes.String(), "manual review required") {
		t.Fatal("expected the missing CloudTrail evidence to be reported")
	}
	if !strings.Contains(rb.Resources.Notes.String(), "Blocking PDBs: 1 PDB(s)") {
		t.Fatal("an unconfirmed stop must retain the PDB finding")
	}
}

func TestStaleAWSMachineStoppedStateDoesNotMaskPDB(t *testing.T) {
	rb, awsClient := stoppedTestResources(t, stoppedTestMachine(t, "workers-0", "i-0stopped"), "workers-0", "workers-0")
	awsClient.EXPECT().GetInstanceByID(gomock.Any(), "i-0stopped").Return(ec2types.Instance{
		State: &ec2types.InstanceState{Name: ec2types.InstanceStateNameRunning},
	}, nil)

	result, err := (&Investigation{}).Run(rb)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Actions) == 0 {
		t.Fatal("expected the ordinary drain investigation to report")
	}
	if !strings.Contains(rb.Resources.Notes.String(), "currently running") || !strings.Contains(rb.Resources.Notes.String(), "Blocking PDBs: 1 PDB(s)") {
		t.Fatal("expected stale AWSMachine state to be reported and the drain path to run")
	}
	if strings.Contains(rb.Resources.Notes.String(), "PDB findings below may be downstream") {
		t.Fatal("a currently running instance must not be treated as a suspected stop")
	}
}

func TestNodePoolValueMatches(t *testing.T) {
	for _, value := range []string{"workers-0", "domain-prefix-workers-0", "clusters/domain-prefix-workers-0", "clusters/workers-0"} {
		if !nodePoolValueMatches(value, "workers-0", "domain-prefix", "clusters") {
			t.Errorf("expected %q to match workers-0", value)
		}
	}
	for _, value := range []string{"domain-prefix-workers-1", "blue-workers-0", "clusters/blue-workers-0", "other-namespace/domain-prefix-workers-0"} {
		if nodePoolValueMatches(value, "workers-0", "domain-prefix", "clusters") {
			t.Errorf("another nodepool or namespace %q must not match", value)
		}
	}
}

type failingNodeListClient struct{ client.Client }

func (c failingNodeListClient) List(ctx context.Context, list client.ObjectList, opts ...client.ListOption) error {
	if _, ok := list.(*corev1.NodeList); ok {
		return errors.New("node API unavailable")
	}
	return c.Client.List(ctx, list, opts...)
}

func TestNodeListFailureDoesNotConfirmStoppedWorker(t *testing.T) {
	rb, _ := stoppedTestResources(t, stoppedTestMachine(t, "workers-0", "i-0stopped"), "workers-0", "workers-0")
	rb.Resources.K8sClient = failingNodeListClient{Client: rb.Resources.K8sClient}
	result, err := (&Investigation{}).Run(rb)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Actions) == 0 || !strings.Contains(rb.Resources.Notes.String(), "stop timing cannot be verified") {
		t.Fatal("expected manual review and the regular drain path after Node discovery fails")
	}
	if strings.Contains(rb.Resources.Notes.String(), "CloudTrail StopInstances") {
		t.Fatal("Node discovery failure must not confirm a stopped worker")
	}
}

func TestMalformedAWSMachineFieldsKeepPDBPath(t *testing.T) {
	tests := []struct {
		name    string
		path    []string
		warning string
	}{
		{name: "malformed state", path: []string{"status", "instanceState"}, warning: "unreadable instance state"},
		{name: "malformed instance ID", path: []string{"spec", "instanceID"}, warning: "unreadable instance ID"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			machine := stoppedTestMachine(t, "workers-0", "i-0stopped")
			if err := unstructured.SetNestedField(machine.Object, int64(1), tt.path...); err != nil {
				t.Fatal(err)
			}
			rb, _ := stoppedTestResources(t, machine, "workers-0", "workers-0")
			if _, err := (&Investigation{}).Run(rb); err != nil {
				t.Fatal(err)
			}
			notes := rb.Resources.Notes.String()
			if !strings.Contains(notes, tt.warning) || !strings.Contains(notes, "Blocking PDBs: 1 PDB(s)") {
				t.Fatalf("expected malformed field warning and PDB finding, got %s", notes)
			}
		})
	}
}

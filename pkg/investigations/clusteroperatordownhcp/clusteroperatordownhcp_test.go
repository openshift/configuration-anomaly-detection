package clusteroperatordownhcp

import (
	"errors"
	"testing"

	ec2v2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	cmv1 "github.com/openshift-online/ocm-sdk-go/clustersmgmt/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	awsmock "github.com/openshift/configuration-anomaly-detection/pkg/aws/mock"
	"github.com/openshift/configuration-anomaly-detection/pkg/executor"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/investigation"
	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
	"github.com/openshift/configuration-anomaly-detection/pkg/notewriter"
	"github.com/openshift/configuration-anomaly-detection/pkg/types"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func hasActionType(actions []types.Action, actionType string) bool {
	for _, action := range actions {
		if action.Type() == actionType {
			return true
		}
	}
	return false
}

func hasEscalateAction(actions []types.Action) bool {
	return hasActionType(actions, string(executor.ActionTypeEscalateIncident))
}

func hasSilenceAction(actions []types.Action) bool {
	return hasActionType(actions, string(executor.ActionTypeSilenceIncident))
}

func hasServiceLogAction(actions []types.Action) bool {
	return hasActionType(actions, string(executor.ActionTypeServiceLog))
}

// awsMachine builds an unstructured AWSMachine for the fake management client,
// mirroring the real CAPA shape (spec.instanceID + spec.providerID +
// status.instanceState). instanceID may be empty to simulate a machine whose
// instance ID is not yet populated.
func awsMachine(namespace, name, instanceState, instanceID string) *unstructured.Unstructured {
	m := &unstructured.Unstructured{}
	m.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   "infrastructure.cluster.x-k8s.io",
		Version: "v1beta2",
		Kind:    "AWSMachine",
	})
	m.SetNamespace(namespace)
	m.SetName(name)
	if instanceID != "" {
		_ = unstructured.SetNestedField(m.Object, instanceID, "spec", "instanceID")
		_ = unstructured.SetNestedField(m.Object, "aws:///us-east-2a/"+instanceID, "spec", "providerID")
	}
	_ = unstructured.SetNestedField(m.Object, instanceState, "status", "instanceState")
	return m
}

func TestInvestigation_Name(t *testing.T) {
	assert.Equal(t, "clusteroperatordownhcp", (&Investigation{}).Name())
}

func TestInstanceIDFromProviderID(t *testing.T) {
	tests := []struct {
		name       string
		providerID string
		want       string
	}{
		{
			name:       "A well-formed providerID yields the instance ID",
			providerID: "aws:///us-east-1a/i-0abc123def456",
			want:       "i-0abc123def456",
		},
		{
			name:       "A short instance ID is still extracted",
			providerID: "aws:///eu-west-2b/i-1",
			want:       "i-1",
		},
		{
			name:       "An empty providerID yields an empty ID",
			providerID: "",
			want:       "",
		},
		{
			name:       "A providerID without an instance segment yields an empty ID",
			providerID: "aws:///us-east-1a/",
			want:       "",
		},
		{
			name:       "A providerID without slashes yields an empty ID",
			providerID: "garbage-without-slashes",
			want:       "",
		},
		{
			name:       "A last segment that is not an i- ID yields an empty ID",
			providerID: "aws:///us-east-1a/notaninstance",
			want:       "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, instanceIDFromProviderID(tt.providerID))
		})
	}
}

func TestInvestigation_Run_BuildError(t *testing.T) {
	buildErr := errors.New("build failed")
	rb := &investigation.ResourceBuilderMock{Resources: nil, BuildError: buildErr}

	result, err := (&Investigation{}).Run(rb)
	assert.Empty(t, result)
	assert.Equal(t, buildErr, err)
}

// A non-HCP occurrence must reach a human, not the AI fallback, so it escalates
// rather than silences.
func TestInvestigation_Run_NonHCPEscalates(t *testing.T) {
	cluster, err := cmv1.NewCluster().ID("test-123").Build()
	require.NoError(t, err)

	rb := &investigation.ResourceBuilderMock{
		Resources: &investigation.Resources{
			IsHCP:   false,
			Cluster: cluster,
			Notes:   notewriter.New("test", logging.RawLogger),
		},
	}

	result, err := (&Investigation{}).Run(rb)
	assert.NoError(t, err)
	assert.True(t, hasEscalateAction(result.Actions), "non-HCP should escalate to a human")
	assert.False(t, hasSilenceAction(result.Actions), "non-HCP must not silence")
	assert.False(t, hasServiceLogAction(result.Actions), "non-HCP must not send a service log")
}

// When no data plane instance is stopped the degraded operator has another
// cause, so CAD escalates instead of remediating.
func TestInvestigation_Run_NoStoppedMachineEscalates(t *testing.T) {
	cluster, err := cmv1.NewCluster().ID("test-123").Build()
	require.NoError(t, err)

	hcpNamespace := "ocm-test-hcp-namespace"
	running := awsMachine(hcpNamespace, "worker-1", "running", "i-0running")
	fakeK8s := fake.NewClientBuilder().WithObjects(running).Build()

	rb := &investigation.ResourceBuilderMock{
		Resources: &investigation.Resources{
			IsHCP:               true,
			Cluster:             cluster,
			HCPNamespace:        hcpNamespace,
			ManagementK8sClient: fakeK8s,
			Notes:               notewriter.New("test", logging.RawLogger),
		},
	}

	result, err := (&Investigation{}).Run(rb)
	assert.NoError(t, err)
	assert.True(t, hasEscalateAction(result.Actions), "no stopped machine should escalate")
	assert.False(t, hasServiceLogAction(result.Actions), "no service log when nothing is stopped")
}

// An empty AWSMachine list (no data plane machines in the namespace) is treated
// the same as "none stopped": escalate, never remediate on absent data.
func TestInvestigation_Run_EmptyMachineListEscalates(t *testing.T) {
	cluster, err := cmv1.NewCluster().ID("test-123").Build()
	require.NoError(t, err)

	fakeK8s := fake.NewClientBuilder().Build()
	rb := &investigation.ResourceBuilderMock{
		Resources: &investigation.Resources{
			IsHCP:               true,
			Cluster:             cluster,
			HCPNamespace:        "ocm-test-hcp-namespace",
			ManagementK8sClient: fakeK8s,
			Notes:               notewriter.New("test", logging.RawLogger),
		},
	}

	result, err := (&Investigation{}).Run(rb)
	assert.NoError(t, err)
	assert.True(t, hasEscalateAction(result.Actions), "empty machine list should escalate")
	assert.False(t, hasServiceLogAction(result.Actions), "no service log on an empty list")
	assert.False(t, hasSilenceAction(result.Actions), "must not silence on an empty list")
}

// A stopped data plane instance is a customer action on HCP: send the service
// log and silence, with CloudTrail attribution recorded in the note.
func TestInvestigation_Run_StoppedMachineSendsServiceLogAndSilences(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	cluster, err := cmv1.NewCluster().ID("test-123").Build()
	require.NoError(t, err)

	hcpNamespace := "ocm-test-hcp-namespace"
	instanceID := "i-0stopped456"
	stopped := awsMachine(hcpNamespace, "worker-1", "stopped", instanceID)
	fakeK8s := fake.NewClientBuilder().WithObjects(stopped).Build()

	awsCli := awsmock.NewMockClient(mockCtrl)
	stoppedInstance := ec2v2types.Instance{InstanceId: &instanceID}
	awsCli.EXPECT().GetInstanceByID(gomock.Any(), instanceID).Return(stoppedInstance, nil)
	// Attribution is best-effort; returning no events still yields the remediation.
	awsCli.EXPECT().PollInstanceStopEventsFor(gomock.Any(), gomock.Any()).Return(nil, nil)

	rb := &investigation.ResourceBuilderMock{
		Resources: &investigation.Resources{
			IsHCP:               true,
			Cluster:             cluster,
			HCPNamespace:        hcpNamespace,
			ManagementK8sClient: fakeK8s,
			AwsClient:           awsCli,
			Notes:               notewriter.New("test", logging.RawLogger),
		},
	}

	result, err := (&Investigation{}).Run(rb)
	assert.NoError(t, err)
	assert.True(t, hasServiceLogAction(result.Actions), "stopped machine should send a service log")
	assert.True(t, hasSilenceAction(result.Actions), "stopped machine should silence")
	assert.False(t, hasEscalateAction(result.Actions), "stopped machine should not escalate")
}

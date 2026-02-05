package executor

import (
	"context"
	"errors"
	"testing"

	cmv1 "github.com/openshift-online/ocm-sdk-go/clustersmgmt/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"go.uber.org/zap"

	bpmock "github.com/openshift/configuration-anomaly-detection/pkg/backplane/mock"
	ocmmock "github.com/openshift/configuration-anomaly-detection/pkg/ocm/mock"
	pdmock "github.com/openshift/configuration-anomaly-detection/pkg/pagerduty/mock"
)

// Mock action for testing
type mockAction struct {
	actionType ActionType
	executed   *bool
	shouldFail bool
}

func (m *mockAction) Type() string {
	return string(m.actionType)
}

func (m *mockAction) Validate() error {
	if m.shouldFail {
		return errors.New("validation error")
	}
	return nil
}

func (m *mockAction) Execute(ctx context.Context, execCtx *ExecutionContext) error {
	if m.executed != nil {
		*m.executed = true
	}
	if m.shouldFail {
		return errors.New("execution error")
	}
	return nil
}

func TestWebhookExecutor_ExecutesAllActions(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockOCMClient := ocmmock.NewMockClient(ctrl)
	mockPDClient := pdmock.NewMockClient(ctrl)
	mockBPClient := &bpmock.MockClient{}
	logger := zap.NewNop().Sugar()

	// Create WebhookExecutor
	exec := NewWebhookExecutor(mockOCMClient, mockPDClient, mockBPClient, logger)

	// Track execution
	pdNoteExecuted := false
	serviceLogExecuted := false
	silenceExecuted := false

	// Create mixed actions
	actions := []Action{
		&mockAction{actionType: ActionTypePagerDutyNote, executed: &pdNoteExecuted},
		&mockAction{actionType: ActionTypeServiceLog, executed: &serviceLogExecuted},
		&mockAction{actionType: ActionTypeSilenceIncident, executed: &silenceExecuted},
	}

	cluster, _ := cmv1.NewCluster().ID("test-cluster").Build()
	input := &ExecutorInput{
		InvestigationName: "test-investigation",
		Actions:           actions,
		Cluster:           cluster,
		Options: ExecutionOptions{
			DryRun:            false,
			StopOnError:       false,
			MaxRetries:        0,
			ConcurrentActions: false,
		},
	}

	// Execute
	err := exec.Execute(context.Background(), input)

	// Assert all actions executed
	assert.NoError(t, err)
	assert.True(t, pdNoteExecuted, "PagerDuty note should be executed")
	assert.True(t, serviceLogExecuted, "Service log should be executed")
	assert.True(t, silenceExecuted, "Silence incident should be executed")
}

func TestManualExecutor_FiltersPagerDutyActions(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockOCMClient := ocmmock.NewMockClient(ctrl)
	mockBPClient := &bpmock.MockClient{}
	logger := zap.NewNop().Sugar()

	// Create ManualExecutor (no PD client)
	exec := NewManualExecutor(mockOCMClient, mockBPClient, logger)

	// Track execution
	pdNoteExecuted := false
	serviceLogExecuted := false
	silenceExecuted := false
	escalateExecuted := false

	// Create mixed actions
	actions := []Action{
		&mockAction{actionType: ActionTypePagerDutyNote, executed: &pdNoteExecuted},
		&mockAction{actionType: ActionTypeServiceLog, executed: &serviceLogExecuted},
		&mockAction{actionType: ActionTypeSilenceIncident, executed: &silenceExecuted},
		&mockAction{actionType: ActionTypeEscalateIncident, executed: &escalateExecuted},
	}

	cluster, _ := cmv1.NewCluster().ID("test-cluster").Build()
	input := &ExecutorInput{
		InvestigationName: "test-investigation",
		Actions:           actions,
		Cluster:           cluster,
		Options: ExecutionOptions{
			DryRun:            false,
			StopOnError:       false,
			MaxRetries:        0,
			ConcurrentActions: false,
		},
	}

	// Execute
	err := exec.Execute(context.Background(), input)

	// Assert only non-PD actions executed
	assert.NoError(t, err)
	assert.False(t, pdNoteExecuted, "PagerDuty note should be filtered")
	assert.True(t, serviceLogExecuted, "Service log should be executed")
	assert.False(t, silenceExecuted, "Silence incident should be filtered")
	assert.False(t, escalateExecuted, "Escalate incident should be filtered")
}

func TestManualExecutor_ExecutesOCMActions(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockOCMClient := ocmmock.NewMockClient(ctrl)
	mockBPClient := &bpmock.MockClient{}
	logger := zap.NewNop().Sugar()

	// Create ManualExecutor
	exec := NewManualExecutor(mockOCMClient, mockBPClient, logger)

	// Track execution
	serviceLogExecuted := false
	limitedSupportExecuted := false

	// Create only OCM actions
	actions := []Action{
		&mockAction{actionType: ActionTypeServiceLog, executed: &serviceLogExecuted},
		&mockAction{actionType: ActionTypeLimitedSupport, executed: &limitedSupportExecuted},
	}

	cluster, _ := cmv1.NewCluster().ID("test-cluster").Build()
	input := &ExecutorInput{
		InvestigationName: "test-investigation",
		Actions:           actions,
		Cluster:           cluster,
		Options: ExecutionOptions{
			DryRun:            false,
			StopOnError:       false,
			MaxRetries:        0,
			ConcurrentActions: false,
		},
	}

	// Execute
	err := exec.Execute(context.Background(), input)

	// Assert all OCM actions executed
	assert.NoError(t, err)
	assert.True(t, serviceLogExecuted, "Service log should be executed")
	assert.True(t, limitedSupportExecuted, "Limited support should be executed")
}

func TestManualExecutor_ReturnsNilWhenAllActionsFiltered(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockOCMClient := ocmmock.NewMockClient(ctrl)
	mockBPClient := &bpmock.MockClient{}
	logger := zap.NewNop().Sugar()

	// Create ManualExecutor
	exec := NewManualExecutor(mockOCMClient, mockBPClient, logger)

	// Track execution
	pdNoteExecuted := false
	silenceExecuted := false

	// Create only PD actions (all should be filtered)
	actions := []Action{
		&mockAction{actionType: ActionTypePagerDutyNote, executed: &pdNoteExecuted},
		&mockAction{actionType: ActionTypeSilenceIncident, executed: &silenceExecuted},
	}

	cluster, _ := cmv1.NewCluster().ID("test-cluster").Build()
	input := &ExecutorInput{
		InvestigationName: "test-investigation",
		Actions:           actions,
		Cluster:           cluster,
		Options: ExecutionOptions{
			DryRun:            false,
			StopOnError:       false,
			MaxRetries:        0,
			ConcurrentActions: false,
		},
	}

	// Execute
	err := exec.Execute(context.Background(), input)

	// Assert no error and no actions executed
	assert.NoError(t, err)
	assert.False(t, pdNoteExecuted, "PagerDuty note should be filtered")
	assert.False(t, silenceExecuted, "Silence incident should be filtered")
}

func TestIsPagerDutyAction(t *testing.T) {
	tests := []struct {
		name     string
		action   Action
		expected bool
	}{
		{
			name:     "PagerDuty note is PD action",
			action:   &mockAction{actionType: ActionTypePagerDutyNote},
			expected: true,
		},
		{
			name:     "Silence incident is PD action",
			action:   &mockAction{actionType: ActionTypeSilenceIncident},
			expected: true,
		},
		{
			name:     "Escalate incident is PD action",
			action:   &mockAction{actionType: ActionTypeEscalateIncident},
			expected: true,
		},
		{
			name:     "Service log is not PD action",
			action:   &mockAction{actionType: ActionTypeServiceLog},
			expected: false,
		},
		{
			name:     "Limited support is not PD action",
			action:   &mockAction{actionType: ActionTypeLimitedSupport},
			expected: false,
		},
		{
			name:     "Backplane report is not PD action",
			action:   &mockAction{actionType: ActionTypeBackplaneReport},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isPagerDutyAction(tt.action)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestWebhookExecutor_Type(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockOCMClient := ocmmock.NewMockClient(ctrl)
	mockPDClient := pdmock.NewMockClient(ctrl)
	mockBPClient := &bpmock.MockClient{}
	logger := zap.NewNop().Sugar()

	exec := NewWebhookExecutor(mockOCMClient, mockPDClient, mockBPClient, logger)
	require.NotNil(t, exec)

	// Verify it's the right type
	webhookExec, ok := exec.(*WebhookExecutor)
	require.True(t, ok, "Should be a WebhookExecutor")
	require.NotNil(t, webhookExec.DefaultExecutor)
}

func TestManualExecutor_Type(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockOCMClient := ocmmock.NewMockClient(ctrl)
	mockBPClient := &bpmock.MockClient{}
	logger := zap.NewNop().Sugar()

	exec := NewManualExecutor(mockOCMClient, mockBPClient, logger)
	require.NotNil(t, exec)

	// Verify it's the right type
	manualExec, ok := exec.(*ManualExecutor)
	require.True(t, ok, "Should be a ManualExecutor")
	require.NotNil(t, manualExec.DefaultExecutor)
}

func TestManualExecutor_NilInputHandling(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockOCMClient := ocmmock.NewMockClient(ctrl)
	mockBPClient := &bpmock.MockClient{}
	logger := zap.NewNop().Sugar()

	exec := NewManualExecutor(mockOCMClient, mockBPClient, logger)

	// Execute with nil input
	err := exec.Execute(context.Background(), nil)

	// Should return error
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "ExecutorInput cannot be nil")
}

func TestManualExecutor_EmptyActionsHandling(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockOCMClient := ocmmock.NewMockClient(ctrl)
	mockBPClient := &bpmock.MockClient{}
	logger := zap.NewNop().Sugar()

	exec := NewManualExecutor(mockOCMClient, mockBPClient, logger)

	cluster, _ := cmv1.NewCluster().ID("test-cluster").Build()
	input := &ExecutorInput{
		InvestigationName: "test-investigation",
		Actions:           []Action{}, // Empty
		Cluster:           cluster,
		Options: ExecutionOptions{
			DryRun:            false,
			StopOnError:       false,
			MaxRetries:        0,
			ConcurrentActions: false,
		},
	}

	// Execute with empty actions
	err := exec.Execute(context.Background(), input)

	// Should not return error
	assert.NoError(t, err)
}

// Integration-style test verifying the full filtering flow
func TestManualExecutor_IntegrationFiltering(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockOCMClient := ocmmock.NewMockClient(ctrl)
	mockBPClient := &bpmock.MockClient{}
	logger := zap.NewNop().Sugar()

	exec := NewManualExecutor(mockOCMClient, mockBPClient, logger)

	// Create a realistic scenario: investigation returns both OCM and PD actions
	pdNote1Executed := false
	pdNote2Executed := false
	serviceLog1Executed := false
	serviceLog2Executed := false
	silenceExecuted := false
	limitedSupportExecuted := false
	titleUpdateExecuted := false

	actions := []Action{
		&mockAction{actionType: ActionTypePagerDutyNote, executed: &pdNote1Executed},
		&mockAction{actionType: ActionTypeServiceLog, executed: &serviceLog1Executed},
		&mockAction{actionType: ActionTypePagerDutyNote, executed: &pdNote2Executed},
		&mockAction{actionType: ActionTypeLimitedSupport, executed: &limitedSupportExecuted},
		&mockAction{actionType: ActionTypeServiceLog, executed: &serviceLog2Executed},
		&mockAction{actionType: ActionTypeSilenceIncident, executed: &silenceExecuted},
		&mockAction{actionType: ActionTypePagerDutyTitleUpdate, executed: &titleUpdateExecuted},
	}

	cluster, _ := cmv1.NewCluster().ID("test-cluster").Build()
	input := &ExecutorInput{
		InvestigationName: "test-investigation",
		Actions:           actions,
		Cluster:           cluster,
		Options: ExecutionOptions{
			DryRun:            false,
			StopOnError:       false,
			MaxRetries:        0,
			ConcurrentActions: false,
		},
	}

	err := exec.Execute(context.Background(), input)

	// Verify correct filtering
	assert.NoError(t, err)
	assert.False(t, pdNote1Executed, "First PD note should be filtered")
	assert.True(t, serviceLog1Executed, "First service log should execute")
	assert.False(t, pdNote2Executed, "Second PD note should be filtered")
	assert.True(t, limitedSupportExecuted, "Limited support should execute")
	assert.True(t, serviceLog2Executed, "Second service log should execute")
	assert.False(t, silenceExecuted, "Silence should be filtered")
	assert.False(t, titleUpdateExecuted, "Title update should be filtered")
}

func TestManualExecutor_DryRunMode(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockOCMClient := ocmmock.NewMockClient(ctrl)
	mockBPClient := &bpmock.MockClient{}
	logger := zap.NewNop().Sugar()

	exec := NewManualExecutor(mockOCMClient, mockBPClient, logger)

	// Track execution - should NOT be executed in dry-run mode
	serviceLogExecuted := false
	limitedSupportExecuted := false

	actions := []Action{
		&mockAction{actionType: ActionTypeServiceLog, executed: &serviceLogExecuted},
		&mockAction{actionType: ActionTypeLimitedSupport, executed: &limitedSupportExecuted},
	}

	cluster, _ := cmv1.NewCluster().ID("test-cluster").Build()
	input := &ExecutorInput{
		InvestigationName: "test-investigation",
		Actions:           actions,
		Cluster:           cluster,
		Options: ExecutionOptions{
			DryRun:            true, // Enable dry-run mode
			StopOnError:       false,
			MaxRetries:        0,
			ConcurrentActions: false,
		},
	}

	err := exec.Execute(context.Background(), input)

	// Verify no actions were executed in dry-run mode
	assert.NoError(t, err)
	assert.False(t, serviceLogExecuted, "Service log should NOT execute in dry-run mode")
	assert.False(t, limitedSupportExecuted, "Limited support should NOT execute in dry-run mode")
}

func TestWebhookExecutor_DryRunMode_ConcurrentActions(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockOCMClient := ocmmock.NewMockClient(ctrl)
	mockPDClient := pdmock.NewMockClient(ctrl)
	mockBPClient := &bpmock.MockClient{}
	logger := zap.NewNop().Sugar()

	exec := NewWebhookExecutor(mockOCMClient, mockPDClient, mockBPClient, logger)

	// Track execution - should NOT be executed in dry-run mode
	pdNoteExecuted := false
	serviceLogExecuted := false
	silenceExecuted := false
	backplaneExecuted := false

	actions := []Action{
		&mockAction{actionType: ActionTypePagerDutyNote, executed: &pdNoteExecuted},
		&mockAction{actionType: ActionTypeServiceLog, executed: &serviceLogExecuted},
		&mockAction{actionType: ActionTypeSilenceIncident, executed: &silenceExecuted},
		&mockAction{actionType: ActionTypeBackplaneReport, executed: &backplaneExecuted},
	}

	cluster, _ := cmv1.NewCluster().ID("test-cluster").Build()
	input := &ExecutorInput{
		InvestigationName: "test-investigation",
		Actions:           actions,
		Cluster:           cluster,
		Options: ExecutionOptions{
			DryRun:            true, // Enable dry-run mode
			StopOnError:       false,
			MaxRetries:        0,
			ConcurrentActions: true, // Test concurrent execution path
		},
	}

	err := exec.Execute(context.Background(), input)

	// Verify no actions were executed in dry-run mode
	assert.NoError(t, err)
	assert.False(t, pdNoteExecuted, "PD note should NOT execute in dry-run mode")
	assert.False(t, serviceLogExecuted, "Service log should NOT execute in dry-run mode")
	assert.False(t, silenceExecuted, "Silence should NOT execute in dry-run mode")
	assert.False(t, backplaneExecuted, "Backplane report should NOT execute in dry-run mode")
}

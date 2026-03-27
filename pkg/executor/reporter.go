package executor

import (
	"context"
	"fmt"

	cmv1 "github.com/openshift-online/ocm-sdk-go/clustersmgmt/v1"
	"github.com/openshift/configuration-anomaly-detection/pkg/backplane"
	"github.com/openshift/configuration-anomaly-detection/pkg/notewriter"
	"github.com/openshift/configuration-anomaly-detection/pkg/ocm"
	"github.com/openshift/configuration-anomaly-detection/pkg/pagerduty"
	"go.uber.org/zap"
)

// Executor executes external system updates based on investigation results
type Executor interface {
	// Execute executes all actions from an investigation result
	Execute(ctx context.Context, input *ExecutorInput) error
}

// ExecutorInput contains all context needed to execute actions
type ExecutorInput struct {
	// InvestigationName identifies which investigation produced these actions
	InvestigationName string

	// Actions to execute
	Actions []Action

	// Cluster context for actions that need it
	Cluster *cmv1.Cluster

	// Notes accumulated during investigation (optional)
	Notes *notewriter.NoteWriter

	// ExecutionOptions controls how actions are executed
	Options ExecutionOptions
}

// ExecutionOptions controls reporter behavior
type ExecutionOptions struct {
	// DryRun logs what would happen without executing
	DryRun bool

	// StopOnError halts execution on first error
	StopOnError bool

	// MaxRetries for transient failures
	MaxRetries int

	// ConcurrentActions allows parallel execution of independent actions
	ConcurrentActions bool
}

// DefaultExecutor is the production implementation of Executor
type DefaultExecutor struct {
	ocmClient       ocm.Client
	pdClient        pagerduty.Client
	backplaneClient backplane.Client

	logger *zap.SugaredLogger
}

// WebhookExecutor executes all actions including PagerDuty actions
// Used for webhook-triggered investigations
type WebhookExecutor struct {
	*DefaultExecutor
}

// NewWebhookExecutor creates an executor for webhook-triggered investigations
// Executes all action types including PagerDuty actions
func NewWebhookExecutor(ocmClient ocm.Client, pdClient pagerduty.Client, bpClient backplane.Client, logger *zap.SugaredLogger) Executor {
	return &WebhookExecutor{
		DefaultExecutor: &DefaultExecutor{
			ocmClient:       ocmClient,
			pdClient:        pdClient,
			backplaneClient: bpClient,
			logger:          logger,
		},
	}
}

// ManualExecutor executes actions but skips PagerDuty-specific actions
// Used for manual CLI-triggered investigations
type ManualExecutor struct {
	*DefaultExecutor
}

// NewManualExecutor creates an executor for manual investigations
// Filters out PagerDuty actions (notes, silence, escalate) since there's no incident
func NewManualExecutor(ocmClient ocm.Client, bpClient backplane.Client, logger *zap.SugaredLogger) Executor {
	return &ManualExecutor{
		DefaultExecutor: &DefaultExecutor{
			ocmClient:       ocmClient,
			pdClient:        nil, // No PD client for manual runs
			backplaneClient: bpClient,
			logger:          logger,
		},
	}
}

// Execute filters PagerDuty actions before executing
func (e *ManualExecutor) Execute(ctx context.Context, input *ExecutorInput) error {
	if input == nil {
		return fmt.Errorf("ExecutorInput cannot be nil")
	}

	if len(input.Actions) == 0 {
		e.logger.Debug("No actions to execute")
		return nil
	}

	// Filter out PagerDuty actions
	filteredActions := make([]Action, 0, len(input.Actions))
	skippedCount := 0

	for _, action := range input.Actions {
		if isPagerDutyAction(action) {
			e.logger.Infof("Skipping PagerDuty action in manual mode: %s", action.Type())
			skippedCount++
			continue
		}
		filteredActions = append(filteredActions, action)
	}

	if skippedCount > 0 {
		e.logger.Infof("Skipped %d PagerDuty action(s) in manual execution mode", skippedCount)
	}

	if len(filteredActions) == 0 {
		e.logger.Debug("No actions to execute after filtering")
		return nil
	}

	// Create filtered input
	filteredInput := *input
	filteredInput.Actions = filteredActions

	// Delegate to parent executor
	return e.DefaultExecutor.Execute(ctx, &filteredInput)
}

// isPagerDutyAction checks if an action is PagerDuty-specific
func isPagerDutyAction(action Action) bool {
	switch action.Type() {
	case string(ActionTypePagerDutyNote),
		string(ActionTypeSilenceIncident),
		string(ActionTypeEscalateIncident),
		string(ActionTypePagerDutyTitleUpdate):
		return true
	default:
		return false
	}
}

// InfraClusterExecutor wraps another executor and transforms actions that should not
// be performed on infrastructure clusters (hive, management, or service clusters).
// Limited Support, Silence, and SL actions are replaced with an escalation and
// a PagerDuty note explaining the substitution.
type InfraClusterExecutor struct {
	inner  Executor
	logger *zap.SugaredLogger
}

// NewInfraClusterExecutor creates an executor that intercepts unsuitable actions
// for infrastructure clusters.
func NewInfraClusterExecutor(inner Executor, logger *zap.SugaredLogger) Executor {
	return &InfraClusterExecutor{inner: inner, logger: logger}
}

func (e *InfraClusterExecutor) Execute(ctx context.Context, input *ExecutorInput) error {
	if input == nil {
		return fmt.Errorf("ExecutorInput cannot be nil")
	}

	if len(input.Actions) == 0 {
		return e.inner.Execute(ctx, input)
	}

	transformedActions := make([]Action, 0, len(input.Actions))
	needsEscalation := false
	var interceptedDescriptions []string

	for _, action := range input.Actions {
		switch action.Type() {
		case string(ActionTypeLimitedSupport):
			e.logger.Infof("Infrastructure cluster: intercepting LimitedSupport action")
			interceptedDescriptions = append(interceptedDescriptions, "Limited Support")
			needsEscalation = true

		case string(ActionTypeSilenceIncident):
			e.logger.Infof("Infrastructure cluster: intercepting Silence action")
			interceptedDescriptions = append(interceptedDescriptions, "Silence")
			needsEscalation = true

		case string(ActionTypeServiceLog):
			e.logger.Infof("Infrastructure cluster: intercepting ServiceLog action")
			interceptedDescriptions = append(interceptedDescriptions, "ServiceLog")
			needsEscalation = true

		default:
			transformedActions = append(transformedActions, action)
		}
	}

	if needsEscalation {
		noteContent := fmt.Sprintf(
			"⚠️ Infra cluster detected: the following action(s) were not executed and replaced with escalation: %s. "+
				"Please investigate and take appropriate action manually.",
			joinDescriptions(interceptedDescriptions),
		)
		transformedActions = append(transformedActions,
			&PagerDutyNoteAction{Content: noteContent},
			&EscalateIncidentAction{Reason: "Infra cluster: actions intercepted"},
		)
	}

	filteredInput := *input
	filteredInput.Actions = transformedActions
	return e.inner.Execute(ctx, &filteredInput)
}

// joinDescriptions joins action type descriptions for the PD note
func joinDescriptions(descriptions []string) string {
	seen := make(map[string]bool)
	unique := make([]string, 0, len(descriptions))
	for _, d := range descriptions {
		if !seen[d] {
			seen[d] = true
			unique = append(unique, d)
		}
	}

	if len(unique) == 1 {
		return unique[0]
	}
	return fmt.Sprintf("%s and %s",
		joinWithComma(unique[:len(unique)-1]),
		unique[len(unique)-1],
	)
}

func joinWithComma(items []string) string {
	result := ""
	for i, item := range items {
		if i > 0 {
			result += ", "
		}
		result += item
	}
	return result
}

func (e *DefaultExecutor) Execute(ctx context.Context, input *ExecutorInput) error {
	if input == nil {
		return fmt.Errorf("ExecutorInput cannot be nil")
	}

	if len(input.Actions) == 0 {
		e.logger.Debug("No actions to execute")
		return nil
	}

	// Apply default options
	opts := input.Options
	if opts.MaxRetries == 0 {
		opts.MaxRetries = 3 // Default retry count
	}

	e.logger.Infof("Executing %d actions for investigation %s",
		len(input.Actions), input.InvestigationName)

	// Validate all actions first
	for i, action := range input.Actions {
		if err := action.Validate(); err != nil {
			return ActionValidationError{
				ActionType: ActionType(action.Type()),
				Err:        fmt.Errorf("action %d: %w", i, err),
			}
		}
	}

	// Create execution context
	execCtx := &ExecutionContext{
		Cluster:           input.Cluster,
		OCMClient:         e.ocmClient,
		PDClient:          e.pdClient,
		BackplaneClient:   e.backplaneClient,
		InvestigationName: input.InvestigationName,
		Logger:            e.logger,
	}

	// Execute actions
	if opts.ConcurrentActions {
		return e.executeConcurrent(ctx, input.Actions, execCtx, opts)
	}
	return e.executeSequential(ctx, input.Actions, execCtx, opts)
}

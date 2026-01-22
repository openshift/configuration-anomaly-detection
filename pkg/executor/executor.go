package executor

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/openshift/configuration-anomaly-detection/pkg/metrics"
)

func (e *DefaultExecutor) executeSequential(
	ctx context.Context,
	actions []Action,
	execCtx *ExecutionContext,
	opts ExecutionOptions,
) error {
	actionErrors := make([]error, 0, len(actions))

	for i, action := range actions {
		actionLogger := execCtx.Logger.With(
			"action_index", i,
			"action_type", action.Type(),
		)

		// Update context with action-specific logger
		actionExecCtx := &ExecutionContext{
			Cluster:           execCtx.Cluster,
			OCMClient:         execCtx.OCMClient,
			PDClient:          execCtx.PDClient,
			InvestigationName: execCtx.InvestigationName,
			Logger:            actionLogger,
		}

		if opts.DryRun {
			actionLogger.Infof("DRY RUN: Would execute action %s", action.Type())
			continue
		}

		// Execute with retry
		err := e.executeWithRetry(ctx, action, actionExecCtx, opts.MaxRetries)
		if err != nil {
			actionLogger.Errorf("Action failed: %v", err)
			actionErrors = append(actionErrors, ActionExecutionError{
				ActionType: ActionType(action.Type()),
				Attempt:    opts.MaxRetries + 1,
				Err:        err,
			})

			if opts.StopOnError {
				break
			}
		} else {
			actionLogger.Infof("Action completed successfully")
		}
	}

	if len(actionErrors) > 0 {
		return MultipleActionsError{Errors: actionErrors}
	}

	return nil
}

func (e *DefaultExecutor) executeConcurrent(
	ctx context.Context,
	actions []Action,
	execCtx *ExecutionContext,
	opts ExecutionOptions,
) error {
	// Group actions by type to determine what can run in parallel
	// Rules:
	// - PagerDuty actions must run sequentially (note, then silence/escalate)
	// - OCM actions can run in parallel
	// - Backplane actions can run in parallel

	type actionWithIndex struct {
		action Action
		index  int
	}

	var (
		pdActions  []actionWithIndex
		ocmActions []actionWithIndex
		bpActions  []actionWithIndex
	)

	for i, action := range actions {
		actionType := action.Type()
		switch actionType {
		case string(ActionTypePagerDutyNote), string(ActionTypeSilenceIncident), string(ActionTypeEscalateIncident):
			pdActions = append(pdActions, actionWithIndex{action, i})
		case string(ActionTypeServiceLog), string(ActionTypeLimitedSupport):
			ocmActions = append(ocmActions, actionWithIndex{action, i})
		case string(ActionTypeBackplaneReport):
			bpActions = append(bpActions, actionWithIndex{action, i})
		}
	}

	var wg sync.WaitGroup
	errorsChan := make(chan error, len(actions))

	// Execute PagerDuty actions sequentially (in original order)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for _, a := range pdActions {
			if err := e.executeWithRetry(ctx, a.action, execCtx, opts.MaxRetries); err != nil {
				errorsChan <- ActionExecutionError{
					ActionType: ActionType(a.action.Type()),
					Attempt:    opts.MaxRetries + 1,
					Err:        err,
				}
				if opts.StopOnError {
					return
				}
			}
		}
	}()

	// Execute OCM actions in parallel
	for _, a := range ocmActions {
		wg.Add(1)
		go func(a actionWithIndex) {
			defer wg.Done()
			if err := e.executeWithRetry(ctx, a.action, execCtx, opts.MaxRetries); err != nil {
				errorsChan <- ActionExecutionError{
					ActionType: ActionType(a.action.Type()),
					Attempt:    opts.MaxRetries + 1,
					Err:        err,
				}
			}
		}(a)
	}

	// Execute Backplane actions in parallel
	for _, a := range bpActions {
		wg.Add(1)
		go func(a actionWithIndex) {
			defer wg.Done()
			if err := e.executeWithRetry(ctx, a.action, execCtx, opts.MaxRetries); err != nil {
				errorsChan <- ActionExecutionError{
					ActionType: ActionType(a.action.Type()),
					Attempt:    opts.MaxRetries + 1,
					Err:        err,
				}
			}
		}(a)
	}

	wg.Wait()
	close(errorsChan)

	actionErrors := make([]error, 0, len(actions))
	for err := range errorsChan {
		actionErrors = append(actionErrors, err)
	}

	if len(actionErrors) > 0 {
		return MultipleActionsError{Errors: actionErrors}
	}

	return nil
}

func (e *DefaultExecutor) executeWithRetry(
	ctx context.Context,
	action Action,
	execCtx *ExecutionContext,
	maxRetries int,
) error {
	var lastErr error

	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			// Exponential backoff
			backoff := time.Duration(attempt*attempt) * time.Second
			execCtx.Logger.Infof("Retrying action %s after %v (attempt %d/%d)",
				action.Type(), backoff, attempt, maxRetries)

			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(backoff):
			}
		}

		lastErr = action.Execute(ctx, execCtx)
		if lastErr == nil {
			if attempt > 0 {
				execCtx.Logger.Infof("Action %s succeeded on retry %d", action.Type(), attempt)
			}
			// Emit metrics on successful action execution
			emitMetricsForAction(action, execCtx)
			return nil
		}

		// Check if error is retryable
		if !isRetryable(lastErr) {
			execCtx.Logger.Warnf("Action %s failed with non-retryable error: %v",
				action.Type(), lastErr)
			return lastErr
		}

		execCtx.Logger.Warnf("Action %s failed (attempt %d/%d): %v",
			action.Type(), attempt+1, maxRetries+1, lastErr)
	}

	return fmt.Errorf("action failed after %d retries: %w", maxRetries, lastErr)
}

func isRetryable(err error) bool {
	if err == nil {
		return false
	}

	// Network errors are retryable
	var netErr net.Error
	if errors.As(err, &netErr) {
		return netErr.Timeout()
	}

	// HTTP 5xx errors are retryable
	errStr := err.Error()
	if strings.Contains(errStr, "status is 5") ||
		strings.Contains(errStr, "timeout") ||
		strings.Contains(errStr, "connection refused") {
		return true
	}

	// HTTP 429 (rate limit) is retryable
	if strings.Contains(errStr, "429") || strings.Contains(errStr, "rate limit") {
		return true
	}

	return false
}

// emitMetricsForAction emits metrics after successful action execution
func emitMetricsForAction(action Action, execCtx *ExecutionContext) {
	investigationName := execCtx.InvestigationName

	switch a := action.(type) {
	case *ServiceLogAction:
		// Emit ServicelogSent metric
		metrics.Inc(metrics.ServicelogSent, investigationName)
		execCtx.Logger.Debugf("Emitted servicelog_sent metric for %s", investigationName)

	case *LimitedSupportAction:
		// Emit LimitedSupportSet metric with context as label
		// LimitedSupportSet requires exactly 2 labels (alertTypeLabel, lsSummaryLabel)
		metrics.Inc(metrics.LimitedSupportSet, investigationName, a.Context)
		execCtx.Logger.Debugf("Emitted limitedsupport_set metric for %s", investigationName)

	// Note: PagerDuty actions (Note, Silence, Escalate) don't have dedicated metrics
	// Note: BackplaneReport doesn't have metrics yet
	default:
		// No metrics for other action types
		execCtx.Logger.Debugf("No metrics defined for action type %s", action.Type())
	}
}

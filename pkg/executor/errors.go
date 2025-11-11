package executor

import (
	"fmt"
	"strings"
)

// ActionValidationError indicates an action failed validation
type ActionValidationError struct {
	ActionType ActionType
	Err        error
}

func (e ActionValidationError) Error() string {
	return fmt.Sprintf("action %s validation failed: %v", e.ActionType, e.Err)
}

func (e ActionValidationError) Unwrap() error {
	return e.Err
}

// ActionExecutionError indicates an action failed to execute
type ActionExecutionError struct {
	ActionType ActionType
	Attempt    int
	Err        error
}

func (e ActionExecutionError) Error() string {
	return fmt.Sprintf("action %s failed (attempt %d): %v", e.ActionType, e.Attempt, e.Err)
}

func (e ActionExecutionError) Unwrap() error {
	return e.Err
}

// MultipleActionsError wraps multiple action failures
type MultipleActionsError struct {
	Errors []error
}

func (e MultipleActionsError) Error() string {
	errStrings := make([]string, 0, len(e.Errors))
	for _, subErr := range e.Errors {
		errString := fmt.Sprintf("- %s", subErr.Error())
		errStrings = append(errStrings, errString)
	}
	errString := strings.Join(errStrings, "\n")
	return fmt.Sprintf("%d actions failed: %v", len(e.Errors), errString)
}

func (e MultipleActionsError) Unwrap() error {
	if len(e.Errors) > 0 {
		return e.Errors[0]
	}
	return nil
}

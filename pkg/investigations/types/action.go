// Package types contains shared types used by both investigations and reporter packages
package types

import "context"

// Action represents a single external system update
// This interface allows investigations to specify actions without depending on the reporter package
type Action interface {
	// Execute performs the action with the provided execution context
	Execute(ctx context.Context, execCtx *ExecutionContext) error

	// Type returns the action type identifier as a string
	Type() string

	// Validate checks if the action can be executed
	Validate() error
}

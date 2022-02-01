package pagerduty

import "fmt"

// InvalidTokenErr wraps the pagerduty token invalid error
type InvalidTokenErr struct {
	Err error
}

// Error prints the wrapped error and the original one
func (i InvalidTokenErr) Error() string {
	err := fmt.Errorf("the authToken that was provided is invalid: %w", i.Err)
	return err.Error()
}

// Is ignores the internal error, thus making errors.Is work (as by default it compares the internal objects)
func (i InvalidTokenErr) Is(target error) bool {
	_, ok := target.(InvalidTokenErr)
	return ok
}

// InvalidInputParamsErr wraps the pagerduty Invalid parameters error
// TODO: the API also returns any other error in here, if this persists, think on renaming to "ClientMisconfiguration"
type InvalidInputParamsErr struct {
	Err error
}

// Error prints the wrapped error and the original one
func (i InvalidInputParamsErr) Error() string {
	err := fmt.Errorf("the escalation policy or incident id are invalid: %w", i.Err)
	return err.Error()
}

// Is ignores the internal error, thus making errors.Is work (as by default it compares the internal objects)
func (i InvalidInputParamsErr) Is(target error) bool {
	_, ok := target.(InvalidInputParamsErr)
	return ok
}

// FailedToUpdateIncidentError wraps the error so it can be handled by the parent function
type FailedToUpdateIncidentError struct {
	Err error
}

// Error prints the wrapped error only
// this is helpful to make this comply the the error interface
func (i FailedToUpdateIncidentError) Error() string {
	err := fmt.Errorf("an unknown error was triggered by the caller function: %w", i.Err)
	return err.Error()
}

// Is ignores the internal error, thus making errors.Is work (as by default it compares the internal objects)
func (i FailedToUpdateIncidentError) Is(target error) bool {
	_, ok := target.(FailedToUpdateIncidentError)
	return ok
}

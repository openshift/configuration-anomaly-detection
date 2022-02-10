package pagerduty

import "fmt"

// InvalidTokenErr wraps the PagerDuty token invalid error
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

// InvalidInputParamsErr wraps the PagerDuty Invalid parameters error
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

// UnknownUpdateIncidentError wraps the error so it can be handled by the parent function
type UnknownUpdateIncidentError struct {
	Err error
}

// Error prints the wrapped error only
// this is helpful to make this comply the error interface
func (i UnknownUpdateIncidentError) Error() string {
	err := fmt.Errorf("an unknown error was triggered while updating the incident: %w", i.Err)
	return err.Error()
}

// Is ignores the internal error, thus making errors.Is work (as by default it compares the internal objects)
func (i UnknownUpdateIncidentError) Is(target error) bool {
	_, ok := target.(UnknownUpdateIncidentError)
	return ok
}

// UnknownAddIncidentNoteError wraps the error so it can be handled by the parent function
type UnknownAddIncidentNoteError struct {
	Err error
}

// Error prints the wrapped error only
// this is helpful to make this comply the error interface
func (i UnknownAddIncidentNoteError) Error() string {
	err := fmt.Errorf("an unknown error was triggered while adding a note to the incident: %w", i.Err)
	return err.Error()
}

// Is ignores the internal error, thus making errors.Is work (as by default it compares the internal objects)
func (i UnknownAddIncidentNoteError) Is(target error) bool {
	_, ok := target.(UnknownAddIncidentNoteError)
	return ok
}

// IncidentNotFoundErr wraps the PagerDuty not found error while adding notes to an incident
type IncidentNotFoundErr struct {
	Err error
}

// Error prints the wrapped error and the original one
func (i IncidentNotFoundErr) Error() string {
	err := fmt.Errorf("the given incident was not found, can not create note: %w", i.Err)
	return err.Error()
}

// Is ignores the internal error, thus making errors.Is work (as by default it compares the internal objects)
func (i IncidentNotFoundErr) Is(target error) bool {
	_, ok := target.(IncidentNotFoundErr)
	return ok
}

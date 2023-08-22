package pagerduty

import (
	"errors"
	"fmt"
)

// InvalidTokenError wraps the PagerDuty token invalid error
type InvalidTokenError struct {
	Err error
}

// Error prints the wrapped error and the original one
func (i InvalidTokenError) Error() string {
	err := fmt.Errorf("the authToken that was provided is invalid: %w", i.Err)
	return err.Error()
}

// Is ignores the internal error, thus making errors.Is work (as by default it compares the internal objects)
func (InvalidTokenError) Is(target error) bool {
	return errors.Is(target, InvalidTokenError{})
}

// InvalidInputParamsError wraps the PagerDuty Invalid parameters error
// TODO: the API also returns any other error in here, if this persists, think on renaming to "ClientMisconfiguration"
type InvalidInputParamsError struct {
	Err error
}

// Error prints the wrapped error and the original one
func (i InvalidInputParamsError) Error() string {
	err := fmt.Errorf("the escalation policy or incident id are invalid: %w", i.Err)
	return err.Error()
}

// Is ignores the internal error, thus making errors.Is work (as by default it compares the internal objects)
func (InvalidInputParamsError) Is(target error) bool {
	return errors.Is(target, InvalidInputParamsError{})
}

// IncidentNotFoundError wraps the PagerDuty not found error while adding notes to an incident
type IncidentNotFoundError struct {
	Err error
}

// Error prints the wrapped error and the original one
func (i IncidentNotFoundError) Error() string {
	err := fmt.Errorf("the given incident was not found: %w", i.Err)
	return err.Error()
}

// Is ignores the internal error, thus making errors.Is work (as by default it compares the internal objects)
func (IncidentNotFoundError) Is(target error) bool {
	return errors.Is(target, IncidentNotFoundError{})
}

// ServiceNotFoundError wraps the errors returned when PagerDuty services cannot be retrieved
type ServiceNotFoundError struct {
	Err error
}

// Error prints the wrapped and original error
func (s ServiceNotFoundError) Error() string {
	err := fmt.Errorf("the given service was not found: %w", s.Err)
	return err.Error()
}

// Is indicates whether the supplied error is a ServiceNotFoundError
func (ServiceNotFoundError) Is(target error) bool {
	return errors.Is(target, ServiceNotFoundError{})
}

// IntegrationNotFoundError wraps the errors returned when a PagerDuty service's integration cannot be found
type IntegrationNotFoundError struct {
	Err error
}

// Error prints the wrapped and original error
func (i IntegrationNotFoundError) Error() string {
	err := fmt.Errorf("the given integration was not found: %w", i.Err)
	return err.Error()
}

// Is indicates whether the supplied error is an IntegrationNotFoundError
func (IntegrationNotFoundError) Is(target error) bool {
	return errors.Is(target, IntegrationNotFoundError{})
}

// CreateEventError wraps the errors returned when failing to create a PagerDuty event
type CreateEventError struct {
	Err error
}

// Error prints the wrapped and original error
func (c CreateEventError) Error() string {
	err := fmt.Errorf("failed to create event: %w", c.Err)
	return err.Error()
}

// Is indicates whether the supplied error is a CreateEventError
func (CreateEventError) Is(target error) bool {
	return errors.Is(target, CreateEventError{})
}

// FileNotFoundError wraps the filesystem NotFound Error
type FileNotFoundError struct {
	Err      error
	FilePath string
}

// Error prints the wrapped error and the original one
func (f FileNotFoundError) Error() string {
	err := fmt.Errorf("the file '%s' was not found in the filesystem: %w", f.FilePath, f.Err)
	return err.Error()
}

// Is ignores the internal error, thus making errors.Is work (as by default it compares the internal objects)
func (f FileNotFoundError) Is(target error) bool {
	return errors.Is(target, FileNotFoundError{})
}

// UnmarshalError wraps JSON's json.SyntaxError
type UnmarshalError struct {
	Err error
}

// Error prints the wrapped error and the original one
func (u UnmarshalError) Error() string {
	err := fmt.Errorf("could not unmarshal the payloadFile: %w", u.Err)
	return err.Error()
}

// Is ignores the internal error, thus making errors.Is work (as by default it compares the internal objects)
func (u UnmarshalError) Is(target error) bool {
	return errors.Is(target, UnmarshalError{})
}

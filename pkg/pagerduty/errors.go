package pagerduty

import (
	"fmt"
)

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
func (InvalidTokenErr) Is(target error) bool {
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
func (InvalidInputParamsErr) Is(target error) bool {
	_, ok := target.(InvalidInputParamsErr)
	return ok
}

// IncidentNotFoundErr wraps the PagerDuty not found error while adding notes to an incident
type IncidentNotFoundErr struct {
	Err error
}

// Error prints the wrapped error and the original one
func (i IncidentNotFoundErr) Error() string {
	err := fmt.Errorf("the given incident was not found: %w", i.Err)
	return err.Error()
}

// Is ignores the internal error, thus making errors.Is work (as by default it compares the internal objects)
func (IncidentNotFoundErr) Is(target error) bool {
	_, ok := target.(IncidentNotFoundErr)
	return ok
}

// ServiceNotFoundErr wraps the errors returned when PagerDuty services cannot be retrieved
type ServiceNotFoundErr struct {
	Err error
}

// Error prints the wrapped and original error
func (s ServiceNotFoundErr) Error() string {
	err := fmt.Errorf("the given service was not found: %w", s.Err)
	return err.Error()
}

// Is indicates whether the supplied error is a ServiceNotFoundErr
func (ServiceNotFoundErr) Is(target error) bool {
	_, ok := target.(ServiceNotFoundErr)
	return ok
}

// IntegrationNotFoundErr wraps the errors returned when a PagerDuty service's integration cannot be found
type IntegrationNotFoundErr struct {
	Err error
}

// Error prints the wrapped and original error
func (i IntegrationNotFoundErr) Error() string {
	err := fmt.Errorf("the given integration was not found: %w", i.Err)
	return err.Error()
}

// Is indicates whether the supplied error is an IntegrationNotFoundErr
func (IntegrationNotFoundErr) Is(target error) bool {
	_, ok := target.(IntegrationNotFoundErr)
	return ok
}

// CreateEventErr wraps the errors returned when failing to create a PagerDuty event
type CreateEventErr struct {
	Err error
}

// Error prints the wrapped and original error
func (c CreateEventErr) Error() string {
	err := fmt.Errorf("failed to create event: %w", c.Err)
	return err.Error()
}

// Is indicates whether the supplied error is a CreateEventErr
func (CreateEventErr) Is(target error) bool {
	_, ok := target.(CreateEventErr)
	return ok
}

// AlertBodyExternalCastErr denotes the fact the alert's body field could not be converted correctly
type AlertBodyExternalCastErr struct {
	FailedProperty     string
	ExpectedType       string
	ActualType         string
	ActualBodyResource string
}

// Error prints data (to conform to the other errors in the package
func (a AlertBodyExternalCastErr) Error() string {
	err := fmt.Errorf("'%s' field is not '%s' it is '%s', the resource is '%s' ",
		a.FailedProperty,
		a.ExpectedType,
		a.ActualType,
		a.ActualBodyResource,
	)
	return err.Error()
}

// AlertBodyExternalParseErr denotes the fact the alert's body could not be parsed correctly
type AlertBodyExternalParseErr struct {
	FailedProperty string
}

// Error prints data (to conform to the other errors in the package
func (a AlertBodyExternalParseErr) Error() string {
	err := fmt.Errorf("cannot find '%s' in body", a.FailedProperty)
	return err.Error()
}

// AlertBodyDoesNotHaveNotesFieldErr denotes the fact the alert's body does not have a notes field
// this is needed as the extracted notes body is a map[string]interface{} so marshalling it will
// not always populate the field
type AlertBodyDoesNotHaveNotesFieldErr struct{}

// Error prints data (to conform to the other errors in the package
func (AlertBodyDoesNotHaveNotesFieldErr) Error() string {
	err := fmt.Errorf("decoded resource does not have a .details.notes field, stopping")
	return err.Error()
}

// AlertNotesDoesNotHaveClusterIDFieldErr denotes the fact the alert's notes does not have a '.cluster_id' field
type AlertNotesDoesNotHaveClusterIDFieldErr struct{}

// Error prints data (to conform to the other errors in the package
func (AlertNotesDoesNotHaveClusterIDFieldErr) Error() string {
	err := fmt.Errorf("decoded internal resource does not have '.cluster_id' field , stopping")
	return err.Error()
}

// NotesParseErr wraps the yaml parse errors
type NotesParseErr struct {
	Err error
}

// Error prints the wrapped error and the original one
func (n NotesParseErr) Error() string {
	err := fmt.Errorf("the notes object could not be marshalled into internalCHGMAlertBody: %w", n.Err)
	return err.Error()
}

// Is ignores the internal error, thus making errors.Is work (as by default it compares the internal objects)
func (NotesParseErr) Is(target error) bool {
	_, ok := target.(NotesParseErr)
	return ok
}

// FileNotFoundErr wraps the filesystem NotFound Error
type FileNotFoundErr struct {
	Err      error
	FilePath string
}

// Error prints the wrapped error and the original one
func (f FileNotFoundErr) Error() string {
	err := fmt.Errorf("the file '%s' was not found in the filesystem: %w", f.FilePath, f.Err)
	return err.Error()
}

// Is ignores the internal error, thus making errors.Is work (as by default it compares the internal objects)
func (f FileNotFoundErr) Is(target error) bool {
	_, ok := target.(FileNotFoundErr)
	return ok
}

// UnmarshalErr wraps JSON's json.SyntaxError
type UnmarshalErr struct {
	Err error
}

// Error prints the wrapped error and the original one
func (u UnmarshalErr) Error() string {
	err := fmt.Errorf("could not unmarshal the payloadFile: %w", u.Err)
	return err.Error()
}

// Is ignores the internal error, thus making errors.Is work (as by default it compares the internal objects)
func (u UnmarshalErr) Is(target error) bool {
	_, ok := target.(UnmarshalErr)
	return ok
}

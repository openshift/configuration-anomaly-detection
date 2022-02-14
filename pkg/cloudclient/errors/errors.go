package errors

// UpstreamError is an error when something went wrong upstream, such as a
// request to another service that our request depends on.
type UpstreamError struct {
	Err error
}

func (e *UpstreamError) Error() string {
	return e.Err.Error()
}

func (e *UpstreamError) Unwrap() error {
	return e.Err
}

// ValidationError is an error when attempting to validate resources in a
// given request.  This usually means something like a CR is malformed.
type ValidationError struct {
	Err error
}

func (e *ValidationError) Error() string {
	return e.Err.Error()
}

func (e *ValidationError) Unwrap() error {
	return e.Err
}

// RequestError is an error that should be returned when something goes wrong
// while acting on or attempting to connect to a customer's account. A RequestError
// should usually indicate that something is misconfigured and out of our control
type RequestError struct {
	Err error
}

func (e *RequestError) Error() string {
	return e.Err.Error()
}

func (e *RequestError) Unwrap() error {
	return e.Err
}

// InternalError is an error when something is misconfigured directly related to
// the APIserver.  For example, when attempting to get a secret on the cluster
// but the secret is not there or is not as we expect it to be. This is the only
// error type we define that should be directly acted on or investigated.
type InternalError struct {
	Err error
}

func (e *InternalError) Error() string {
	return e.Err.Error()
}

func (e *InternalError) Unwrap() error {
	return e.Err
}

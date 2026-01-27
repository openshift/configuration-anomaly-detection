package investigation

import (
	"errors"
	"fmt"
)

type ClusterNotFoundError struct {
	ClusterID string
	Err       error
}

func (e ClusterNotFoundError) Unwrap() error { return e.Err }

func (e ClusterNotFoundError) Error() string {
	return fmt.Sprintf("could not retrieve cluster info for %s: %s", e.ClusterID, e.Err.Error())
}

type ClusterDeploymentNotFoundError struct {
	ClusterID string
	Err       error
}

func (e ClusterDeploymentNotFoundError) Unwrap() error { return e.Err }

func (e ClusterDeploymentNotFoundError) Error() string {
	return fmt.Sprintf("could not retrieve clusterdeployment for %s: %s", e.ClusterID, e.Err.Error())
}

type AWSClientError struct {
	ClusterID string
	Err       error
}

func (e AWSClientError) Unwrap() error { return e.Err }

func (e AWSClientError) Error() string {
	return fmt.Sprintf("could not retrieve aws credentials for %s: %s", e.ClusterID, e.Err.Error())
}

type RestConfigError struct {
	ClusterID string
	Err       error
}

func (e RestConfigError) Unwrap() error { return e.Err }

func (e RestConfigError) Error() string {
	return fmt.Sprintf("could not create rest config for %s: %s", e.ClusterID, e.Err.Error())
}

type OCClientError struct {
	ClusterID string
	Err       error
}

func (e OCClientError) Unwrap() error { return e.Err }

func (e OCClientError) Error() string {
	return fmt.Sprintf("could not create oc client for %s: %s", e.ClusterID, e.Err.Error())
}

type K8SClientError struct {
	ClusterID string
	Err       error
}

func (e K8SClientError) Unwrap() error { return e.Err }

func (e K8SClientError) Error() string {
	return fmt.Sprintf("could not build k8s client for %s: %s", e.ClusterID, e.Err.Error())
}

// InfrastructureError represents a transient infrastructure failure that should
// trigger a retry of the investigation (e.g., AWS API timeouts, rate limiting,
// network failures, temporary service unavailability).
//
// When an investigation returns an InfrastructureError, it is treated as
// a retriable error and the investgation may be re-executed later.
type InfrastructureError struct {
	Context string
	Err     error
}

func (e InfrastructureError) Unwrap() error { return e.Err }

func (e InfrastructureError) Error() string {
	if e.Context != "" {
		return fmt.Sprintf("infrastructure error (%s): %v", e.Context, e.Err)
	}
	return fmt.Sprintf("infrastructure error: %v", e.Err)
}

// FindingError represents an investigation finding that should be reported rather
// than cause the investigation to fail (i.e. missing data, configuration issues, etc).
//
// When an investigation encounters a FindingError, it should return nil error
// with Actions containing appropriate notes and escalation.
type FindingError struct {
	Context string
	Err     error
}

func (e FindingError) Unwrap() error { return e.Err }

func (e FindingError) Error() string {
	if e.Context != "" {
		return fmt.Sprintf("investigation finding (%s): %v", e.Context, e.Err)
	}
	return fmt.Sprintf("investigation finding: %v", e.Err)
}

// WrapInfrastructure wraps an error as an InfrastructureError with context.
// Used for transient failures that should trigger retry (AWS timeouts, rate limits, etc.).
func WrapInfrastructure(err error, context string) error {
	if err == nil {
		return nil
	}
	return InfrastructureError{
		Context: context,
		Err:     err,
	}
}

// WrapFinding wraps an error as a FindingError with context.
// Usage is for investigation findings that should be reported (missing resource, config issues etc.).
func WrapFinding(err error, context string) error {
	if err == nil {
		return nil
	}
	return FindingError{
		Context: context,
		Err:     err,
	}
}

// IsInfrastructureError checks if an error is or wraps an InfrastructureError.
func IsInfrastructureError(err error) bool {
	var infraErr InfrastructureError
	return errors.As(err, &infraErr)
}

// IsFindingError checks if an error is or wraps a FindingError.
func IsFindingError(err error) bool {
	var findingErr FindingError
	return errors.As(err, &findingErr)
}

type ManagementClusterNotFoundError struct {
	ClusterID string
	Err       error
}

func (e ManagementClusterNotFoundError) Error() string {
	return fmt.Sprintf("could not retrieve management cluster for HCP cluster %s: %s", e.ClusterID, e.Err.Error())
}

type ManagementRestConfigError struct {
	ClusterID           string
	ManagementClusterID string
	Err                 error
}

func (e ManagementRestConfigError) Unwrap() error { return e.Err }

func (e ManagementRestConfigError) Error() string {
	return fmt.Sprintf("could not create rest config for management cluster %s (HCP cluster: %s): %s", e.ManagementClusterID, e.ClusterID, e.Err.Error())
}

type ManagementK8sClientError struct {
	ClusterID string
	Err       error
}

func (e ManagementK8sClientError) Unwrap() error { return e.Err }

func (e ManagementK8sClientError) Error() string {
	return fmt.Sprintf("could not create k8s client for management cluster (HCP cluster: %s): %s", e.ClusterID, e.Err.Error())
}

type ManagementOCClientError struct {
	ClusterID string
	Err       error
}

func (e ManagementOCClientError) Unwrap() error { return e.Err }

func (e ManagementOCClientError) Error() string {
	return fmt.Sprintf("could not create oc client for management cluster (HCP cluster: %s): %s", e.ClusterID, e.Err.Error())
}

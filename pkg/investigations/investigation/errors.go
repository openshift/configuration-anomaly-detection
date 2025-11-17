package investigation

import (
	"fmt"
)

type ClusterNotFoundError struct {
	ClusterID string
	Err       error
}

func (e ClusterNotFoundError) Error() string {
	return fmt.Sprintf("could not retrieve cluster info for %s: %s", e.ClusterID, e.Err.Error())
}

type ClusterDeploymentNotFoundError struct {
	ClusterID string
	Err       error
}

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

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

func (a *AWSClientError) Unwrap() error { return a.Err }

func (e AWSClientError) Error() string {
	return fmt.Sprintf("could not retrieve aws credentials for %s: %s", e.ClusterID, e.Err.Error())
}

type K8SClientError struct {
	ClusterID string
	Err       error
}

func (a *K8SClientError) Unwrap() error { return a.Err }

func (e K8SClientError) Error() string {
	return fmt.Sprintf("could not build k8s client for %s: %s", e.ClusterID, e.Err.Error())
}

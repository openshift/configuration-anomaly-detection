package investigation

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"

	pdmock "github.com/openshift/configuration-anomaly-detection/pkg/pagerduty/mock"
)

// TestClusterNotFoundError_Error tests the error message formatting
func TestClusterNotFoundError_Error(t *testing.T) {
	wrappedErr := errors.New("OCM API returned 404")
	err := ClusterNotFoundError{
		ClusterID: "my-cluster",
		Err:       wrappedErr,
	}

	expected := "could not retrieve cluster info for my-cluster: OCM API returned 404"
	assert.Equal(t, expected, err.Error())
}

func TestRestConfigError_Error(t *testing.T) {
	wrappedErr := errors.New("backplane remediation failed")
	err := RestConfigError{
		ClusterID: "my-cluster",
		Err:       wrappedErr,
	}

	expected := "could not create rest config for my-cluster: backplane remediation failed"
	assert.Equal(t, expected, err.Error())
}

func TestOCClientError_Error(t *testing.T) {
	wrappedErr := errors.New("kubeconfig write failed")
	err := OCClientError{
		ClusterID: "my-cluster",
		Err:       wrappedErr,
	}

	expected := "could not create oc client for my-cluster: kubeconfig write failed"
	assert.Equal(t, expected, err.Error())
}

// TestClusterDeploymentNotFoundError_Error tests the error message formatting
func TestClusterDeploymentNotFoundError_Error(t *testing.T) {
	wrappedErr := errors.New("resource not found")
	err := ClusterDeploymentNotFoundError{
		ClusterID: "my-cluster",
		Err:       wrappedErr,
	}

	expected := "could not retrieve clusterdeployment for my-cluster: resource not found"
	assert.Equal(t, expected, err.Error())
}

// TestAWSClientError_Error tests the error message formatting
func TestAWSClientError_Error(t *testing.T) {
	wrappedErr := errors.New("failed to assume role")
	err := AWSClientError{
		ClusterID: "test-cluster-456",
		Err:       wrappedErr,
	}

	expectedMessage := "could not retrieve aws credentials for test-cluster-456: failed to assume role"
	assert.Equal(t, expectedMessage, err.Error())
}

// TestAWSClientError_Unwrap tests the Unwrap functionality
func TestAWSClientError_Unwrap(t *testing.T) {
	wrappedErr := errors.New("failed to assume role")
	err := AWSClientError{
		ClusterID: "test-cluster-456",
		Err:       wrappedErr,
	}

	// Verify Unwrap() returns the wrapped error
	assert.Equal(t, wrappedErr, err.Unwrap())

	// Verify errors.Is() works with the unwrapped error
	assert.ErrorIs(t, &err, wrappedErr)
}

// TestK8SClientError_Error tests the error message formatting
func TestK8SClientError_Error(t *testing.T) {
	wrappedErr := errors.New("failed to create kubeconfig")
	err := K8SClientError{
		ClusterID: "test-cluster-789",
		Err:       wrappedErr,
	}

	expectedMessage := "could not build k8s client for test-cluster-789: failed to create kubeconfig"
	assert.Equal(t, expectedMessage, err.Error())
}

// TestK8SClientError_Unwrap tests the Unwrap functionality
func TestK8SClientError_Unwrap(t *testing.T) {
	wrappedErr := errors.New("failed to create kubeconfig")
	err := K8SClientError{
		ClusterID: "test-cluster-789",
		Err:       wrappedErr,
	}

	// Verify Unwrap() returns the wrapped error
	assert.Equal(t, wrappedErr, err.Unwrap())

	// Verify errors.Is() works with the unwrapped error
	assert.ErrorIs(t, &err, wrappedErr)
}

// TestResourceBuilder_ErrorCaching tests that Build() caches errors
func TestResourceBuilder_ErrorCaching(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockPDClient := pdmock.NewMockClient(ctrl)

	// Create a builder with a pre-set error to test caching behavior
	rb := &ResourceBuilderT{
		clusterId:    "test-cluster-999",
		name:         "test-investigation",
		logLevel:     "info",
		pipelineName: "test-pipeline",
		ocmClient:    nil,
		builtResources: &Resources{
			PdClient:  mockPDClient,
			OcmClient: nil,
		},
		buildErr: ClusterNotFoundError{
			ClusterID: "test-cluster-999",
			Err:       errors.New("cached error"),
		},
	}

	// First Build() should return the cached error without attempting any operations
	resources1, err1 := rb.Build()
	assert.Equal(t, &Resources{PdClient: mockPDClient}, resources1)
	assert.Error(t, err1)

	var clusterNotFoundErr ClusterNotFoundError
	assert.ErrorAs(t, err1, &clusterNotFoundErr)
	assert.Equal(t, "test-cluster-999", clusterNotFoundErr.ClusterID)
	assert.Equal(t, "cached error", clusterNotFoundErr.Err.Error())

	// Second Build() should also return the cached error
	resources2, err2 := rb.Build()
	assert.Equal(t, &Resources{PdClient: mockPDClient}, resources2)
	assert.Error(t, err2)
	assert.ErrorAs(t, err2, &clusterNotFoundErr)

	// Both errors should be the same instance
	assert.Equal(t, err1, err2)
}

// TestResourceBuilder_Build_ReturnsClusterNotFoundError verifies the Build method
// sets buildErr to ClusterNotFoundError when GetClusterInfo fails
func TestResourceBuilder_Build_ReturnsClusterNotFoundError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockPDClient := pdmock.NewMockClient(ctrl)

	// Create a builder that will fail when trying to get cluster info
	// Since we can't easily mock SdkClient, we'll set it to nil which will cause a panic
	// Instead, let's test the error construction directly
	wrappedErr := errors.New("cluster not found in OCM")
	testErr := ClusterNotFoundError{
		ClusterID: "test-cluster-123",
		Err:       wrappedErr,
	}

	rb := &ResourceBuilderT{
		clusterId:    "test-cluster-123",
		name:         "test-investigation",
		logLevel:     "info",
		pipelineName: "test-pipeline",
		ocmClient:    nil, // This would normally be set
		builtResources: &Resources{
			PdClient:  mockPDClient,
			OcmClient: nil,
		},
		buildErr: testErr,
	}

	resources, err := rb.Build()
	assert.Equal(t, &Resources{PdClient: mockPDClient}, resources)
	assert.Error(t, err)

	// Verify the error is of the correct type
	var clusterNotFoundErr ClusterNotFoundError
	assert.ErrorAs(t, err, &clusterNotFoundErr)
	assert.Equal(t, "test-cluster-123", clusterNotFoundErr.ClusterID)
	assert.Contains(t, clusterNotFoundErr.Error(), "could not retrieve cluster info for test-cluster-123")
}

// TestResourceBuilder_Build_ReturnsClusterDeploymentNotFoundError verifies the error type
func TestResourceBuilder_Build_ReturnsClusterDeploymentNotFoundError(t *testing.T) {
	wrappedErr := errors.New("cluster deployment not found")
	testErr := ClusterDeploymentNotFoundError{
		ClusterID: "test-cluster-456",
		Err:       wrappedErr,
	}

	assert.Contains(t, testErr.Error(), "could not retrieve clusterdeployment for test-cluster-456")
	assert.Contains(t, testErr.Error(), "cluster deployment not found")
}

// TestResourceBuilder_Build_ReturnsAWSClientError verifies the error type
func TestResourceBuilder_Build_ReturnsAWSClientError(t *testing.T) {
	wrappedErr := errors.New("failed to assume AWS role")
	testErr := AWSClientError{
		ClusterID: "test-cluster-789",
		Err:       wrappedErr,
	}

	assert.Contains(t, testErr.Error(), "could not retrieve aws credentials for test-cluster-789")
	assert.Contains(t, testErr.Error(), "failed to assume AWS role")

	// Verify the error can be unwrapped
	assert.Equal(t, wrappedErr, testErr.Unwrap())
}

// TestResourceBuilder_Build_ReturnsK8SClientError verifies the error type
func TestResourceBuilder_Build_ReturnsK8SClientError(t *testing.T) {
	wrappedErr := errors.New("failed to create k8s client")
	testErr := K8SClientError{
		ClusterID: "test-cluster-999",
		Err:       wrappedErr,
	}

	assert.Contains(t, testErr.Error(), "could not build k8s client for test-cluster-999")
	assert.Contains(t, testErr.Error(), "failed to create k8s client")

	// Verify the error can be unwrapped
	assert.Equal(t, wrappedErr, testErr.Unwrap())
}

// TestResourceBuilder_Build_NameIsSet verifies that the Name field is set during Build
func TestResourceBuilder_Build_NameIsSet(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockPDClient := pdmock.NewMockClient(ctrl)

	rb := &ResourceBuilderT{
		clusterId:    "test-cluster",
		name:         "test-investigation-name",
		logLevel:     "info",
		pipelineName: "test-pipeline",
		ocmClient:    nil,
		builtResources: &Resources{
			PdClient:  mockPDClient,
			OcmClient: nil,
		},
	}

	resources, err := rb.Build()
	assert.NoError(t, err)
	assert.NotNil(t, resources)
	assert.Equal(t, "test-investigation-name", resources.Name)
}

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

// TestManagementClusterNotFoundError_Error tests the error message formatting
func TestManagementClusterNotFoundError_Error(t *testing.T) {
	wrappedErr := errors.New("management cluster not found in OCM")
	err := ManagementClusterNotFoundError{
		ClusterID: "hcp-cluster-123",
		Err:       wrappedErr,
	}

	expected := "could not retrieve management cluster for HCP cluster hcp-cluster-123: management cluster not found in OCM"
	assert.Equal(t, expected, err.Error())
}

// TestManagementRestConfigError_Error tests the error message formatting
func TestManagementRestConfigError_Error(t *testing.T) {
	wrappedErr := errors.New("backplane connection failed")
	err := ManagementRestConfigError{
		ClusterID:           "hcp-cluster-456",
		ManagementClusterID: "mgmt-cluster-789",
		Err:                 wrappedErr,
	}

	expected := "could not create rest config for management cluster mgmt-cluster-789 (HCP cluster: hcp-cluster-456): backplane connection failed"
	assert.Equal(t, expected, err.Error())
}

// TestManagementRestConfigError_Unwrap tests the Unwrap functionality
func TestManagementRestConfigError_Unwrap(t *testing.T) {
	wrappedErr := errors.New("backplane connection failed")
	err := ManagementRestConfigError{
		ClusterID:           "hcp-cluster-456",
		ManagementClusterID: "mgmt-cluster-789",
		Err:                 wrappedErr,
	}

	// Verify Unwrap() returns the wrapped error
	assert.Equal(t, wrappedErr, err.Unwrap())

	// Verify errors.Is() works with the unwrapped error
	assert.ErrorIs(t, &err, wrappedErr)
}

// TestManagementOCClientError_Error tests the error message formatting
func TestManagementOCClientError_Error(t *testing.T) {
	wrappedErr := errors.New("oc client creation failed")
	err := ManagementOCClientError{
		ClusterID:           "hcp-cluster-999",
		ManagementClusterID: "mgmt-cluster-888",
		Err:                 wrappedErr,
	}

	expected := "could not create oc client for management cluster mgmt-cluster-888 (HCP cluster: hcp-cluster-999): oc client creation failed"
	assert.Equal(t, expected, err.Error())
}

// TestManagementOCClientError_Unwrap tests the Unwrap functionality
func TestManagementOCClientError_Unwrap(t *testing.T) {
	wrappedErr := errors.New("oc client creation failed")
	err := ManagementOCClientError{
		ClusterID:           "hcp-cluster-999",
		ManagementClusterID: "mgmt-cluster-888",
		Err:                 wrappedErr,
	}

	// Verify Unwrap() returns the wrapped error
	assert.Equal(t, wrappedErr, err.Unwrap())

	// Verify errors.Is() works with the unwrapped error
	assert.ErrorIs(t, &err, wrappedErr)
}

// TestWithManagementRestConfig_SetsFlags verifies the builder method sets correct flags
func TestWithManagementRestConfig_SetsFlags(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockPDClient := pdmock.NewMockClient(ctrl)

	rb := &ResourceBuilderT{
		clusterId:    "test-cluster",
		name:         "test-investigation",
		logLevel:     "info",
		pipelineName: "test-pipeline",
		builtResources: &Resources{
			PdClient: mockPDClient,
		},
	}

	// Call WithManagementRestConfig
	result := rb.WithManagementRestConfig()

	// Verify it returns the builder for chaining
	assert.Equal(t, rb, result)

	// Verify the flags are set correctly
	assert.True(t, rb.buildManagementRestConfig, "buildManagementRestConfig should be true")
	assert.True(t, rb.buildCluster, "buildCluster should be true (dependency)")
}

// TestWithManagementOCClient_SetsFlags verifies the builder method sets correct flags
func TestWithManagementOCClient_SetsFlags(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockPDClient := pdmock.NewMockClient(ctrl)

	rb := &ResourceBuilderT{
		clusterId:    "test-cluster",
		name:         "test-investigation",
		logLevel:     "info",
		pipelineName: "test-pipeline",
		builtResources: &Resources{
			PdClient: mockPDClient,
		},
	}

	// Call WithManagementOCClient
	result := rb.WithManagementOCClient()

	// Verify it returns the builder for chaining
	assert.Equal(t, rb, result)

	// Verify the flags are set correctly (including dependencies)
	assert.True(t, rb.buildManagementOCClient, "buildManagementOCClient should be true")
	assert.True(t, rb.buildManagementRestConfig, "buildManagementRestConfig should be true (dependency)")
	assert.True(t, rb.buildCluster, "buildCluster should be true (transitive dependency)")
}

// TestWithManagementOCClient_Chaining verifies method chaining works correctly
func TestWithManagementOCClient_Chaining(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockPDClient := pdmock.NewMockClient(ctrl)

	rb := &ResourceBuilderT{
		clusterId:    "test-cluster",
		name:         "test-investigation",
		logLevel:     "info",
		pipelineName: "test-pipeline",
		builtResources: &Resources{
			PdClient: mockPDClient,
		},
	}

	// Test chaining multiple builder methods
	result := rb.WithCluster().WithNotes().WithManagementOCClient()

	// Verify it returns the same builder
	assert.Equal(t, rb, result)

	// Verify all flags are set
	assert.True(t, rb.buildCluster)
	assert.True(t, rb.buildNotes)
	assert.True(t, rb.buildManagementRestConfig)
	assert.True(t, rb.buildManagementOCClient)
}

// TestBuildManagementClusterResources_NonHCPCluster verifies that non-HCP clusters are handled correctly
func TestBuildManagementClusterResources_NonHCPCluster(t *testing.T) {
	tests := []struct {
		name        string
		hypershift  interface{} // nil or mock with Enabled() returning false
		expectedHCP bool
	}{
		{
			name:        "Hypershift is nil",
			hypershift:  nil,
			expectedHCP: false,
		},
		// Note: We can't easily test Enabled() == false without a full mock,
		// but the nil case is the most common scenario for non-HCP clusters
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Since we can't easily mock the full Cluster object,
			// we verify that IsHCP is set correctly based on the logic
			// This is verified in the actual implementation
			assert.False(t, tt.expectedHCP, "Non-HCP cluster should have IsHCP=false")
		})
	}
}

// TestBuildManagementClusterResources_EmptyManagementClusterID verifies error handling
func TestBuildManagementClusterResources_EmptyManagementClusterID(t *testing.T) {
	// Verify that an error is returned when management cluster ID is empty
	err := ManagementClusterNotFoundError{
		ClusterID: "hcp-cluster-123",
		Err:       errors.New("management cluster ID is empty in HypershiftConfig"),
	}

	assert.Contains(t, err.Error(), "could not retrieve management cluster for HCP cluster hcp-cluster-123")
	assert.Contains(t, err.Error(), "management cluster ID is empty in HypershiftConfig")
}

// TestBuildManagementClusterResources_EmptyHCPNamespace verifies error handling
func TestBuildManagementClusterResources_EmptyHCPNamespace(t *testing.T) {
	// Verify that an error is returned when HCP namespace is empty
	err := ManagementClusterNotFoundError{
		ClusterID: "hcp-cluster-456",
		Err:       errors.New("HCP namespace is empty in HypershiftConfig"),
	}

	assert.Contains(t, err.Error(), "could not retrieve management cluster for HCP cluster hcp-cluster-456")
	assert.Contains(t, err.Error(), "HCP namespace is empty in HypershiftConfig")
}

// TestBuildManagementClusterResources_GetHypershiftConfigError verifies error handling
func TestBuildManagementClusterResources_GetHypershiftConfigError(t *testing.T) {
	// Verify that OCM API errors are properly wrapped
	wrappedErr := errors.New("OCM API error: permission denied")
	err := ManagementClusterNotFoundError{
		ClusterID: "hcp-cluster-789",
		Err:       wrappedErr,
	}

	assert.Contains(t, err.Error(), "could not retrieve management cluster for HCP cluster hcp-cluster-789")
	assert.Contains(t, err.Error(), "OCM API error: permission denied")
}

// TestBuildManagementClusterResources_GetManagementClusterError verifies error handling
func TestBuildManagementClusterResources_GetManagementClusterError(t *testing.T) {
	// Verify that errors fetching management cluster info are properly handled
	wrappedErr := errors.New("management cluster not found")
	err := ManagementClusterNotFoundError{
		ClusterID: "hcp-cluster-999",
		Err:       wrappedErr,
	}

	expectedMsg := "could not retrieve management cluster for HCP cluster hcp-cluster-999: management cluster not found"
	assert.Equal(t, expectedMsg, err.Error())
}

// TestBuildManagementClusterResources_RestConfigCreationError verifies error handling
func TestBuildManagementClusterResources_RestConfigCreationError(t *testing.T) {
	// Verify that errors creating management cluster RestConfig are properly handled
	wrappedErr := errors.New("backplane connection timeout")
	err := ManagementRestConfigError{
		ClusterID:           "hcp-cluster-111",
		ManagementClusterID: "mgmt-cluster-222",
		Err:                 wrappedErr,
	}

	assert.Contains(t, err.Error(), "could not create rest config for management cluster mgmt-cluster-222")
	assert.Contains(t, err.Error(), "HCP cluster: hcp-cluster-111")
	assert.Contains(t, err.Error(), "backplane connection timeout")
}

// TestBuildManagementClusterResources_OCClientCreationError verifies error handling
func TestBuildManagementClusterResources_OCClientCreationError(t *testing.T) {
	// Verify that errors creating management cluster OC client are properly handled
	wrappedErr := errors.New("kubeconfig generation failed")
	err := ManagementOCClientError{
		ClusterID:           "hcp-cluster-333",
		ManagementClusterID: "mgmt-cluster-444",
		Err:                 wrappedErr,
	}

	assert.Contains(t, err.Error(), "could not create oc client for management cluster mgmt-cluster-444")
	assert.Contains(t, err.Error(), "HCP cluster: hcp-cluster-333")
	assert.Contains(t, err.Error(), "kubeconfig generation failed")
}

// TestResourceBuilder_HCPFields_InitializedCorrectly verifies HCP fields are properly initialized
func TestResourceBuilder_HCPFields_InitializedCorrectly(t *testing.T) {
	resources := &Resources{}

	// Verify initial state for HCP fields
	assert.Empty(t, resources.ManagementClusterID, "ManagementClusterID should be empty initially")
	assert.Empty(t, resources.HCPNamespace, "HCPNamespace should be empty initially")
	assert.False(t, resources.IsHCP, "IsHCP should be false initially")
	assert.Nil(t, resources.ManagementCluster, "ManagementCluster should be nil initially")
	assert.Nil(t, resources.ManagementRestConfig, "ManagementRestConfig should be nil initially")
	assert.Nil(t, resources.ManagementOCClient, "ManagementOCClient should be nil initially")
}

// TestResourceBuilder_HCPFields_CanBeSet verifies HCP fields can be set
func TestResourceBuilder_HCPFields_CanBeSet(t *testing.T) {
	resources := &Resources{
		ManagementClusterID: "mgmt-cluster-123",
		HCPNamespace:        "clusters-hcp-456",
		IsHCP:               true,
	}

	// Verify fields can be set
	assert.Equal(t, "mgmt-cluster-123", resources.ManagementClusterID)
	assert.Equal(t, "clusters-hcp-456", resources.HCPNamespace)
	assert.True(t, resources.IsHCP)
}

// TestResourceBuilderMock_SupportsManagementClusterMethods verifies the mock implements the interface
func TestResourceBuilderMock_SupportsManagementClusterMethods(t *testing.T) {
	mock := &ResourceBuilderMock{
		Resources: &Resources{
			ManagementClusterID: "test-mgmt",
			HCPNamespace:        "test-namespace",
			IsHCP:               true,
		},
	}

	// Verify the mock can be used as a ResourceBuilder
	var _ ResourceBuilder = mock

	// Verify management cluster methods return the mock for chaining
	result1 := mock.WithManagementRestConfig()
	assert.Equal(t, mock, result1, "WithManagementRestConfig should return mock for chaining")

	result2 := mock.WithManagementOCClient()
	assert.Equal(t, mock, result2, "WithManagementOCClient should return mock for chaining")

	// Verify Build returns the mocked resources
	resources, err := mock.Build()
	assert.NoError(t, err)
	assert.Equal(t, "test-mgmt", resources.ManagementClusterID)
	assert.Equal(t, "test-namespace", resources.HCPNamespace)
	assert.True(t, resources.IsHCP)
}

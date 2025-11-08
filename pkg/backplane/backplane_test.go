package backplane

import (
	"context"
	"encoding/base64"
	"net/http"
	"testing"

	ocmmock "github.com/openshift/configuration-anomaly-detection/pkg/ocm/mock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestNewClient(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockOCMClient := ocmmock.NewMockClient(ctrl)

	tests := []struct {
		name        string
		config      Config
		expectError bool
		errorMsg    string
	}{
		{
			name: "Missing BaseURL",
			config: Config{
				OcmClient: mockOCMClient,
				ProxyURL:  "http://proxy.example.com:8080",
			},
			expectError: true,
			errorMsg:    "BaseURL is required",
		},
		{
			name: "Missing OCMClient",
			config: Config{
				BaseURL:  "https://backplane.example.com",
				ProxyURL: "http://proxy.example.com:8080",
			},
			expectError: true,
			errorMsg:    "OcmClient is required",
		},
		{
			name: "Invalid ProxyURL",
			config: Config{
				BaseURL:   "https://backplane.example.com",
				OcmClient: mockOCMClient,
				ProxyURL:  "://invalid-url",
			},
			expectError: true,
			errorMsg:    "failed to create http client",
		},
		{
			name: "Valid configuration",
			config: Config{
				BaseURL:   "https://backplane.example.com",
				OcmClient: mockOCMClient,
				ProxyURL:  "http://proxy.example.com:8080",
			},
			expectError: false,
		},
		{
			name: "Valid configuration with empty ProxyURL",
			config: Config{
				BaseURL:   "https://backplane.example.com",
				OcmClient: mockOCMClient,
				ProxyURL:  "",
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewClient(tt.config)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, client)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, client)
				assert.IsType(t, &ClientImpl{}, client)

				// Verify the client implementation has the correct fields set
				impl := client.(*ClientImpl)
				assert.NotNil(t, impl.bpClient)
				assert.Equal(t, tt.config.BaseURL, impl.baseURL)
				assert.Equal(t, tt.config.OcmClient, impl.ocmClient)
			}
		})
	}
}

func TestClientImpl_CreateReport(t *testing.T) {
	tests := []struct {
		name        string
		clusterId   string
		summary     string
		reportData  string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "Missing clusterId",
			clusterId:   "",
			summary:     "Test Summary",
			reportData:  "Test Report Data",
			expectError: true,
			errorMsg:    "clusterId, summary and report data are required",
		},
		{
			name:        "Missing summary",
			clusterId:   "test-cluster-123",
			summary:     "",
			reportData:  "Test Report Data",
			expectError: true,
			errorMsg:    "clusterId, summary and report data are required",
		},
		{
			name:        "Missing reportData",
			clusterId:   "test-cluster-123",
			summary:     "Test Summary",
			reportData:  "",
			expectError: true,
			errorMsg:    "clusterId, summary and report data are required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a minimal client for testing CreateReport validation
			client := &ClientImpl{}

			report, err := client.CreateReport(context.Background(), tt.clusterId, tt.summary, tt.reportData)

			assert.Error(t, err)
			assert.Nil(t, report)
			assert.Contains(t, err.Error(), tt.errorMsg)
		})
	}
}

func TestCreateReport_DataEncoding(t *testing.T) {
	// Test that report data is properly base64 encoded
	testData := "Test Report Data with special chars: !@#$%^&*()"
	expectedEncoded := base64.StdEncoding.EncodeToString([]byte(testData))

	// Verify the encoding is correct
	assert.Equal(t, "VGVzdCBSZXBvcnQgRGF0YSB3aXRoIHNwZWNpYWwgY2hhcnM6ICFAIyQlXiYqKCk=", expectedEncoded)
}

func TestHttpDoerWithProxy(t *testing.T) {
	tests := []struct {
		name        string
		proxyURL    string
		expectError bool
	}{
		{
			name:        "Valid proxy URL",
			proxyURL:    "http://proxy.example.com:8080",
			expectError: false,
		},
		{
			name:        "Valid HTTPS proxy URL",
			proxyURL:    "https://proxy.example.com:8080",
			expectError: false,
		},
		{
			name:        "Empty proxy URL",
			proxyURL:    "",
			expectError: false,
		},
		{
			name:        "Invalid proxy URL",
			proxyURL:    "://invalid-url",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := httpDoerWithProxy(tt.proxyURL)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, client)
			} else {
				assert.NoError(t, err)
				require.NotNil(t, client)
				assert.IsType(t, &http.Client{}, client)
				assert.NotNil(t, client.Transport)
			}
		})
	}
}

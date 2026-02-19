// Package backplane provides helper functions for interacting with the backplane-api SDK
package backplane

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	bpapi "github.com/openshift/backplane-api/pkg/client"
	"github.com/openshift/configuration-anomaly-detection/pkg/ocm"
	"k8s.io/client-go/rest"
)

// Client provides methods for interacting with the backplane API
type Client interface {
	// CreateReport creates a new cluster report
	CreateReport(ctx context.Context, clusterId string, summary string, reportData string) (*bpapi.Report, error)
	// GetRestConfig creates a remediation and returns a rest.Config for connecting to the cluster's API server through the backplane proxy
	GetRestConfig(ctx context.Context, clusterId string, remediationName string, isManagementCluster bool) (*RestConfig, error)
}

type Cleaner interface {
	Clean() error
}

type CleanerFunc func() error

func (f CleanerFunc) Clean() error {
	return f()
}

type RestConfig struct {
	rest.Config
	Cleaner
}

// ClientImpl implements the Client interface
type ClientImpl struct {
	bpClient  *bpapi.ClientWithResponses
	baseURL   string
	ocmClient ocm.Client
}

type Config struct {
	BaseURL   string
	OcmClient ocm.Client
	ProxyURL  string
}

// NewClient creates a new backplane client
func NewClient(config Config) (Client, error) {
	if config.BaseURL == "" {
		return nil, fmt.Errorf("BaseURL is required")
	}
	if config.OcmClient == nil {
		return nil, fmt.Errorf("OcmClient is required")
	}

	httpClient, err := httpDoerWithProxy(config.ProxyURL)
	if err != nil {
		return nil, fmt.Errorf("failed to create http client: %w", err)
	}

	// Create the backplane API client with authentication and a custom httpClient configured with to use
	apiClient, err := bpapi.NewClientWithResponses(
		config.BaseURL,
		bpapi.WithRequestEditorFn(func(ctx context.Context, req *http.Request) error {
			// Add OCM authentication token to requests
			accessToken, _, err := config.OcmClient.GetConnection().TokensContext(ctx)
			if err != nil {
				return fmt.Errorf("failed to get OCM token: %w", err)
			}
			req.Header.Set("Authorization", "Bearer "+accessToken)
			req.Header.Set("User-Agent", "configuration-anomaly-detection")
			return nil
		}),
		bpapi.WithHTTPClient(httpClient),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create backplane API client: %w", err)
	}

	return &ClientImpl{
		bpClient:  apiClient,
		baseURL:   config.BaseURL,
		ocmClient: config.OcmClient,
	}, nil
}

// CreateReport creates a new investigation report for a cluster using the backplane API
func (c *ClientImpl) CreateReport(ctx context.Context, clusterId string, summary string, reportData string) (*bpapi.Report, error) {
	if reportData == "" || clusterId == "" || summary == "" {
		return nil, fmt.Errorf("clusterId, summary and report data are required")
	}

	encoded := base64.StdEncoding.EncodeToString([]byte(reportData))

	createReq := bpapi.CreateReportJSONRequestBody{
		Summary: summary,
		Data:    encoded,
	}

	resp, err := c.bpClient.CreateReportWithResponse(ctx, clusterId, createReq)
	if err != nil {
		return nil, fmt.Errorf("failed to create report: %w", err)
	}

	if resp.StatusCode() != http.StatusCreated {
		return nil, fmt.Errorf("unexpected status code %d when creating report: %s", resp.StatusCode(), resp.Body)
	}

	return resp.JSON201, nil
}

func (c *ClientImpl) GetRestConfig(ctx context.Context, clusterId string, remediationName string, isManagementCluster bool) (*RestConfig, error) {
	createRemediationParams := bpapi.CreateRemediationParams{
		RemediationName: remediationName,
		ManagingCluster: nil, // If this parameter is nil in CreateRemediationParams, it specifies spoke cluster
	}
	if isManagementCluster {
		managingCluster := bpapi.CreateRemediationParamsManagingClusterManagement
		createRemediationParams.ManagingCluster = &managingCluster
	}

	ocmConnection := c.ocmClient.GetConnection()
	accessToken, _, err := ocmConnection.TokensContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get OCM token: %w", err)
	}
	accessToken = strings.TrimSpace(accessToken)

	response, err := c.bpClient.CreateRemediationWithResponse(ctx, clusterId, &createRemediationParams)
	if err != nil {
		return nil, fmt.Errorf("failed to create remediation: %w", err)
	}
	if response == nil {
		return nil, fmt.Errorf("failed to create remediation: empty response")
	}
	if response.StatusCode() != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code %d when creating remediation: %s", response.StatusCode(), response.Body)
	}
	if response.JSON200 == nil {
		return nil, fmt.Errorf("failed to create remediation: missing response payload")
	}
	if response.JSON200.ProxyUri == nil || *response.JSON200.ProxyUri == "" {
		return nil, fmt.Errorf("failed to create remediation: missing proxy URI in response payload")
	}

	bpAPIClusterURL := c.baseURL + *response.JSON200.ProxyUri

	cfg := &rest.Config{
		Host:        bpAPIClusterURL,
		BearerToken: accessToken,
	}

	deleteRemediationParams := bpapi.DeleteRemediationParams{
		RemediationInstanceId: response.JSON200.RemediationInstanceId,
		ManagingCluster:       nil,
	}
	if isManagementCluster {
		managingCluster := bpapi.DeleteRemediationParamsManagingClusterManagement
		deleteRemediationParams.ManagingCluster = &managingCluster
	}

	restConfig := &RestConfig{
		Config: *cfg,
		Cleaner: CleanerFunc(func() error {
			cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			delResponse, err := c.bpClient.DeleteRemediationWithResponse(cleanupCtx, clusterId, &deleteRemediationParams)
			if err != nil {
				return fmt.Errorf("failed to delete remediation: %w", err)
			}
			if delResponse == nil {
				return fmt.Errorf("failed to delete remediation: empty response")
			}
			if delResponse.StatusCode() >= http.StatusMultipleChoices {
				return fmt.Errorf("unexpected status code %d when deleting remediation: %s", delResponse.StatusCode(), delResponse.Body)
			}
			return nil
		}),
	}

	return restConfig, nil
}

func httpDoerWithProxy(proxyURL string) (*http.Client, error) {
	client := &http.Client{}

	// If the caller passed an empty proxyURL, return a bare client without it
	if proxyURL == "" {
		return client, nil
	}

	proxy, err := url.Parse(proxyURL)
	if err != nil {
		return nil, err
	}

	client.Transport = &http.Transport{Proxy: http.ProxyURL(proxy)}

	return client, nil
}

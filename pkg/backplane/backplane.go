// Package backplane provides helper functions for interacting with the backplane-api SDK
package backplane

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"

	bpapi "github.com/openshift/backplane-api/pkg/client"
	"github.com/openshift/configuration-anomaly-detection/pkg/ocm"
)

// Client provides methods for interacting with the backplane API
type Client interface {
	// CreateReport creates a new cluster report
	CreateReport(ctx context.Context, clusterId string, summary string, reportData string) (*bpapi.Report, error)
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

func httpDoerWithProxy(proxyURL string) (*http.Client, error) {
	proxy, err := url.Parse(proxyURL)
	if err != nil {
		return nil, err
	}

	return &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxy)},
	}, nil
}

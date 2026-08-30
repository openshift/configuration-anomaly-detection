// Package dynatrace contains functions for querying Dynatrace GRAIL data using DQL
package dynatrace

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
)

//go:generate mockgen --build_flags=--mod=readonly -source $GOFILE -destination ./mock/dynatracemock.go -package dynatracemock

const (
	defaultTimeout  = 30 * time.Second
	pollInterval    = 2 * time.Second
	maxPollAttempts = 60 // Increased from 30 to 60 (2 minutes total)
)

type Client interface {
	ExecuteQuery(ctx context.Context, query string) (*QueryResult, error)
	GetPodLogs(ctx context.Context, podName, namespace, mcName string, since time.Duration) ([]LogRecord, error)
	// If containerName is empty, retrieves logs from all containers
	GetPodContainerLogs(ctx context.Context, podName, namespace, mcName, containerName string, since time.Duration) ([]LogRecord, error)
}

type SdkClient struct {
	environmentID string
	accessToken   string
	httpClient    *http.Client
	baseURL       string
}

type Config struct {
	EnvironmentID string
	ClientID      string
	ClientSecret  string
	AccessToken   string // Optional: if you already have an access token
}

// If Config.AccessToken is provided, uses it directly.
// Otherwise, obtains an OAuth token using ClientID and ClientSecret.
func New(config Config) (*SdkClient, error) {
	if config.EnvironmentID == "" {
		return nil, fmt.Errorf("environmentID is required")
	}

	client := &SdkClient{
		environmentID: config.EnvironmentID,
		httpClient: &http.Client{
			Timeout: defaultTimeout,
		},
		baseURL: fmt.Sprintf("https://%s.apps.dynatrace.com/platform/storage/query/v1", config.EnvironmentID),
	}

	// If access token is provided, use it directly
	if config.AccessToken != "" {
		client.accessToken = config.AccessToken
		return client, nil
	}

	if config.ClientID == "" || config.ClientSecret == "" {
		return nil, fmt.Errorf("either AccessToken or both ClientID and ClientSecret must be provided")
	}

	token, err := client.obtainOAuthToken(config.ClientID, config.ClientSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to obtain OAuth token: %w", err)
	}

	client.accessToken = token
	return client, nil
}
func (c *SdkClient) obtainOAuthToken(clientID, clientSecret string) (string, error) {
	tokenURL := "https://sso.dynatrace.com/sso/oauth2/token"

	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	data.Set("client_id", clientID)
	data.Set("client_secret", clientSecret)
	data.Set("scope", "storage:logs:read storage:buckets:read")

	req, err := http.NewRequest(http.MethodPost, tokenURL, bytes.NewBufferString(data.Encode()))
	if err != nil {
		return "", err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("token request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", fmt.Errorf("failed to decode token response: %w", err)
	}

	return tokenResp.AccessToken, nil
}

func (c *SdkClient) ExecuteQuery(ctx context.Context, query string) (*QueryResult, error) {
	logging.Debugf("Executing DQL query: %s", query)

	reqBody := QueryRequest{Query: query}
	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal query request: %w", err)
	}

	endpoint := fmt.Sprintf("%s/query:execute", c.baseURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.accessToken))

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute query: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("query request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var queryResp QueryResponse
	if err := json.NewDecoder(resp.Body).Decode(&queryResp); err != nil {
		return nil, fmt.Errorf("failed to decode query response: %w", err)
	}

	if queryResp.State == "RUNNING" {
		logging.Infof("Query is running asynchronously, polling for results with request ID: %s", queryResp.RequestToken)
		return c.pollQueryResults(ctx, queryResp.RequestToken)
	}

	return &QueryResult{
		Records: queryResp.Result.Records,
		State:   queryResp.State,
	}, nil
}
func (c *SdkClient) pollQueryResults(ctx context.Context, requestToken string) (*QueryResult, error) {
	endpoint := fmt.Sprintf("%s/query:poll?request-token=%s", c.baseURL, requestToken)

	for attempt := 0; attempt < maxPollAttempts; attempt++ {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(pollInterval):
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create poll request: %w", err)
		}

		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.accessToken))

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("failed to poll query results: %w", err)
		}

		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			return nil, fmt.Errorf("poll request failed with status %d: %s", resp.StatusCode, string(body))
		}

		var queryResp QueryResponse
		if err := json.NewDecoder(resp.Body).Decode(&queryResp); err != nil {
			resp.Body.Close()
			return nil, fmt.Errorf("failed to decode poll response: %w", err)
		}
		resp.Body.Close()

		logging.Infof("Poll attempt %d: state=%s", attempt+1, queryResp.State)

		if queryResp.State == "SUCCEEDED" {
			logging.Infof("Query completed successfully after %d poll attempts", attempt+1)
			return &QueryResult{
				Records: queryResp.Result.Records,
				State:   queryResp.State,
			}, nil
		}

		if queryResp.State == "FAILED" {
			return nil, fmt.Errorf("query failed: %s", queryResp.State)
		}

		logging.Debugf("Query still running, attempt %d/%d", attempt+1, maxPollAttempts)
	}

	return nil, fmt.Errorf("query polling timed out after %d attempts", maxPollAttempts)
}

func (c *SdkClient) GetPodLogs(ctx context.Context, podName, namespace, mcName string, since time.Duration) ([]LogRecord, error) {
	return c.GetPodContainerLogs(ctx, podName, namespace, mcName, "", since)
}

// If containerName is empty, retrieves logs from all containers in the pod.
// Uses DQL syntax compatible with Dynatrace GRAIL API.
func (c *SdkClient) GetPodContainerLogs(ctx context.Context, podName, namespace, mcName, containerName string, since time.Duration) ([]LogRecord, error) {
	query := fmt.Sprintf(`fetch logs, from:now()-%s
| filter matchesValue(event.type, "LOG")
  and matchesPhrase(dt.kubernetes.cluster.name, "%s")
  and matchesValue(k8s.namespace.name, "%s")
  and matchesValue(k8s.pod.name, "%s")`, formatDuration(since), mcName, namespace, podName)

	if containerName != "" {
		query += fmt.Sprintf(`
  and matchesValue(k8s.container.name, "%s")`, containerName)
	}

	query += `
| sort timestamp asc`

	result, err := c.ExecuteQuery(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query pod logs: %w", err)
	}

	logs := make([]LogRecord, 0, len(result.Records))
	for _, record := range result.Records {
		logs = append(logs, LogRecord{
			Timestamp: getStringValue(record, "timestamp"),
			Content:   getStringValue(record, "content"),
			PodName:   getStringValue(record, "k8s.pod.name"),
			Namespace: getStringValue(record, "k8s.namespace.name"),
			Container: getStringValue(record, "k8s.container.name"),
		})
	}

	if containerName != "" {
		logging.Infof("Retrieved %d log entries for container %s in pod %s", len(logs), containerName, podName)
	} else {
		logging.Infof("Retrieved %d log entries for pod %s", len(logs), podName)
	}
	return logs, nil
}
func formatDuration(d time.Duration) string {
	hours := int(d.Hours())
	if hours > 0 {
		return fmt.Sprintf("%dh", hours)
	}
	minutes := int(d.Minutes())
	if minutes > 0 {
		return fmt.Sprintf("%dm", minutes)
	}
	return fmt.Sprintf("%ds", int(d.Seconds()))
}

func getStringValue(record map[string]interface{}, key string) string {
	if val, ok := record[key]; ok {
		if strVal, ok := val.(string); ok {
			return strVal
		}
	}
	return ""
}

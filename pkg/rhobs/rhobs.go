package rhobs

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	defaultHTTPTimeout = 30 * time.Second
	maxErrorBodyLength = 500
)

type Client interface {
	QueryLogs(ctx context.Context, logQLQuery string, start, end time.Time, limit int) (*LogQueryResult, error)
}

type ClientImpl struct {
	httpClient *http.Client
	baseURL    string
	token      string
}

type Config struct {
	BaseURL string
	Token   string
}

func NewClient(config Config) (Client, error) {
	if config.BaseURL == "" {
		return nil, fmt.Errorf("BaseURL is required")
	}
	if config.Token == "" {
		return nil, fmt.Errorf("token is required")
	}

	return &ClientImpl{
		httpClient: &http.Client{
			Timeout: defaultHTTPTimeout,
		},
		baseURL: config.BaseURL,
		token:   config.Token,
	}, nil
}

// QueryLogs queries Loki for logs matching the given LogQL query within the specified time range
func (c *ClientImpl) QueryLogs(ctx context.Context, logQLQuery string, start, end time.Time, limit int) (*LogQueryResult, error) {
	params := url.Values{}
	params.Add("query", logQLQuery)
	params.Add("start", strconv.FormatInt(start.UnixNano(), 10))
	params.Add("end", strconv.FormatInt(end.UnixNano(), 10))
	if limit > 0 {
		params.Add("limit", strconv.Itoa(limit))
	}

	queryURL := fmt.Sprintf("%s/loki/api/v1/query_range?%s", c.baseURL, params.Encode())

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, queryURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "configuration-anomaly-detection")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		errorBody := string(body)
		if len(errorBody) > maxErrorBodyLength {
			errorBody = errorBody[:maxErrorBodyLength] + "..."
		}
		return nil, fmt.Errorf("unexpected status code %d: %s", resp.StatusCode, errorBody)
	}

	var queryResp QueryRangeResponse
	if err := json.Unmarshal(body, &queryResp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	if queryResp.Status != "success" {
		return nil, fmt.Errorf("query failed with status: %s", queryResp.Status)
	}

	result := parseQueryResponse(&queryResp)
	return result, nil
}

// parseQueryResponse converts the Loki API response into a structured LogQueryResult
func parseQueryResponse(resp *QueryRangeResponse) *LogQueryResult {
	result := &LogQueryResult{
		Entries:     make([]LogEntry, 0),
		StreamCount: len(resp.Data.Result),
	}

	for _, stream := range resp.Data.Result {
		for _, value := range stream.Values {
			if len(value) < 2 {
				continue
			}

			timestampNano, err := strconv.ParseInt(value[0], 10, 64)
			if err != nil {
				continue
			}
			timestamp := time.Unix(0, timestampNano)

			entry := LogEntry{
				Timestamp: timestamp,
				Line:      value[1],
				Labels:    stream.Stream,
			}
			result.Entries = append(result.Entries, entry)
		}
	}

	result.TotalLines = len(result.Entries)
	return result
}

func FormatLogsForDisplay(result *LogQueryResult, maxLines int) string {
	if result == nil || len(result.Entries) == 0 {
		return "No logs found"
	}

	var output strings.Builder
	fmt.Fprintf(&output, "Found %d log entries from %d streams\n\n", result.TotalLines, result.StreamCount)

	displayCount := len(result.Entries)
	if maxLines > 0 && displayCount > maxLines {
		displayCount = maxLines
	}

	for i := 0; i < displayCount; i++ {
		entry := result.Entries[i]
		fmt.Fprintf(&output, "[%s] %s\n", entry.Timestamp.Format(time.RFC3339), entry.Line)
	}

	if len(result.Entries) > displayCount {
		fmt.Fprintf(&output, "\n... and %d more lines (truncated for display)\n", len(result.Entries)-displayCount)
	}

	return output.String()
}

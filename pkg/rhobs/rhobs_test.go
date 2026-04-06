package rhobs

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewClient(t *testing.T) {
	tests := []struct {
		name        string
		config      Config
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid config",
			config: Config{
				BaseURL: "https://grafana.example.com",
				Token:   "test-token",
			},
			expectError: false,
		},
		{
			name: "missing base URL",
			config: Config{
				Token: "test-token",
			},
			expectError: true,
			errorMsg:    "BaseURL is required",
		},
		{
			name: "missing token",
			config: Config{
				BaseURL: "https://grafana.example.com",
			},
			expectError: true,
			errorMsg:    "token is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewClient(tt.config)

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
				assert.Nil(t, client)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, client)
			}
		})
	}
}

func TestQueryLogs_Success(t *testing.T) {
	// Create a test server that returns mock Loki response
	mockResponse := QueryRangeResponse{
		Status: "success",
		Data: QueryRangeResult{
			ResultType: "streams",
			Result: []Stream{
				{
					Stream: map[string]string{
						"kubernetes_namespace_name": "test-namespace",
						"kubernetes_pod_name":       "test-pod-123",
					},
					Values: [][]string{
						{"1704067200000000000", "First log line"},
						{"1704067201000000000", "Second log line"},
						{"1704067202000000000", "Third log line"},
					},
				},
			},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request
		assert.Equal(t, "GET", r.Method)
		assert.Equal(t, "/loki/api/v1/query_range", r.URL.Path)
		assert.Equal(t, "Bearer test-token", r.Header.Get("Authorization"))

		// Verify query parameters
		query := r.URL.Query()
		assert.NotEmpty(t, query.Get("query"))
		assert.NotEmpty(t, query.Get("start"))
		assert.NotEmpty(t, query.Get("end"))
		assert.Equal(t, "100", query.Get("limit"))

		// Return mock response
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(mockResponse)
	}))
	defer server.Close()

	client, err := NewClient(Config{
		BaseURL: server.URL,
		Token:   "test-token",
	})
	require.NoError(t, err)

	ctx := context.Background()
	end := time.Now()
	start := end.Add(-30 * time.Minute)

	result, err := client.QueryLogs(ctx, `{namespace="test"}`, start, end, 100)

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, 3, result.TotalLines)
	assert.Equal(t, 1, result.StreamCount)
	assert.Len(t, result.Entries, 3)
	assert.Equal(t, "First log line", result.Entries[0].Line)
	assert.Equal(t, "Second log line", result.Entries[1].Line)
	assert.Equal(t, "Third log line", result.Entries[2].Line)
}

func TestQueryLogs_HTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("Unauthorized"))
	}))
	defer server.Close()

	client, err := NewClient(Config{
		BaseURL: server.URL,
		Token:   "invalid-token",
	})
	require.NoError(t, err)

	ctx := context.Background()
	end := time.Now()
	start := end.Add(-30 * time.Minute)

	result, err := client.QueryLogs(ctx, `{namespace="test"}`, start, end, 100)

	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "401")
}

func TestQueryLogs_InvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("invalid json"))
	}))
	defer server.Close()

	client, err := NewClient(Config{
		BaseURL: server.URL,
		Token:   "test-token",
	})
	require.NoError(t, err)

	ctx := context.Background()
	end := time.Now()
	start := end.Add(-30 * time.Minute)

	result, err := client.QueryLogs(ctx, `{namespace="test"}`, start, end, 100)

	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "failed to unmarshal response")
}

func TestQueryLogs_FailedStatus(t *testing.T) {
	mockResponse := QueryRangeResponse{
		Status: "error",
		Data:   QueryRangeResult{},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(mockResponse)
	}))
	defer server.Close()

	client, err := NewClient(Config{
		BaseURL: server.URL,
		Token:   "test-token",
	})
	require.NoError(t, err)

	ctx := context.Background()
	end := time.Now()
	start := end.Add(-30 * time.Minute)

	result, err := client.QueryLogs(ctx, `{namespace="test"}`, start, end, 100)

	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "query failed with status: error")
}

func TestQueryLogs_EmptyResult(t *testing.T) {
	mockResponse := QueryRangeResponse{
		Status: "success",
		Data: QueryRangeResult{
			ResultType: "streams",
			Result:     []Stream{},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(mockResponse)
	}))
	defer server.Close()

	client, err := NewClient(Config{
		BaseURL: server.URL,
		Token:   "test-token",
	})
	require.NoError(t, err)

	ctx := context.Background()
	end := time.Now()
	start := end.Add(-30 * time.Minute)

	result, err := client.QueryLogs(ctx, `{namespace="test"}`, start, end, 100)

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, 0, result.TotalLines)
	assert.Equal(t, 0, result.StreamCount)
}

func TestFormatLogsForDisplay_NoLogs(t *testing.T) {
	result := &LogQueryResult{
		Entries:     []LogEntry{},
		TotalLines:  0,
		StreamCount: 0,
	}

	output := FormatLogsForDisplay(result, 10)
	assert.Equal(t, "No logs found", output)
}

func TestFormatLogsForDisplay_WithLogs(t *testing.T) {
	timestamp := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
	result := &LogQueryResult{
		Entries: []LogEntry{
			{Timestamp: timestamp, Line: "Log line 1"},
			{Timestamp: timestamp.Add(time.Second), Line: "Log line 2"},
			{Timestamp: timestamp.Add(2 * time.Second), Line: "Log line 3"},
		},
		TotalLines:  3,
		StreamCount: 1,
	}

	output := FormatLogsForDisplay(result, 10)
	assert.Contains(t, output, "Found 3 log entries from 1 streams")
	assert.Contains(t, output, "Log line 1")
	assert.Contains(t, output, "Log line 2")
	assert.Contains(t, output, "Log line 3")
}

func TestFormatLogsForDisplay_Truncation(t *testing.T) {
	timestamp := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
	entries := make([]LogEntry, 10)
	for i := 0; i < 10; i++ {
		entries[i] = LogEntry{
			Timestamp: timestamp.Add(time.Duration(i) * time.Second),
			Line:      "Log line",
		}
	}

	result := &LogQueryResult{
		Entries:     entries,
		TotalLines:  10,
		StreamCount: 1,
	}

	output := FormatLogsForDisplay(result, 5)
	assert.Contains(t, output, "Found 10 log entries from 1 streams")
	assert.Contains(t, output, "... and 5 more lines (truncated for display)")
}

func TestFormatLogsForDisplay_NilResult(t *testing.T) {
	output := FormatLogsForDisplay(nil, 10)
	assert.Equal(t, "No logs found", output)
}

func TestParseQueryResponse_MultipleStreams(t *testing.T) {
	resp := &QueryRangeResponse{
		Status: "success",
		Data: QueryRangeResult{
			ResultType: "streams",
			Result: []Stream{
				{
					Stream: map[string]string{"pod": "pod1"},
					Values: [][]string{
						{"1704067200000000000", "Pod 1 log line"},
					},
				},
				{
					Stream: map[string]string{"pod": "pod2"},
					Values: [][]string{
						{"1704067201000000000", "Pod 2 log line"},
					},
				},
			},
		},
	}

	result := parseQueryResponse(resp)

	assert.Equal(t, 2, result.TotalLines)
	assert.Equal(t, 2, result.StreamCount)
	assert.Len(t, result.Entries, 2)
	assert.Equal(t, "Pod 1 log line", result.Entries[0].Line)
	assert.Equal(t, "Pod 2 log line", result.Entries[1].Line)
}

func TestParseQueryResponse_InvalidTimestamp(t *testing.T) {
	resp := &QueryRangeResponse{
		Status: "success",
		Data: QueryRangeResult{
			ResultType: "streams",
			Result: []Stream{
				{
					Stream: map[string]string{"pod": "pod1"},
					Values: [][]string{
						{"invalid-timestamp", "This should be skipped"},
						{"1704067200000000000", "This should be included"},
					},
				},
			},
		},
	}

	result := parseQueryResponse(resp)

	// Only one entry should be parsed successfully
	assert.Equal(t, 1, result.TotalLines)
	assert.Len(t, result.Entries, 1)
	assert.Equal(t, "This should be included", result.Entries[0].Line)
}

func TestParseQueryResponse_MalformedValues(t *testing.T) {
	resp := &QueryRangeResponse{
		Status: "success",
		Data: QueryRangeResult{
			ResultType: "streams",
			Result: []Stream{
				{
					Stream: map[string]string{"pod": "pod1"},
					Values: [][]string{
						{"1704067200000000000"}, // Missing log line
						{"1704067201000000000", "Valid log line"},
					},
				},
			},
		},
	}

	result := parseQueryResponse(resp)

	// Only the valid entry should be parsed
	assert.Equal(t, 1, result.TotalLines)
	assert.Len(t, result.Entries, 1)
	assert.Equal(t, "Valid log line", result.Entries[0].Line)
}

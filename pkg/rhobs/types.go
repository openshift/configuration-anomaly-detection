// Package rhobs provides a client for querying RHOBS Grafana Loki API
package rhobs

import "time"

// QueryRangeResponse represents the response from Loki's /loki/api/v1/query_range endpoint
type QueryRangeResponse struct {
	Status string           `json:"status"`
	Data   QueryRangeResult `json:"data"`
}

// QueryRangeResult contains the result data from a Loki query
type QueryRangeResult struct {
	ResultType string   `json:"resultType"`
	Result     []Stream `json:"result"`
	Stats      Stats    `json:"stats,omitempty"`
}

// Stream represents a log stream with its labels and values
type Stream struct {
	Stream map[string]string `json:"stream"`
	Values [][]string        `json:"values"`
}

// Stats contains query statistics
type Stats struct {
	Summary Summary `json:"summary,omitempty"`
}

// Summary contains summary statistics
type Summary struct {
	BytesProcessedPerSecond int     `json:"bytesProcessedPerSecond,omitempty"`
	LinesProcessedPerSecond int     `json:"linesProcessedPerSecond,omitempty"`
	TotalBytesProcessed     int     `json:"totalBytesProcessed,omitempty"`
	TotalLinesProcessed     int     `json:"totalLinesProcessed,omitempty"`
	ExecTime                float64 `json:"execTime,omitempty"`
}

// LogEntry represents a single log entry with timestamp and line
type LogEntry struct {
	Timestamp time.Time
	Line      string
	Labels    map[string]string
}

// LogQueryResult represents the parsed result of a log query
type LogQueryResult struct {
	Entries     []LogEntry
	TotalLines  int
	StreamCount int
}

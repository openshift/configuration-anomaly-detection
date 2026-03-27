package dynatrace

type QueryRequest struct {
	Query string `json:"query"`
}

type QueryPollRequest struct {
	RequestToken string `json:"requestToken"`
}

type QueryResponse struct {
	State        string       `json:"state"` // "SUCCEEDED", "RUNNING", "FAILED"
	RequestToken string       `json:"requestToken,omitempty"`
	Result       QueryResults `json:"result,omitempty"`
}

type QueryResults struct {
	Records []map[string]interface{} `json:"records"`
}

type QueryResult struct {
	Records []map[string]interface{}
	State   string
}

type LogRecord struct {
	Timestamp string `json:"timestamp"`
	Content   string `json:"content"`
	PodName   string `json:"pod_name"`
	Namespace string `json:"namespace"`
	Container string `json:"container"`
	Severity  string `json:"severity,omitempty"`
	Level     string `json:"level,omitempty"`
}

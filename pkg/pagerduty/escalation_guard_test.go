package pagerduty

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	sdk "github.com/PagerDuty/go-pagerduty"
	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

const (
	escalationTestIncidentPath = "/incidents/I"
	escalationTestHistoryPath  = escalationTestIncidentPath + "/log_entries"
)

type escalationHTTPClientFunc func(*http.Request) (*http.Response, error)

func (f escalationHTTPClientFunc) Do(r *http.Request) (*http.Response, error) {
	return f(r)
}

// TestEscalationUpdateErrorRedaction keeps failed updates retryable without exposing SDK details.
func TestEscalationUpdateErrorRedaction(t *testing.T) {
	logging.InitLogger("fatal", "", "")
	for _, transportFailure := range []bool{false, true} {
		t.Run(fmt.Sprintf("transportFailure=%t", transportFailure), func(t *testing.T) {
			updates := 0
			sdkClient := sdk.NewClient("fake")
			sdkClient.HTTPClient = escalationHTTPClientFunc(func(r *http.Request) (*http.Response, error) {
				status := http.StatusOK
				var body string
				switch r.URL.Path {
				case escalationTestHistoryPath:
					body = `{"log_entries":[{"type":"trigger_log_entry"}],"more":false}`
				case escalationTestIncidentPath:
					body = `{"incident":{"id":"I","status":"triggered"}}`
				case "/incidents":
					if r.Method != http.MethodPut {
						t.Errorf("unexpected update method %s", r.Method)
					}
					updates++
					if transportFailure {
						return nil, fmt.Errorf("transport failure for %s: private details", r.URL)
					}
					status = http.StatusServiceUnavailable
					body = `{"error":{"message":"customer-private-response-detail"}}`
				default:
					t.Errorf("unexpected path %s", r.URL.Path)
				}
				return &http.Response{
					StatusCode: status,
					Header:     http.Header{"Content-Type": []string{"application/json"}},
					Body:       io.NopCloser(strings.NewReader(body)),
				}, nil
			})
			client := &SdkClient{sdkClient: sdkClient, incidentData: &IncidentData{IncidentID: "I"}}
			for i := 0; i < 2; i++ {
				err := client.EscalateIncident()
				var skipped *EscalationSkippedError
				if err == nil || errors.As(err, &skipped) {
					t.Fatalf("expected ordinary update error, got %v", err)
				}
				if err.Error() != "could not escalate the incident" || errors.Unwrap(err) != nil {
					t.Fatalf("update error exposes SDK details: %v", err)
				}
			}
			if updates != 2 {
				t.Fatalf("updates=%d, want 2 failed attempts", updates)
			}
		})
	}
}

// TestEscalationLiveGuard exercises live reads, fail-closed decisions and update errors.
func TestEscalationLiveGuard(t *testing.T) {
	const (
		triggerEvent       = "trigger_log_entry"
		triggeredStatus    = "triggered"
		acknowledgedStatus = "acknowledged"
		sensitiveDetail    = "customer-private-response-detail"
	)
	core, logs := observer.New(zap.WarnLevel)
	originalLogger := logging.RawLogger
	logging.RawLogger = zap.New(core).Sugar()
	t.Cleanup(func() { logging.RawLogger = originalLogger })
	for _, tc := range []struct {
		name, status, event, failPath                                   string
		secondPage, changeAfterHistory, invalidUpdate, transportFailure bool
		want                                                            int
	}{
		{name: "eligible", status: triggeredStatus, event: triggerEvent, want: 1},
		{name: "invalid update parameters", status: triggeredStatus, event: triggerEvent, want: 1, invalidUpdate: true},
		{name: "already escalated", status: triggeredStatus, event: "escalate_log_entry"},
		{name: acknowledgedStatus, status: acknowledgedStatus, event: triggerEvent},
		{name: "resolved", status: "resolved", event: triggerEvent},
		{name: "unknown status", status: "future_status", event: triggerEvent},
		{name: "incident lookup failed", event: triggerEvent, failPath: escalationTestIncidentPath},
		{name: "history lookup failed", failPath: escalationTestHistoryPath},
		{name: "transport failure with incident URL", transportFailure: true},
		{name: "unknown history", status: triggeredStatus, event: sensitiveDetail},
		{name: "empty history", status: triggeredStatus},
		{name: "reassigned is ambiguous", status: triggeredStatus, event: "assign_log_entry"},
		{name: "escalated on next page", status: triggeredStatus, event: triggerEvent, secondPage: true},
		{name: "acknowledged after history lookup", status: triggeredStatus, event: triggerEvent, changeAfterHistory: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			write := func(w http.ResponseWriter, format string, args ...any) {
				if _, err := fmt.Fprintf(w, format, args...); err != nil {
					t.Errorf("write mock response: %v", err)
				}
			}
			updates := 0
			historyRead := false
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if tc.failPath == r.URL.Path {
					w.WriteHeader(http.StatusServiceUnavailable)
					write(w, `{"error":{"message":%q}}`, sensitiveDetail)
					return
				}
				switch r.URL.Path {
				case escalationTestHistoryPath:
					historyRead = true
					event := tc.event
					more := tc.secondPage && r.URL.Query().Get("offset") == ""
					if tc.secondPage && !more {
						event = "escalate_log_entry"
					}
					if event == "" {
						write(w, `%s`, `{"log_entries":[],"more":false}`)
					} else {
						write(w, `{"log_entries":[{"type":%q}],"more":%t}`, event, more)
					}
				case escalationTestIncidentPath:
					if !historyRead {
						t.Error("expected history before final live status read")
					}
					status := tc.status
					if tc.changeAfterHistory && historyRead {
						status = acknowledgedStatus
					}
					write(w, `{"incident":{"id":"I","status":%q}}`, status)
				case "/incidents":
					if r.Method != http.MethodPut {
						t.Errorf("unexpected method %s", r.Method)
					}
					updates++
					if tc.invalidUpdate {
						w.WriteHeader(http.StatusBadRequest)
						write(w, `{"error":{"code":2001,"message":%q}}`, sensitiveDetail)
						return
					}
					write(w, `%s`, `{"incidents":[]}`)
				default:
					t.Errorf("unexpected path %s", r.URL.Path)
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			defer server.Close()
			if tc.transportFailure {
				server.Close() // Force an SDK transport error containing the request URL.
			}
			// Fresh clients represent independent pipelines without a shared local tracker.
			for i := 0; i < 2; i++ {
				historyRead = false
				c := &SdkClient{sdkClient: sdk.NewClient("fake", sdk.WithAPIEndpoint(server.URL)), incidentData: &IncidentData{IncidentID: "I"}}
				err := c.EscalateIncident()
				if tc.want == 0 || tc.invalidUpdate {
					var skipped *EscalationSkippedError
					if !errors.As(err, &skipped) {
						t.Fatalf("expected skip, got %v", err)
					}
					if strings.Contains(err.Error(), sensitiveDetail) || strings.Contains(err.Error(), escalationTestIncidentPath) {
						t.Error("skip error exposes SDK response details or incident URL")
					}
				} else if err != nil {
					t.Fatal(err)
				}
			}
			if updates != 2*tc.want {
				t.Fatalf("updates=%d, want %d", updates, 2*tc.want)
			}
		})
	}
	if logs.Len() == 0 {
		t.Fatal("expected skip warnings")
	}
	for _, entry := range logs.All() {
		if strings.Contains(entry.Message, sensitiveDetail) || strings.Contains(entry.Message, escalationTestIncidentPath) {
			t.Errorf("skip log exposes incident URL or response details: %s", entry.Message)
		}
	}
}

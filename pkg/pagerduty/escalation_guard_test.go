package pagerduty

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	sdk "github.com/PagerDuty/go-pagerduty"
	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

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
		{name: "incident lookup failed", event: triggerEvent, failPath: "/incidents/I"},
		{name: "history lookup failed", failPath: "/incidents/I/log_entries"},
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
				case "/incidents/I/log_entries":
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
				case "/incidents/I":
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
					if strings.Contains(err.Error(), sensitiveDetail) || strings.Contains(err.Error(), "/incidents/I") {
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
		if strings.Contains(entry.Message, sensitiveDetail) || strings.Contains(entry.Message, "/incidents/I") {
			t.Errorf("skip log exposes incident URL or response details: %s", entry.Message)
		}
	}
}

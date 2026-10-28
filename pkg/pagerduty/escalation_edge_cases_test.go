package pagerduty

import (
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"

	sdk "github.com/PagerDuty/go-pagerduty"
	"github.com/stretchr/testify/require"
)

const escalationTestUpdatesPath = "/incidents"

func escalationTestResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

// TestEscalationHistoryPagination verifies complete history is required before updating.
func TestEscalationHistoryPagination(t *testing.T) {
	const trigger = `{"type":"trigger_log_entry"}`
	for _, tc := range []struct {
		name       string
		pages      []string
		wantReads  int
		pageSize   int
		wantReason string
	}{
		{
			name: "initial trigger on second page",
			pages: []string{
				`{"log_entries":[{"type":"notify_log_entry"},{"type":"annotate_log_entry"}],"more":true}`,
				`{"log_entries":[` + trigger + `],"more":false}`,
			},
			wantReads: 2,
			pageSize:  2,
		},
		{
			name:       "empty page with more history",
			pages:      []string{`{"log_entries":[],"more":true}`},
			wantReads:  1,
			wantReason: "incomplete history pagination",
		},
		{
			name:       "benign history without initial trigger",
			pages:      []string{`{"log_entries":[{"type":"notify_log_entry"}],"more":false}`},
			wantReads:  1,
			wantReason: "complete initial-trigger history unavailable",
		},
		{
			name:       "history exceeds pagination bound",
			pages:      []string{`{"log_entries":[` + strings.TrimSuffix(strings.Repeat(trigger+",", 100), ",") + `],"more":true}`},
			wantReads:  100,
			pageSize:   100,
			wantReason: "complete initial-trigger history unavailable",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reads, updates, statusReads := 0, 0, 0
			sdkClient := sdk.NewClient("fake")
			sdkClient.HTTPClient = escalationHTTPClientFunc(func(r *http.Request) (*http.Response, error) {
				switch r.URL.Path {
				case escalationTestHistoryPath:
					offset := reads * tc.pageSize
					if offset > 0 {
						require.Equal(t, strconv.Itoa(offset), r.URL.Query().Get("offset"))
					}
					require.Equal(t, "100", r.URL.Query().Get("limit"))
					page := tc.pages[reads%len(tc.pages)]
					reads++
					return escalationTestResponse(http.StatusOK, page), nil
				case escalationTestIncidentPath:
					statusReads++
					return escalationTestResponse(http.StatusOK, `{"incident":{"status":"triggered"}}`), nil
				case escalationTestUpdatesPath:
					updates++
					require.Equal(t, http.MethodPut, r.Method)
					return escalationTestResponse(http.StatusOK, `{"incidents":[]}`), nil
				default:
					return nil, fmt.Errorf("unexpected request %s", r.URL.Path)
				}
			})
			client := &SdkClient{sdkClient: sdkClient, incidentData: &IncidentData{IncidentID: "I"}}
			err := client.EscalateIncident()
			if tc.wantReason == "" {
				require.NoError(t, err)
				require.Equal(t, 1, updates)
				require.Equal(t, 1, statusReads)
			} else {
				var skipped *EscalationSkippedError
				require.ErrorAs(t, err, &skipped)
				require.Equal(t, tc.wantReason, skipped.Reason)
				require.Zero(t, updates)
				require.Zero(t, statusReads)
			}
			require.Equal(t, tc.wantReads, reads)
		})
	}
}

// TestEscalationUpdateClassification covers legacy skips and authentication failures after eligibility succeeds.
func TestEscalationUpdateClassification(t *testing.T) {
	for _, tc := range []struct {
		name, message, wantReason string
		status                    int
	}{
		{name: "unauthorized", status: http.StatusUnauthorized, message: "invalid token"},
		{name: "resolved during update", status: http.StatusBadRequest, message: "Incident Already Resolved", wantReason: "incident already resolved"},
		{name: "legacy invalid policy", status: http.StatusBadRequest, message: "the escalation policy or incident id are invalid", wantReason: "escalation policy invalid or no higher level available"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			updates := 0
			sdkClient := sdk.NewClient("fake")
			sdkClient.HTTPClient = escalationHTTPClientFunc(func(r *http.Request) (*http.Response, error) {
				switch r.URL.Path {
				case escalationTestHistoryPath:
					return escalationTestResponse(http.StatusOK, `{"log_entries":[{"type":"trigger_log_entry"}],"more":false}`), nil
				case escalationTestIncidentPath:
					return escalationTestResponse(http.StatusOK, `{"incident":{"status":"triggered"}}`), nil
				case escalationTestUpdatesPath:
					updates++
					return escalationTestResponse(tc.status, fmt.Sprintf(`{"error":{"message":%q}}`, tc.message)), nil
				default:
					return nil, fmt.Errorf("unexpected request %s", r.URL.Path)
				}
			})
			client := &SdkClient{sdkClient: sdkClient, incidentData: &IncidentData{IncidentID: "I"}}
			err := client.EscalateIncident()
			if tc.wantReason == "" {
				var invalidToken InvalidTokenError
				require.ErrorAs(t, err, &invalidToken)
			} else {
				var skipped *EscalationSkippedError
				require.ErrorAs(t, err, &skipped)
				require.Equal(t, tc.wantReason, skipped.Reason)
			}
			require.Equal(t, 1, updates)
		})
	}
}

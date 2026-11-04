package pagerduty

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"testing"

	sdk "github.com/PagerDuty/go-pagerduty"
	"github.com/stretchr/testify/require"
)

// TestEscalationRoutingDenylist models CAD's policy moves, not just trigger/note history.
func TestEscalationRoutingDenylist(t *testing.T) {
	const (
		cadActor   = `"agent":{"id":"CAD","type":"user_reference"}`
		humanActor = `"agent":{"id":"HUMAN","type":"user_reference"}`
	)
	// Newest first: automatic assignment after CAD delegation, then grouping,
	// urgency, initial automatic assignment, and the initial trigger.
	baseline := []string{
		`{"type":"assign_log_entry","assignees":[{"id":"SILENT","type":"user_reference"}]}`,
		`{"type":"delegate_log_entry",` + cadActor + `}`,
		`{"type":"annotate_log_entry"}`,
		`{"type":"event_rule_action_log_entry"}`,
		`{"type":"link_log_entry"}`,
		`{"type":"assign_log_entry","agent":{"type":"service_reference"},"assignees":[{"id":"INITIAL","type":"user_reference"}]}`,
		`{"type":"trigger_log_entry"}`,
	}
	for _, tc := range []struct {
		name, extra      string
		deny, failLookup bool
	}{
		{name: "normal CAD routing"},
		{name: "future event is not handling", extra: `{"type":"future_log_entry"}`},
		{name: "CAD assignment", extra: `{"type":"assign_log_entry",` + cadActor + `,"assignees":[{"id":"SILENT","type":"user_reference"}]}`},
		{name: "human returns assignment to CAD", extra: `{"type":"assign_log_entry",` + humanActor + `,"assignees":[{"id":"CAD","type":"user_reference"}]}`},
		{name: "human assigns another responder", deny: true, extra: `{"type":"assign_log_entry",` + humanActor + `,"assignees":[{"id":"OTHER","type":"user_reference"}]}`},
		{name: "mixed targets", deny: true, extra: `{"type":"assign_log_entry",` + humanActor + `,"assignees":[{"id":"CAD","type":"user_reference"},{"id":"OTHER","type":"user_reference"}]}`},
		{name: "human assigns schedule", deny: true, extra: `{"type":"assign_log_entry",` + humanActor + `,"assignees":[{"id":"SCHEDULE","type":"schedule_reference"}]}`},
		{name: "human delegation", deny: true, extra: `{"type":"delegate_log_entry",` + humanActor + `}`},
		{name: "missing targets for human assignment", deny: true, extra: `{"type":"assign_log_entry",` + humanActor + `}`},
		{name: "missing user ID", deny: true, extra: `{"type":"assign_log_entry","agent":{"type":"user_reference"}}`},
		{name: "user lookup fails", deny: true, failLookup: true},
		{name: "escalation on older page", deny: true, extra: `{"type":"escalate_log_entry"}`},
		{name: "acknowledgment on older page", deny: true, extra: `{"type":"acknowledge_log_entry"}`},
		{name: "resolution on older page", deny: true, extra: `{"type":"resolve_log_entry"}`},
		{name: "acknowledgment timeout", deny: true, extra: `{"type":"unacknowledge_log_entry"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			history := append([]string{}, baseline...)
			if tc.extra != "" {
				// Place the candidate beyond the first page to exercise full scanning.
				history = append(history[:6], tc.extra, baseline[6])
			}
			updates, statusReads := 0, 0
			lookups := map[string]int{}
			sdkClient := sdk.NewClient("fake")
			sdkClient.HTTPClient = escalationHTTPClientFunc(func(r *http.Request) (*http.Response, error) {
				if strings.HasPrefix(r.URL.Path, "/users/") {
					id := strings.TrimPrefix(r.URL.Path, "/users/")
					lookups[id]++
					if tc.failLookup {
						return escalationTestResponse(http.StatusServiceUnavailable, `{}`), nil
					}
					email := "responder@example.com"
					if id == "CAD" {
						email = CADEmailAddress
					}
					return escalationTestResponse(http.StatusOK, fmt.Sprintf(`{"user":{"id":%q,"email":%q}}`, id, email)), nil
				}
				switch r.URL.Path {
				case escalationTestHistoryPath:
					offset := 0
					if value := r.URL.Query().Get("offset"); value != "" {
						var err error
						offset, err = strconv.Atoi(value)
						require.NoError(t, err)
					}
					require.Less(t, offset, len(history))
					end := min(offset+3, len(history))
					return escalationTestResponse(http.StatusOK, fmt.Sprintf(`{"log_entries":[%s],"more":%t}`, strings.Join(history[offset:end], ","), end < len(history))), nil
				case escalationTestIncidentPath:
					statusReads++
					return escalationTestResponse(http.StatusOK, `{"incident":{"status":"triggered"}}`), nil
				case escalationTestUpdatesPath:
					updates++
					require.Equal(t, http.MethodPut, r.Method)
					return escalationTestResponse(http.StatusOK, `{"incidents":[]}`), nil
				default:
					return nil, fmt.Errorf("unexpected path %s", r.URL.Path)
				}
			})
			client := &SdkClient{sdkClient: sdkClient, incidentData: &IncidentData{IncidentID: "I"}}
			err := client.EscalateIncident()
			if tc.deny {
				var skipped *EscalationSkippedError
				require.ErrorAs(t, err, &skipped)
				require.Zero(t, updates)
				require.Zero(t, statusReads)
			} else {
				require.NoError(t, err)
				require.Equal(t, 1, updates)
				require.Equal(t, 1, statusReads)
			}
			for _, count := range lookups {
				require.Equal(t, 1, count, "identity lookups should be cached within an attempt")
			}
		})
	}
}

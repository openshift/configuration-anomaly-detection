package pagerduty

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	sdk "github.com/PagerDuty/go-pagerduty"
)

func TestNodePoolIDsFromAlertBody(t *testing.T) {
	tests := []struct {
		name string
		body map[string]interface{}
		want []string
	}{
		{
			name: "COO firing groups nodepools",
			body: map[string]interface{}{"details": map[string]interface{}{"firing": []interface{}{
				map[string]interface{}{"labels": map[string]interface{}{"node_pool_id": "workers-0"}},
				map[string]interface{}{"labels": map[string]interface{}{"node_pool_id": "workers-1"}},
			}}},
			want: []string{"workers-0", "workers-1"},
		},
		{
			name: "legacy firing text",
			body: map[string]interface{}{"details": map[string]interface{}{"firing": "nodepool = workers-0\n - node_pool_id = workers-1"}},
			want: []string{"workers-0", "workers-1"},
		},
		{
			name: "direct detail",
			body: map[string]interface{}{"details": map[string]interface{}{"node_pool_id": "workers-0"}},
			want: []string{"workers-0"},
		},
		{
			name: "missing labels",
			body: map[string]interface{}{"details": map[string]interface{}{"firing": []interface{}{map[string]interface{}{"labels": map[string]interface{}{"cluster_id": "cluster-1"}}}}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := nodePoolIDsFromAlertBody(tt.body)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRetrieveNodePoolIDsUsesEveryPageOfFiringAlerts(t *testing.T) {
	var offsets []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/incidents/incident-1/alerts" || r.URL.Query().Get("limit") != "100" {
			t.Errorf("unexpected PagerDuty request: %s", r.URL.String())
		}
		offset := r.URL.Query().Get("offset")
		offsets = append(offsets, offset)
		w.Header().Set("Content-Type", "application/json")
		switch offset {
		case "":
			_, _ = fmt.Fprint(w, `{"more":true,"alerts":[{"status":"resolved","body":{"details":{"node_pool_id":"resolved-pool"}}},{"status":"triggered","body":{"details":{"node_pool_id":"workers-0"}}}]}`)
		case "100":
			_, _ = fmt.Fprint(w, `{"more":false,"alerts":[{"status":"triggered","body":{"details":{"node_pool_id":"workers-1"}}},{"status":"triggered","body":{"details":{"node_pool_id":"workers-0"}}}]}`)
		default:
			t.Errorf("unexpected offset %q", offset)
			http.Error(w, "unexpected offset", http.StatusBadRequest)
		}
	}))
	defer server.Close()

	client := &SdkClient{
		sdkClient:    sdk.NewClient("test-token", sdk.WithAPIEndpoint(server.URL)),
		incidentData: &IncidentData{IncidentID: "incident-1"},
	}
	got, err := client.RetrieveNodePoolIDs()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, []string{"workers-0", "workers-1"}) {
		t.Fatalf("got nodepools %v, want only firing pools from both pages", got)
	}
	if !reflect.DeepEqual(offsets, []string{"", "100"}) {
		t.Fatalf("got page offsets %v, want initial and next page", offsets)
	}
}

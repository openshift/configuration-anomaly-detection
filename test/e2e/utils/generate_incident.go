package utils

import (
	"context"
	"crypto/rand"
	"fmt"
	"time"

	sdk "github.com/PagerDuty/go-pagerduty"
)

type TestPagerDutyClient interface {
	TriggerIncident(alertTitle, clusterID string) (string, error)
	GetIncidentID(dedupKey string) (string, error)
	ResolveIncident(incidentID string) error
}
type client struct {
	routingKey string
	apiClient  *sdk.Client
}

func NewClient(routingKey string) TestPagerDutyClient {
	return &client{
		routingKey: routingKey,
		apiClient:  sdk.NewClient(routingKey),
	}
}

// TriggerIncident creates a PagerDuty incident for testing purposes using the given alert title and cluster ID
func (c *client) TriggerIncident(alertTitle, clusterID string) (string, error) {
	event := sdk.V2Event{
		RoutingKey: c.routingKey,
		Action:     "trigger",
		DedupKey:   generateUUID(),
		Payload: &sdk.V2Payload{
			Summary:   alertTitle + " - E2E",
			Source:    "cad-integration-testing",
			Severity:  "critical",
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Details: map[string]interface{}{
				"alertname":  alertTitle,
				"cluster_id": clusterID,
			},
		},
	}
	resp, err := sdk.ManageEventWithContext(context.Background(), event)
	if err != nil {
		return "", err
	}
	return resp.DedupKey, nil
}

func (c *client) GetIncidentID(dedupKey string) (string, error) {
	// Implementation can be added if needed
	return "", nil
}

func (c *client) ResolveIncident(incidentID string) error {
	// Implementation can be added if needed
	return nil
}

func generateUUID() string {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		// Fallback to timestamp-based if crypto/rand fails
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	// Set version (4) and variant bits
	b[6] = (b[6] & 0x0f) | 0x40 // Version 4
	b[8] = (b[8] & 0x3f) | 0x80 // Variant 10
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

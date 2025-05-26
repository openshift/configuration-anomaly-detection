package utils

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	sdk "github.com/PagerDuty/go-pagerduty"
)

const (
	ClusterHasGoneMissing                         = "ClusterHasGoneMissing"
	ClusterProvisioningDelay                      = "ClusterProvisioningDelay"
	ClusterMonitoringErrorBudgetBurnSRE           = "ClusterMonitoringErrorBudgetBurnSRE"
	InsightsOperatorDown                          = "InsightsOperatorDown"
	MachineHealthCheckUnterminatedShortCircuitSRE = "MachineHealthCheckUnterminatedShortCircuitSRE"
	ApiErrorBudgetBurn                            = "ApiErrorBudgetBurn"
	AlertManagerDown                              = "AlertManagerDown"

	// PagerDuty Events API endpoint
	PagerDutyEventsURL = "https://events.pagerduty.com/v2/enqueue"
)

// EventPayload represents the payload structure for PagerDuty Events API
type EventPayload struct {
	Summary   string                 `json:"summary"`
	Source    string                 `json:"source"`
	Severity  string                 `json:"severity"`
	Timestamp string                 `json:"timestamp"`
	Details   map[string]interface{} `json:"custom_details,omitempty"`
}

// Event represents the complete event structure for PagerDuty Events API
type Event struct {
	RoutingKey  string        `json:"routing_key"`
	EventAction string        `json:"event_action"`
	DedupKey    string        `json:"dedup_key,omitempty"`
	Payload     *EventPayload `json:"payload"`
}

// EventResponse represents the response from PagerDuty Events API
type EventResponse struct {
	Status   string `json:"status"`
	Message  string `json:"message"`
	DedupKey string `json:"dedup_key"`
}

func GetAlertSummary(alertName string) (string, error) {
	switch alertName {
	case ClusterHasGoneMissing:
		return "cadtest has gone missing", nil
	case ClusterProvisioningDelay:
		return "ClusterProvisioningDelay -", nil
	case ClusterMonitoringErrorBudgetBurnSRE:
		return "ClusterMonitoringErrorBudgetBurnSRE Critical (1)", nil
	case InsightsOperatorDown:
		return "InsightsOperatorDown", nil
	case MachineHealthCheckUnterminatedShortCircuitSRE:
		return "MachineHealthCheckUnterminatedShortCircuitSRE CRITICAL (1)", nil
	case ApiErrorBudgetBurn:
		return "api-ErrorBudgetBurn k8sgpt test CRITICAL (1)", nil
	case AlertManagerDown:
		return "Alert Manager Down", nil
	default:
		return "", fmt.Errorf("unknown alert name: %s", alertName)
	}
}

type TestPagerDutyClient interface {
	CreateRequest(alertName, clusterID string) (string, error)
	GetIncidentID(dedupKey string) (string, error)
	ResolveIncident(incidentID string) error
}

type client struct {
	routingKey string
	apiClient  *sdk.Client
	httpClient *http.Client
}

func NewClient(routingKey string) TestPagerDutyClient {
	return &client{
		routingKey: routingKey,
		apiClient:  sdk.NewClient(routingKey),
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

func (c *client) CreateRequest(alertName, clusterID string) (string, error) {
	summary, err := GetAlertSummary(alertName)
	if err != nil {
		return "", err
	}

	dedupKey := generateUUID()

	event := Event{
		RoutingKey:  c.routingKey,
		EventAction: "trigger",
		DedupKey:    dedupKey,
		Payload: &EventPayload{
			Summary:   summary,
			Source:    "cad-integration-testing",
			Severity:  "critical",
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Details: map[string]interface{}{
				"alertname":  alertName,
				"cluster_id": clusterID,
			},
		},
	}

	jsonData, err := json.Marshal(event)
	if err != nil {
		return "", fmt.Errorf("failed to marshal event: %w", err)
	}

	req, err := http.NewRequestWithContext(context.Background(), "POST", PagerDutyEventsURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusAccepted {
		return "", fmt.Errorf("PagerDuty API returned status %d: %s", resp.StatusCode, string(body))
	}

	var eventResponse EventResponse
	if err := json.Unmarshal(body, &eventResponse); err != nil {
		return "", fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return eventResponse.DedupKey, nil
}

func (c *client) ResolveIncident(incidentID string) error {
	// For resolving, we need to send a "resolve" event with the same dedup_key
	event := Event{
		RoutingKey:  c.routingKey,
		EventAction: "resolve",
		DedupKey:    incidentID, // incidentID should be the dedup_key from the original event
	}

	jsonData, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal resolve event: %w", err)
	}

	req, err := http.NewRequestWithContext(context.Background(), "POST", PagerDutyEventsURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create resolve request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send resolve request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusAccepted {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("PagerDuty API returned status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

func (c *client) GetIncidentID(dedupKey string) (string, error) {
	// To get incident ID from dedup key, you would need to use the REST API
	// This requires different authentication (API token) and different endpoint
	// For now, returning the dedupKey as it's often used interchangeably
	// In practice, you might want to implement this using the PagerDuty REST API v2
	return dedupKey, nil
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

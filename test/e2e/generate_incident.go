package osde2etests

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/google/uuid"
)

type PagerDutyClient interface {
	CreateSilentRequest(alertName, clusterID string) (string, error)
	GetIncidentID(dedupKey string) (string, error)
	ResolveIncident(incidentID string) error
}

type client struct {
	eventsURL     string
	apiURL        string
	routingKey    string
	authToken     string
	alertMappings map[string]string
	httpClient    *http.Client
}

func NewClient(routingKey, authToken string) PagerDutyClient {
	return &client{
		eventsURL:  "https://events.pagerduty.com/v2/enqueue",
		apiURL:     "https://api.pagerduty.com/incidents",
		routingKey: routingKey,
		authToken:  authToken,
		alertMappings: map[string]string{
			"ClusterHasGoneMissing":                         "cadtest has gone missing",
			"ClusterProvisioningDelay":                      "ClusterProvisioningDelay -",
			"ClusterMonitoringErrorBudgetBurnSRE":           "ClusterMonitoringErrorBudgetBurnSRE Critical (1)",
			"InsightsOperatorDown":                          "InsightsOperatorDown",
			"MachineHealthCheckUnterminatedShortCircuitSRE": "MachineHealthCheckUnterminatedShortCircuitSRE CRITICAL (1)",
			"ApiErrorBudgetBurn":                            "api-ErrorBudgetBurn k8sgpt test CRITICAL (1)",
		},
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}
}

type payload struct {
	Payload struct {
		Summary   string            `json:"summary"`
		Timestamp string            `json:"timestamp"`
		Severity  string            `json:"severity"`
		Source    string            `json:"source"`
		Details   map[string]string `json:"custom_details"`
	} `json:"payload"`
	RoutingKey  string `json:"routing_key"`
	EventAction string `json:"event_action"`
	DedupKey    string `json:"dedup_key"`
}

func (c *client) CreateSilentRequest(alertName, clusterID string) (string, error) {
	title, ok := c.alertMappings[alertName]
	if !ok {
		return "", fmt.Errorf("unknown alert name: %s", alertName)
	}

	dedupKey := generateUUID()

	now := time.Now().UTC().Format(time.RFC3339)
	p := payload{
		RoutingKey:  c.routingKey,
		EventAction: "trigger",
		DedupKey:    dedupKey,
	}
	p.Payload.Summary = title
	p.Payload.Timestamp = now
	p.Payload.Severity = "critical"
	p.Payload.Source = "cad-integration-testing"
	p.Payload.Details = map[string]string{
		"alertname":  alertName,
		"cluster_id": clusterID,
	}

	body, err := json.Marshal(p)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest("POST", c.eventsURL, bytes.NewBuffer(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %v", err)
	}

	if resp.StatusCode != http.StatusAccepted && resp.StatusCode != http.StatusOK {
		return "", errors.New("failed to trigger alert - RespBody : " + string(respBody))
	}

	// Sleep to give time for the incident to be indexed
	time.Sleep(2 * time.Second)

	return dedupKey, nil
}

func (c *client) GetIncidentID(dedupKey string) (string, error) {
	url := fmt.Sprintf("%s?incident_key=%s", c.apiURL, dedupKey)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Token token="+c.authToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var result struct {
		Incidents []struct {
			ID string `json:"id"`
		} `json:"incidents"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}

	if len(result.Incidents) == 0 {
		return "", errors.New("incident not found")
	}
	return result.Incidents[0].ID, nil
}

func (c *client) ResolveIncident(incidentID string) error {
	url := fmt.Sprintf("%s/%s", c.apiURL, incidentID)

	payload := map[string]interface{}{
		"incident": map[string]string{
			"type":   "incident_reference",
			"status": "resolved",
		},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("PUT", url, bytes.NewBuffer(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Token token="+c.authToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/vnd.pagerduty+json;version=2")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to resolve incident, status code: %d", resp.StatusCode)
	}

	return nil
}

func generateUUID() string {
	return uuid.New().String()
}

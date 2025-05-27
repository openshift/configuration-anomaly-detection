package utils

import (
	"context"
	"crypto/rand"
	"fmt"
	"time"

	sdk "github.com/PagerDuty/go-pagerduty"
)

const (
	AlertClusterHasGoneMissing                         = "ClusterHasGoneMissing"
	AlertClusterProvisioningDelay                      = "ClusterProvisioningDelay"
	AlertClusterMonitoringErrorBudgetBurnSRE           = "ClusterMonitoringErrorBudgetBurnSRE"
	AlertInsightsOperatorDown                          = "InsightsOperatorDown"
	AlertMachineHealthCheckUnterminatedShortCircuitSRE = "MachineHealthCheckUnterminatedShortCircuitSRE"
	AlertApiErrorBudgetBurn                            = "ApiErrorBudgetBurn"
)

func GetAlertTitle(alertName string) (string, error) {
	switch alertName {
	case AlertClusterHasGoneMissing:
		return "cadtest has gone missing", nil
	case AlertClusterProvisioningDelay:
		return "ClusterProvisioningDelay -", nil
	case AlertClusterMonitoringErrorBudgetBurnSRE:
		return "ClusterMonitoringErrorBudgetBurnSRE Critical (1)", nil
	case AlertInsightsOperatorDown:
		return "InsightsOperatorDown", nil
	case AlertMachineHealthCheckUnterminatedShortCircuitSRE:
		return "MachineHealthCheckUnterminatedShortCircuitSRE CRITICAL (1)", nil
	case AlertApiErrorBudgetBurn:
		return "api-ErrorBudgetBurn k8sgpt test CRITICAL (1)", nil
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
}

func NewClient(routingKey string) TestPagerDutyClient {
	return &client{
		routingKey: routingKey,
		apiClient:  sdk.NewClient(routingKey),
	}
}
func (c *client) CreateRequest(alertName, clusterID string) (string, error) {
	summary, err := GetAlertTitle(alertName)
	if err != nil {
		return "", err
	}
	event := sdk.V2Event{
		RoutingKey: c.routingKey,
		Action:     "trigger",
		DedupKey:   generateUUID(),
		Payload: &sdk.V2Payload{
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

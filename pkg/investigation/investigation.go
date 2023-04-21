// Package investigation contains base functions for investigations
package investigation

import (
	"fmt"

	"github.com/openshift/configuration-anomaly-detection/pkg/pagerduty"
)

// Investigation wraps all possible event types and serves as a parent class
// This enables the structure of cmd/investigate.go
// Implement only functions for those event types that are desired
// and are set on the corresponding webhook
// add missing event types you want to implement from this list
// https://support.pagerduty.com/docs/webhooks#supported-resources-and-event-types
// Important: If you add an event type that can return a different data field type
// update the webhook parsing in the pagerduty service accordingly
// https://developer.pagerduty.com/docs/db0fa8c8984fc-overview#event-data-types
type Investigation interface {
	Triggered() error
	Resolved() error
	// Reopened() (InvestigationOutput, error)
	// Escalated() (InvestigationOutput, error)
}

// Client is the investigation client
type Client struct {
	Investigation
}

var webhookMisconfigurationMsg = "Please review the webhook configuration and exclude or implement the event type."

// Triggered is the Client behavior in case the investigation does not implement event type Triggered
func (c *Client) Triggered() error {
	return fmt.Errorf("event type 'incident.triggered' is not implemented for this alert" + webhookMisconfigurationMsg)
}

// Resolved is the Client behavior in case the investigation does not implement event type Resolved
func (c *Client) Resolved() error {
	return fmt.Errorf("event type 'incident.resolved' is not implemented for this alert" + webhookMisconfigurationMsg)
}

// // Reopened is the Client behavior in case the investigation does not implement event type Reopened
// func (c *Client) Reopened() (InvestigationOutput, error) {
// 	return InvestigationOutput{}, fmt.Errorf("event type 'incident.reopened' is not implemented for this alert" + webhookMisconfigurationMsg)
// }

// // Escalated is the Client behavior in case the investigation does not implement event type Reopened
// func (c *Client) Escalated() (InvestigationOutput, error) {
// 	return InvestigationOutput{}, fmt.Errorf("event type 'incident.escalated' is not implemented for this alert" + webhookMisconfigurationMsg)
// }

// BuildAlertForLimitedSupportRemovalFailure populates the alert template that is used in case of failure to remove a limited support reason that was
// previously added by CAD
func BuildAlertForLimitedSupportRemovalFailure(lsErr error, internalClusterID string) pagerduty.NewAlert {
	// The alert description acts as a title for the resulting incident
	return pagerduty.NewAlert{
		Description: fmt.Sprintf("CAD is unable to remove a Limited Support reason from cluster %s", internalClusterID),
		Details: pagerduty.NewAlertDetails{
			ClusterID:  internalClusterID,
			Error:      lsErr.Error(),
			Resolution: "CAD has been unable to remove a Limited Support reason from this cluster. The cluster needs to be manually reviewed and have any appropriate Limited Support reasons removed. After corrective actions have been taken, this alert must be manually resolved.",
			SOP:        "https://github.com/openshift/ops-sop/blob/master/v4/alerts/CAD_ErrorRemovingLSReason.md",
		},
	}
}

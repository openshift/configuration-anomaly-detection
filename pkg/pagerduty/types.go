package pagerduty

// AlertDetails exposes the required info we need from an alert
type AlertDetails struct {
	ID        string
	ClusterID string // This can be internal or external ID
}

// NewAlertCustomDetails is a format for the alert details shown in the pagerduty incident
type NewAlertCustomDetails struct {
	ClusterID  string `json:"Cluster ID"`
	Error      string `json:"Error"`
	Resolution string `json:"Resolution"`
	SOP        string `json:"SOP"`
}

// NewAlert is a type for alerts to create on pagerduty
type NewAlert struct {
	// The alert description acts as a title for the resulting incident
	Description string
	Details     NewAlertCustomDetails
}

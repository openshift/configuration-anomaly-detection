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

// FiringAlert represents a single firing alert from the firing_json PagerDuty custom detail field.
type FiringAlert struct {
	Labels      map[string]string `json:"labels"`
	Annotations map[string]string `json:"annotations"`
	StartsAt    string            `json:"startsAt"`
	EndsAt      string            `json:"endsAt"`
}

// FiringAlertsResult holds the result of parsing firing_json from all PD alerts.
type FiringAlertsResult struct {
	Alerts       []FiringAlert
	RawFallbacks []string
	Partial      bool
}

// AlertCustomDetails holds the known custom detail fields from a PD alert's Body["details"].
type AlertCustomDetails struct {
	Link        string
	NumFiring   string
	NumResolved string
	OCMLink     string
	Region      string
	Dashboard   string
}

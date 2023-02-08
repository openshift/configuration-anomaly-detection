// Package pagerduty contains pagerduty related functionality
package pagerduty

// Alert exposes the required info we need from an alert
type Alert struct {
	ID         string
	ExternalID string
}

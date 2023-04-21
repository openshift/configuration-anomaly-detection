// Package pagerduty contains wrappers for pagerduty api calls
package pagerduty

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"time"

	sdk "github.com/PagerDuty/go-pagerduty"
	"gopkg.in/yaml.v2"
)

const (
	// InvalidInputParamsErrorCode is exposed from the PagerDuty's API error response, used to distinguish between different error codes.
	// for more details see https://developer.pagerduty.com/docs/ZG9jOjExMDI5NTYz-errors#pagerduty-error-codes
	InvalidInputParamsErrorCode = 2001
	// pagerDutyTimeout is the chosen timeout for api requests, can be changed later
	pagerDutyTimeout = time.Second * 30
	// CADEmailAddress is the email address for the 'Configuration-Anomaly-Detection' PagerDuty User
	CADEmailAddress = "sd-sre-platform+pagerduty-configuration-anomaly-detection-agent@redhat.com"
	// CADIntegrationName is the name of the PD integration used to escalate alerts to Primary.
	CADIntegrationName = "Dead Man's Snitch"
	// possible event types of the incident
	// https://support.pagerduty.com/docs/webhooks#supported-resources-and-event-types
	// add others when needed

	// IncidentResolved is an incident event type
	IncidentResolved = "incident.resolved"
	// IncidentTriggered is an incident event type
	IncidentTriggered = "incident.triggered"
	// IncidentEscalated is an incident event type
	IncidentEscalated = "incident.escalated"
	// IncidentReopened is an incident event type
	IncidentReopened = "incident.reopened"
)

// Client will hold all the required fields for any Client Operation
type Client struct {
	// c is the PagerDuty client
	sdkClient *sdk.Client
	// currentUserEmail is the current logged-in user's email
	currentUserEmail string
	// onCallEscalationPolicy
	onCallEscalationPolicy string
	// silentEscalationPolicy
	silentEscalationPolicy string
	// parsedPayload holds some of the webhook payloads fields ( add more if needed )
	parsedPayload WebhookPayload
	// externalClusterID ( only gets initialized after the first GetExternalClusterID call )
	externalClusterID *string
}

// WebhookPayload is a struct to fill with information we parse out of the webhook
// The data field schema can differ depending on the event type that triggered the webhook.
// https://developer.pagerduty.com/docs/db0fa8c8984fc-overview#event-data-types
// We only use event types that return a webhook with 'incident' as data field for now.
type WebhookPayload struct {
	Event struct {
		EventType string `json:"event_type"`
		Data      struct {
			Service struct {
				ServiceID string `json:"id"`
				Summary   string `json:"summary"`
			} `json:"service"`
			Title      string `json:"title"`
			IncidentID string `json:"id"`
		} `json:"data"`
	} `json:"event"`
}

// Unmarshal wraps the json.Unmarshal to do some sanity checks
// it may be worth to do a proper schema and validation
func (c *WebhookPayload) Unmarshal(data []byte) error {
	err := json.Unmarshal(data, c)
	if err != nil {
		return err
	}

	if c.Event.EventType == "" {
		return UnmarshalErr{Err: fmt.Errorf("payload is missing field: event_type")}
	}
	if c.Event.Data.Service.ServiceID == "" {
		return UnmarshalErr{Err: fmt.Errorf("payload is missing field: ServiceID")}
	}
	if c.Event.Data.Service.Summary == "" {
		return UnmarshalErr{Err: fmt.Errorf("payload is missing field: Summary")}
	}
	if c.Event.Data.Title == "" {
		return UnmarshalErr{Err: fmt.Errorf("payload is missing field: Title")}
	}
	if c.Event.Data.IncidentID == "" {
		return UnmarshalErr{Err: fmt.Errorf("payload is missing field: IncidentID")}
	}
	return nil
}

// NewWithToken is similar to New, but you only need to supply to authentication token to start
// The token can be created using the docs https://support.pagerduty.com/docs/api-access-keys#section-generate-a-user-token-rest-api-key
func NewWithToken(escalationPolicy string, silentPolicy string, webhookPayload []byte, authToken string, options ...sdk.ClientOptions) (Client, error) {
	parsedPayload := WebhookPayload{}
	err := parsedPayload.Unmarshal(webhookPayload)
	if err != nil {
		return Client{}, UnmarshalErr{Err: err}
	}
	c := Client{
		sdkClient:              sdk.NewClient(authToken, options...),
		onCallEscalationPolicy: escalationPolicy,
		silentEscalationPolicy: silentPolicy,
		parsedPayload:          parsedPayload,
	}
	return c, nil
}

// GetEventType returns the event type of the webhook
func (c *Client) GetEventType() string {
	return c.parsedPayload.Event.EventType
}

// GetServiceID returns the event type of the webhook
func (c *Client) GetServiceID() string {
	return c.parsedPayload.Event.Data.Service.ServiceID
}

// GetServiceName returns the event type of the webhook
func (c *Client) GetServiceName() string {
	return c.parsedPayload.Event.Data.Service.Summary
}

// GetTitle returns the event type of the webhook
func (c *Client) GetTitle() string {
	return c.parsedPayload.Event.Data.Title
}

// GetIncidentID returns the event type of the webhook
func (c *Client) GetIncidentID() string {
	return c.parsedPayload.Event.Data.IncidentID
}

// GetOnCallEscalationPolicy returns the set on call escalation policy
func (c *Client) GetOnCallEscalationPolicy() string {
	return c.onCallEscalationPolicy
}

// GetSilentEscalationPolicy returns the set policy for silencing alerts
func (c *Client) GetSilentEscalationPolicy() string {
	return c.silentEscalationPolicy
}

// RetrieveExternalClusterID returns the externalClusterID. The cluster id is not on the payload so the first time it is called it will
// retrieve the externalClusterID from pagerduty, and update the client.
func (c *Client) RetrieveExternalClusterID() (string, error) {

	// Only do the api call to pagerduty once
	if c.externalClusterID != nil {
		return *c.externalClusterID, nil
	}

	incidentID := c.GetIncidentID()

	// pulls alerts from pagerduty
	alerts, err := c.GetAlerts()
	if err != nil {
		return "", fmt.Errorf("could not retrieve alerts for incident '%s': %w", incidentID, err)
	}

	// there should be only one alert
	if len(alerts) > 1 {
		fmt.Printf("warning: there should be only one alert on each incident, taking the first result of incident: %s", incidentID)
	}

	for _, a := range alerts {
		// that one alert should have a valid ExternalID
		if a.ExternalID != "" {
			c.externalClusterID = &a.ExternalID
			return *c.externalClusterID, nil
		}
	}

	return "", fmt.Errorf("could not find an ExternalID in the given alerts")
}

// MoveToEscalationPolicy will move the incident's EscalationPolicy to the new EscalationPolicy
func (c *Client) MoveToEscalationPolicy(escalationPolicyID string) error {
	fmt.Printf("Moving to escalation policy: %s\n", escalationPolicyID)

	o := []sdk.ManageIncidentsOptions{
		{
			ID: c.GetIncidentID(),
			EscalationPolicy: &sdk.APIReference{
				Type: "escalation_policy_reference",
				ID:   escalationPolicyID,
			},
		},
	}

	err := c.updateIncident(o)
	if err != nil {
		if strings.Contains(err.Error(), "Incident Already Resolved") {
			fmt.Printf("Skipped moving alert to escalation policy '%s', alert is already resolved.\n", escalationPolicyID)
			return nil
		}
		return fmt.Errorf("could not update the escalation policy: %w", err)
	}
	return nil
}

// AssignToUser will assign the incident to the provided user
// This is currently not needed by anything
func (c *Client) AssignToUser(userID string) error {
	o := []sdk.ManageIncidentsOptions{{
		ID: c.GetIncidentID(),
		Assignments: []sdk.Assignee{{
			Assignee: sdk.APIObject{
				Type: "user_reference",
				ID:   userID,
			},
		}},
	}}
	err := c.updateIncident(o)
	if err != nil {
		return fmt.Errorf("could not assign to user: %w", err)
	}
	return nil
}

// AcknowledgeIncident will acknowledge an incident
// This is currently not needed by anything
func (c *Client) AcknowledgeIncident() error {
	o := []sdk.ManageIncidentsOptions{
		{
			ID:     c.GetIncidentID(),
			Status: "acknowledged",
		},
	}
	err := c.updateIncident(o)
	if err != nil {
		return fmt.Errorf("could not acknowledge the incident: %w", err)
	}
	return nil
}

// updateIncident will run the API call to PagerDuty for updating the incident, and handle the error codes that arise
// the reason we send an array instead of a single item is to be compatible with the sdk
// the customErrorString is a nice touch so when the error bubbles up it's clear who called it (if it's an unknown error)
func (c *Client) updateIncident(o []sdk.ManageIncidentsOptions) error {
	ctx, cancel := context.WithTimeout(context.Background(), pagerDutyTimeout)
	defer cancel()
	_, err := c.sdkClient.ManageIncidentsWithContext(ctx, c.currentUserEmail, o)

	sdkErr := sdk.APIError{}
	if errors.As(err, &sdkErr) {
		commonErr := commonErrorHandling(err, sdkErr)
		if commonErr != nil {
			return commonErr
		}
	}

	if err != nil {
		return err
	}

	return nil
}

// AddNote will add a note to an incident
func (c *Client) AddNote(noteContent string) error {
	fmt.Println("Attaching Note...")
	sdkNote := sdk.IncidentNote{
		Content: noteContent,
	}
	_, err := c.sdkClient.CreateIncidentNoteWithContext(context.TODO(), c.GetIncidentID(), sdkNote)

	sdkErr := sdk.APIError{}
	if errors.As(err, &sdkErr) {
		commonErr := commonErrorHandling(err, sdkErr)
		if commonErr != nil {
			return commonErr
		}
		if sdkErr.StatusCode == http.StatusNotFound {
			// this case can happen if the incidentID is not a valid incident (like a number prepended with zeroes)
			return IncidentNotFoundErr{Err: err}
		}
	}

	if err != nil {
		return err
	}

	return nil
}

// CreateNewAlert triggers an alert using the Deadmanssnitch integration for the given service.
// If the provided service does not have a DMS integration, an error is returned
func (c *Client) CreateNewAlert(newAlert NewAlert, serviceID string) error {
	service, err := c.sdkClient.GetServiceWithContext(context.TODO(), serviceID, &sdk.GetServiceOptions{})
	if err != nil {
		return ServiceNotFoundErr{Err: err}
	}

	integration, err := c.getCADIntegrationFromService(service)
	if err != nil {
		return IntegrationNotFoundErr{Err: err}
	}

	// Current DMS integration requires us to use v1 events
	event := sdk.Event{
		ServiceKey:  integration.IntegrationKey,
		Type:        "trigger",
		Description: newAlert.Description,
		Details:     newAlert.Details,
		Client:      CADEmailAddress,
	}

	response, err := sdk.CreateEventWithHTTPClient(event, c.sdkClient.HTTPClient)
	if err != nil {
		return CreateEventErr{Err: fmt.Errorf("%w. Full response: %#v", err, response)}
	}
	fmt.Printf("Alert has been created %s\n", newAlert.Description)
	return nil
}

// getCADIntegrationFromService retrieves the PagerDuty integration used by CAD from the given service.
// If the integration CAD expects is not found, an error is returned
func (c *Client) getCADIntegrationFromService(service *sdk.Service) (sdk.Integration, error) {
	// For some reason the .Integrations array in the Service object does not contain any usable data,
	// aside from the ID, so we have to re-grab each integration separately to examine them
	for _, brokenIntegration := range service.Integrations {
		realIntegration, err := c.sdkClient.GetIntegrationWithContext(context.TODO(), service.ID, brokenIntegration.ID, sdk.GetIntegrationOptions{})
		if err != nil {
			return sdk.Integration{}, fmt.Errorf("failed to retrieve integration '%s' for service '%s': %w", brokenIntegration.ID, service.ID, err)
		}
		if realIntegration.Name == CADIntegrationName {
			return *realIntegration, nil
		}
	}
	return sdk.Integration{}, fmt.Errorf("no integration '%s' exists for service '%s'", CADIntegrationName, service.Name)
}

// GetAlerts will retrieve the alerts for a specific incident
func (c *Client) GetAlerts() ([]Alert, error) {
	ctx, cancel := context.WithTimeout(context.Background(), pagerDutyTimeout)
	defer cancel()

	o := sdk.ListIncidentAlertsOptions{}

	alerts, err := c.sdkClient.ListIncidentAlertsWithContext(ctx, c.GetIncidentID(), o)

	sdkErr := sdk.APIError{}
	if errors.As(err, &sdkErr) {
		commonErr := commonErrorHandling(err, sdkErr)
		if commonErr != nil {
			return nil, commonErr
		}
		if sdkErr.StatusCode == http.StatusNotFound {
			// this case can happen if the incidentID is not a valid incident (like a number prepended with zeroes)
			return nil, IncidentNotFoundErr{Err: err}
		}
	}
	if err != nil {
		return nil, err
	}

	res := []Alert{}
	for _, alert := range alerts.Alerts {
		localAlert, err := c.toLocalAlert(alert)
		if err != nil {
			return nil, fmt.Errorf("could not convert alert toLocalAlert: %w", err)
		}
		res = append(res, localAlert)
	}
	return res, nil
}

// extractExternalIDFromAlertBody extracts from an Alert body until an external ID
// the function is a member function but doesn't use any of the other functions / types in the PagerDuty struct
func extractExternalIDFromAlertBody(data map[string]interface{}) (string, error) {
	var err error

	externalBody, err := extractNotesFromBody(data)
	if err != nil {
		return "", fmt.Errorf("cannot marshal externalCHGMAlertBody: %w", err)
	}

	if externalBody == "" {
		return "", AlertBodyDoesNotHaveNotesFieldErr{}
	}

	internalBody := internalCHGMAlertBody{}

	err = yaml.Unmarshal([]byte(externalBody), &internalBody)
	if err != nil {
		// TODO: add errcheck for this specific error
		externalBody = strings.ReplaceAll(externalBody, `\n`, "\n")
		err = yaml.Unmarshal([]byte(externalBody), &internalBody)
		if err != nil {
			return "", NotesParseErr{Err: err}
		}
	}

	if internalBody.ClusterID == "" {
		return "", AlertNotesDoesNotHaveClusterIDFieldErr{}
	}

	return internalBody.ClusterID, nil
}

// extractNotesFromBody will extract from map[string]interface{} the '.details.notes' while doing type checks
// this is better than a third party as it is better maintained and required less dependencies
func extractNotesFromBody(body map[string]interface{}) (string, error) {
	var ok bool
	_, ok = body["details"]
	if !ok {
		return "", AlertBodyExternalParseErr{FailedProperty: ".details"}
	}

	details, ok := body["details"].(map[string]interface{})
	if !ok {
		err := AlertBodyExternalCastErr{
			FailedProperty:     ".details",
			ExpectedType:       "map[string]interface{}",
			ActualType:         reflect.TypeOf(body["details"]).String(),
			ActualBodyResource: fmt.Sprintf("%v", body["details"]),
		}
		return "", err
	}

	notesInterface, ok := details["notes"]
	if !ok {
		return "", AlertBodyExternalParseErr{FailedProperty: ".details.notes"}
	}

	notes, ok := notesInterface.(string)
	if !ok {
		err := AlertBodyExternalCastErr{
			FailedProperty:     ".details.notes",
			ExpectedType:       "string",
			ActualType:         reflect.TypeOf(details["notes"]).String(),
			ActualBodyResource: fmt.Sprintf("%v", details["notes"]),
		}
		return "", err
	}

	return notes, nil
}

// internalCHGMAlertBody is a struct for manipulating CHGM from the note until the ClusterID
type internalCHGMAlertBody struct {
	// ClusterID in the ExternalId that the notes holds
	ClusterID string `yaml:"cluster_id"`
}

// toLocalAlert will convert an sdk.IncidentAlert to a local Alert resource
func (c *Client) toLocalAlert(sdkAlert sdk.IncidentAlert) (Alert, error) {
	externalID, err := extractExternalIDFromAlertBody(sdkAlert.Body)
	if err != nil {
		return Alert{}, fmt.Errorf("could not ExtractIDFromCHGM: %w", err)
	}
	alert := Alert{
		ID:         sdkAlert.APIObject.ID,
		ExternalID: externalID,
	}
	return alert, nil
}

// commonErrorHandling will take a sdk.APIError and check it on common known errors.
// if found the boolean will be false (not ok and should raise)
func commonErrorHandling(err error, sdkErr sdk.APIError) error {
	switch sdkErr.StatusCode {
	case http.StatusUnauthorized:
		return InvalidTokenErr{Err: err}
	case http.StatusBadRequest:
		isAnInvalidInputErr := sdkErr.APIError.Valid &&
			sdkErr.APIError.ErrorObject.Code == InvalidInputParamsErrorCode
		if isAnInvalidInputErr {
			return InvalidInputParamsErr{Err: err}
		}
	}
	return nil
}

// SilenceAlert silences the alert by assigning the "Silent Test" escalation policy
func (c *Client) SilenceAlert() error {
	return c.MoveToEscalationPolicy(c.GetSilentEscalationPolicy())
}

// SilenceAlertWithNote annotates the PagerDuty alert with the given notes and silences it by
// assigning the "Silent Test" escalation policy
func (c *Client) SilenceAlertWithNote(notes string) error {
	return c.addNoteAndEscalate(notes, c.GetSilentEscalationPolicy())
}

// EscalateAlert escalates the alert to the on call escalation policy
func (c *Client) EscalateAlert() error {
	return c.MoveToEscalationPolicy(c.GetOnCallEscalationPolicy())
}

// EscalateAlertWithNote annotates the PagerDuty alert with the given notes and escalates it by
// assigning to the on call escalation policy
func (c *Client) EscalateAlertWithNote(notes string) error {
	return c.addNoteAndEscalate(notes, c.GetOnCallEscalationPolicy())
}

// addNoteAndEscalate attaches notes to an incident and moves it to the given escalation policy
func (c *Client) addNoteAndEscalate(notes, escalationPolicy string) error {
	if notes != "" {
		err := c.AddNote(notes)
		if err != nil {
			return fmt.Errorf("failed to attach notes to CHGM incident: %w", err)
		}
	}
	return c.MoveToEscalationPolicy(escalationPolicy)
}

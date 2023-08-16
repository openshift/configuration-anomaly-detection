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

	"github.com/openshift/configuration-anomaly-detection/pkg/logging"

	"github.com/PagerDuty/go-pagerduty"
	sdk "github.com/PagerDuty/go-pagerduty"
)

//go:generate mockgen --build_flags=--mod=readonly -source $GOFILE -destination ./mock/pagerdutymock.go -package pdmock

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

// Client is the interface exposing pagerduty functions
type Client interface {
	SilenceAlertWithNote(notes string) error
	AddNote(notes string) error
	CreateNewAlert(newAlert NewAlert, serviceID string) error
	GetServiceID() string
	EscalateAlertWithNote(notes string) error
	EscalateAlert() error
}

// SdkClient will hold all the required fields for any SdkClient Operation
type SdkClient struct {
	// c is the PagerDuty client
	sdkClient *sdk.Client
	// onCallEscalationPolicy
	onCallEscalationPolicy string
	// silentEscalationPolicy
	silentEscalationPolicy string
	// incidentData
	incidentData *IncidentData
	// clusterID ( only gets initialized after the first GetclusterID call )
	clusterID *string
}

// IncidentData represents the data contained in an incident
type IncidentData struct {
	IncidentEventType string // e.g. incident.Triggered
	IncidentTitle     string // e.g. InfraNodesNeedResizingSRE CRITICAL (1)
	IncidentID        string // e.g. Q2I4AV3ZURABC
	IncidentRef       string // e.g. https://<>.pagerduty.com/incidents/Q2I4AV3ZURABC
	ServiceID         string // e.g. PCH1XGB
	ServiceSummary    string // e.g. prod-deadmanssnitch
}

func (c *SdkClient) initializeIncidentData(payload []byte) (*IncidentData, error) {
	incidentData := &IncidentData{}

	logging.Debug("Attempting to unmarshal webhookV3...")
	unmarshalled, err := unmarshalWebhookV3(payload)
	if err == nil {
		incidentData.IncidentEventType = unmarshalled.Event.EventType
		incidentData.IncidentTitle = unmarshalled.Event.Data.Title
		incidentData.IncidentID = unmarshalled.Event.Data.IncidentID
		incidentData.IncidentRef = unmarshalled.Event.Data.IncidentRef
		incidentData.ServiceID = unmarshalled.Event.Data.Service.ServiceID
		incidentData.ServiceSummary = unmarshalled.Event.Data.Service.Summary
		return incidentData, nil
	}

	logging.Infof("Could not unmarshal as pagerduty webhook V3: %s. re-trying to unmarshall for different payload types...", err.Error())

	logging.Debug("Attempting to unmarshal EventOrchestrationWebhook...")
	unmarshalled2, err := unmarshalEventOrchestrationWebhook(payload)
	if err != nil {
		return nil, err
	}

	fetchedIncident, err := c.sdkClient.GetIncidentWithContext(context.TODO(), unmarshalled2.PDMetadata.Incident.ID)
	if err != nil {
		return nil, err
	}

	incidentData.IncidentEventType = fetchedIncident.Type
	incidentData.IncidentTitle = fetchedIncident.Title
	incidentData.IncidentID = fetchedIncident.ID
	incidentData.IncidentRef = fetchedIncident.HTMLURL
	incidentData.ServiceID = fetchedIncident.Service.ID
	incidentData.ServiceSummary = fetchedIncident.Service.Summary
	return incidentData, nil
}

// webhookV3 is a struct to fill with information we parse out of the webhook
// The data field schema can differ depending on the event type that triggered the webhook.
// https://developer.pagerduty.com/docs/db0fa8c8984fc-overview#event-data-types
// We only use event types that return a webhook with 'incident' as data field for now.
type webhookV3 struct {
	Event struct {
		EventType string `json:"event_type"`
		Data      struct {
			Service struct {
				ServiceID string `json:"id"`
				Summary   string `json:"summary"`
			} `json:"service"`
			Title       string `json:"title"`
			IncidentID  string `json:"id"`
			IncidentRef string `json:"html_url"`
		} `json:"data"`
	} `json:"event"`
}

// unmarshalWebhookV3 unmarshals a webhook v3 payload
// https://support.pagerduty.com/docs/webhooks
func unmarshalWebhookV3(data []byte) (*webhookV3, error) {
	unmarshalled := &webhookV3{}

	err := json.Unmarshal(data, unmarshalled)
	if err != nil {
		return nil, err
	}

	if unmarshalled.Event.EventType == "" {
		return nil, UnmarshalError{Err: fmt.Errorf("payload is missing field: event_type")}
	}
	if unmarshalled.Event.Data.Service.ServiceID == "" {
		return nil, UnmarshalError{Err: fmt.Errorf("payload is missing field: ServiceID")}
	}
	if unmarshalled.Event.Data.Service.Summary == "" {
		return nil, UnmarshalError{Err: fmt.Errorf("payload is missing field: Summary")}
	}
	if unmarshalled.Event.Data.Title == "" {
		return nil, UnmarshalError{Err: fmt.Errorf("payload is missing field: Title")}
	}
	if unmarshalled.Event.Data.IncidentID == "" {
		return nil, UnmarshalError{Err: fmt.Errorf("payload is missing field: IncidentID")}
	}
	if unmarshalled.Event.Data.IncidentRef == "" {
		return nil, UnmarshalError{Err: fmt.Errorf("payload is missing field: IncidentRef")}
	}
	return unmarshalled, nil
}

// eventOrchestrationWebhook is a struct respresentation of a pagerduty event orchestration webhook payload
// e.g. {"__pd_metadata":{"incident":{"id":"Q0OGN8S5WIM0FX"}}}
type eventOrchestrationWebhook struct {
	PDMetadata struct {
		Incident struct {
			ID string `json:"id"`
		} `json:"incident"`
	} `json:"__pd_metadata"`
}

func unmarshalEventOrchestrationWebhook(data []byte) (*eventOrchestrationWebhook, error) {
	unmarshalled := &eventOrchestrationWebhook{}
	err := json.Unmarshal(data, unmarshalled)
	if err != nil {
		return nil, err
	}

	if unmarshalled.PDMetadata.Incident.ID == "" {
		return nil, UnmarshalError{Err: fmt.Errorf("payload is missing field: ID")}
	}
	return unmarshalled, nil
}

// NewWithToken initializes a new SdkClient
// The token can be created using the docs https://support.pagerduty.com/docs/api-access-keys#section-generate-a-user-token-rest-api-key
func NewWithToken(escalationPolicy string, silentPolicy string, webhookPayload []byte, authToken string, options ...sdk.ClientOptions) (*SdkClient, error) {
	c := SdkClient{
		sdkClient: sdk.NewClient(authToken, options...),

		// All three of the below should be moved out of the SDK.
		// These are static values that should not be part of an sdk
		onCallEscalationPolicy: escalationPolicy,
		silentEscalationPolicy: silentPolicy,
		incidentData:           &IncidentData{},
	}

	// We first need to initialize the client before we can use initializeIncidentData
	// as all our calls to the sdk are wrapped within it.
	incidentData, err := c.initializeIncidentData(webhookPayload)
	if err != nil {
		return nil, err
	}

	c.SetIncidentData(incidentData)

	return &c, nil
}

// SetIncidentData sets the Client's incidentData
func (c *SdkClient) SetIncidentData(incidentData *IncidentData) {
	c.incidentData = incidentData
}

// GetEventType returns the event type of the webhook
func (c *SdkClient) GetEventType() string {
	return c.incidentData.IncidentEventType
}

// GetServiceID returns the event type of the webhook
func (c *SdkClient) GetServiceID() string {
	return c.incidentData.ServiceID
}

// GetServiceName returns the event type of the webhook
func (c *SdkClient) GetServiceName() string {
	return c.incidentData.ServiceSummary
}

// GetTitle returns the event type of the webhook
func (c *SdkClient) GetTitle() string {
	return c.incidentData.IncidentTitle
}

// GetIncidentID returns the event type of the webhook
func (c *SdkClient) GetIncidentID() string {
	return c.incidentData.IncidentID
}

// GetOnCallEscalationPolicy returns the set on call escalation policy
func (c *SdkClient) GetOnCallEscalationPolicy() string {
	return c.onCallEscalationPolicy
}

// GetSilentEscalationPolicy returns the set policy for silencing alerts
func (c *SdkClient) GetSilentEscalationPolicy() string {
	return c.silentEscalationPolicy
}

// GetIncidentRef returns a link to the pagerduty incident
func (c *SdkClient) GetIncidentRef() string {
	return c.incidentData.IncidentRef
}

// RetrieveClusterID returns the clusterID for the current alert context of the SdkClient.
// The cluster id is not on the payload so the first time it is called it will
// retrieve the clusterID from pagerduty, and update the client.
func (c *SdkClient) RetrieveClusterID() (string, error) {
	// Only do the api call to pagerduty once
	if c.clusterID != nil {
		return *c.clusterID, nil
	}

	incidentID := c.GetIncidentID()

	alerts, err := c.GetAlertsForIncident(incidentID)
	if err != nil {
		return "", err
	}

	alertDetails, err := c.GetAlertListDetails(alerts)
	if err != nil {
		return "", err
	}

	// there should be only one alert
	if len(alertDetails) > 1 {
		logging.Warnf("There should be only one alert on each incident, taking the first result of incident: %s", incidentID)
	}

	for _, a := range alertDetails {
		a := a
		// that one alert should have a valid clusterID
		if a.ClusterID != "" {
			c.clusterID = &a.ClusterID
			return *c.clusterID, nil
		}
	}

	return "", fmt.Errorf("could not find a clusterID in the given alerts")
}

// MoveToEscalationPolicy will move the incident's EscalationPolicy to the new EscalationPolicy
func (c *SdkClient) MoveToEscalationPolicy(escalationPolicyID string) error {
	logging.Infof("Moving to escalation policy: %s", escalationPolicyID)

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
			logging.Infof("Skipped moving alert to escalation policy '%s', alert is already resolved.", escalationPolicyID)
			return nil
		}
		return fmt.Errorf("could not update the escalation policy: %w", err)
	}
	return nil
}

// AssignToUser will assign the incident to the provided user
// This is currently not needed by anything
func (c *SdkClient) AssignToUser(userID string) error {
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
func (c *SdkClient) AcknowledgeIncident() error {
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
func (c *SdkClient) updateIncident(o []sdk.ManageIncidentsOptions) error {
	ctx, cancel := context.WithTimeout(context.Background(), pagerDutyTimeout)
	defer cancel()
	_, err := c.sdkClient.ManageIncidentsWithContext(ctx, CADEmailAddress, o)

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

// AddNote will add a note to the incident the client was initialized with
func (c *SdkClient) AddNote(noteContent string) error {
	return c.AddNoteToIncident(c.incidentData.IncidentID, noteContent)
}

// AddNoteToIncident will add a note to an incident
func (c *SdkClient) AddNoteToIncident(incidentID string, noteContent string) error {
	logging.Info("Attaching Note...")
	sdkNote := sdk.IncidentNote{
		Content: noteContent,
	}
	_, err := c.sdkClient.CreateIncidentNoteWithContext(context.TODO(), incidentID, sdkNote)

	sdkErr := sdk.APIError{}
	if errors.As(err, &sdkErr) {
		commonErr := commonErrorHandling(err, sdkErr)
		if commonErr != nil {
			return commonErr
		}
		if sdkErr.StatusCode == http.StatusNotFound {
			// this case can happen if the incidentID is not a valid incident (like a number prepended with zeroes)
			return IncidentNotFoundError{Err: err}
		}
	}

	if err != nil {
		return err
	}

	return nil
}

// CreateNewAlert triggers an alert using the Deadmanssnitch integration for the given service.
// If the provided service does not have a DMS integration, an error is returned
func (c *SdkClient) CreateNewAlert(newAlert NewAlert, serviceID string) error {
	service, err := c.sdkClient.GetServiceWithContext(context.TODO(), serviceID, &sdk.GetServiceOptions{})
	if err != nil {
		return ServiceNotFoundError{Err: err}
	}

	integration, err := c.getCADIntegrationFromService(service)
	if err != nil {
		return IntegrationNotFoundError{Err: err}
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
		return CreateEventError{Err: fmt.Errorf("%w. Full response: %#v", err, response)}
	}
	logging.Infof("Alert has been created %s", newAlert.Description)
	return nil
}

// getCADIntegrationFromService retrieves the PagerDuty integration used by CAD from the given service.
// If the integration CAD expects is not found, an error is returned
func (c *SdkClient) getCADIntegrationFromService(service *sdk.Service) (sdk.Integration, error) {
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

// GetAlertsForIncident gets all alerts that are part of an incident
func (c *SdkClient) GetAlertsForIncident(incidentID string) (*[]sdk.IncidentAlert, error) {
	ctx, cancel := context.WithTimeout(context.Background(), pagerDutyTimeout)
	defer cancel()

	o := sdk.ListIncidentAlertsOptions{}

	listIncidentAlertsResponse, err := c.sdkClient.ListIncidentAlertsWithContext(ctx, incidentID, o)

	sdkErr := sdk.APIError{}
	if errors.As(err, &sdkErr) {
		commonErr := commonErrorHandling(err, sdkErr)
		if commonErr != nil {
			return nil, commonErr
		}
		if sdkErr.StatusCode == http.StatusNotFound {
			// this case can happen if the incidentID is not a valid incident (like a number prepended with zeroes)
			return nil, IncidentNotFoundError{Err: err}
		}
	}
	if err != nil {
		return nil, err
	}
	return &listIncidentAlertsResponse.Alerts, nil
}

// GetAlertListDetails will retrieve the required details for a list of alerts and return an array of alertDetails
// in the same order
func (c *SdkClient) GetAlertListDetails(alertList *[]sdk.IncidentAlert) ([]AlertDetails, error) {
	res := []AlertDetails{}
	for _, alert := range *alertList {
		alertDetails, err := extractAlertDetails(alert)
		if err != nil {
			return nil, fmt.Errorf("could not extract alert details from alert '%s': %w", alert.ID, err)
		}
		res = append(res, alertDetails)
	}
	return res, nil
}

func extractClusterIDFromAlertBody(data map[string]interface{}) (string, error) {
	var ok bool
	_, ok = data["details"]
	if !ok {
		return "", AlertBodyExternalParseError{FailedProperty: ".details"}
	}

	details, ok := data["details"].(map[string]interface{})
	if !ok {
		err := AlertBodyExternalCastError{
			FailedProperty:     ".details",
			ExpectedType:       "map[string]interface{}",
			ActualType:         reflect.TypeOf(data["details"]).String(),
			ActualBodyResource: fmt.Sprintf("%v", data["details"]),
		}
		return "", err
	}

	clusterIDInterface, ok := details["cluster_id"]
	if !ok {
		return "", AlertBodyExternalParseError{FailedProperty: ".details.cluster_id"}
	}

	clusterID, ok := clusterIDInterface.(string)
	if !ok {
		err := AlertBodyExternalCastError{
			FailedProperty:     ".details.cluster_id",
			ExpectedType:       "string",
			ActualType:         reflect.TypeOf(details["cluster_id"]).String(),
			ActualBodyResource: fmt.Sprintf("%v", details["cluster_id"]),
		}
		return "", err
	}

	return clusterID, nil
}

// extractAlertDetails will extract required details from a sdk.IncidentAlert
func extractAlertDetails(sdkAlert sdk.IncidentAlert) (AlertDetails, error) {
	logging.Debugf("Extracting clusterID from alert body: %s", sdkAlert.Body)
	clusterID, err := extractClusterIDFromAlertBody(sdkAlert.Body)
	if err != nil {
		return AlertDetails{}, fmt.Errorf("failed to extractClusterIDFromAlertBody: %w", err)
	}

	alertDetails := AlertDetails{
		ID:        sdkAlert.APIObject.ID,
		ClusterID: clusterID,
	}
	return alertDetails, nil
}

// commonErrorHandling will take a sdk.APIError and check it on common known errors.
// if found the boolean will be false (not ok and should raise)
func commonErrorHandling(err error, sdkErr sdk.APIError) error {
	switch sdkErr.StatusCode {
	case http.StatusUnauthorized:
		return InvalidTokenError{Err: err}
	case http.StatusBadRequest:
		isAnInvalidInputErr := sdkErr.APIError.Valid &&
			sdkErr.APIError.ErrorObject.Code == InvalidInputParamsErrorCode
		if isAnInvalidInputErr {
			return InvalidInputParamsError{Err: err}
		}
	}
	return nil
}

// SilenceAlert silences the alert by assigning the "Silent Test" escalation policy
func (c *SdkClient) SilenceAlert() error {
	return c.MoveToEscalationPolicy(c.GetSilentEscalationPolicy())
}

// SilenceAlertWithNote annotates the PagerDuty alert with the given notes and silences it by
// assigning the "Silent Test" escalation policy
func (c *SdkClient) SilenceAlertWithNote(notes string) error {
	return c.addNoteAndEscalate(notes, c.GetSilentEscalationPolicy())
}

// EscalateAlert escalates the alert to the on call escalation policy
func (c *SdkClient) EscalateAlert() error {
	return c.MoveToEscalationPolicy(c.GetOnCallEscalationPolicy())
}

// EscalateAlertWithNote annotates the PagerDuty alert with the given notes and escalates it by
// assigning to the on call escalation policy
func (c *SdkClient) EscalateAlertWithNote(notes string) error {
	return c.addNoteAndEscalate(notes, c.GetOnCallEscalationPolicy())
}

// addNoteAndEscalate attaches notes to an incident and moves it to the given escalation policy
func (c *SdkClient) addNoteAndEscalate(notes, escalationPolicy string) error {
	if notes != "" {
		err := c.AddNote(notes)
		if err != nil {
			return fmt.Errorf("failed to attach notes to incident: %w", err)
		}
	}
	return c.MoveToEscalationPolicy(escalationPolicy)
}

// ResolveIncident resolves an incident
func (c *SdkClient) ResolveIncident(incident *pagerduty.Incident) error {
	opts := pagerduty.ManageIncidentsOptions{
		ID:     incident.ID,
		Type:   incident.Type,
		Status: "resolved",
	}

	_, err := c.sdkClient.ManageIncidentsWithContext(context.TODO(), CADEmailAddress, []pagerduty.ManageIncidentsOptions{opts})

	return err
}

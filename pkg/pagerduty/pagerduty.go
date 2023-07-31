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
	"gopkg.in/yaml.v2"
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
	ResolveAlertsForCluster(clusterID string) error
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
	// externalClusterID ( only gets initialized after the first GetExternalClusterID call )
	externalClusterID *string
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

// RetrieveExternalClusterID returns the externalClusterID. The cluster id is not on the payload so the first time it is called it will
// retrieve the externalClusterID from pagerduty, and update the client.
func (c *SdkClient) RetrieveExternalClusterID() (string, error) {
	// Only do the api call to pagerduty once
	if c.externalClusterID != nil {
		return *c.externalClusterID, nil
	}

	incidentID := c.GetIncidentID()

	// pulls alerts from pagerduty
	alerts, err := c.GetAlerts(incidentID)
	if err != nil {
		return "", fmt.Errorf("could not retrieve alerts for incident '%s': %w", incidentID, err)
	}

	// there should be only one alert
	if len(alerts) > 1 {
		logging.Warnf("There should be only one alert on each incident, taking the first result of incident: %s", incidentID)
	}

	for _, a := range alerts {
		a := a
		// that one alert should have a valid ExternalID
		if a.ExternalID != "" {
			c.externalClusterID = &a.ExternalID
			return *c.externalClusterID, nil
		}
	}

	return "", fmt.Errorf("could not find an ExternalID in the given alerts")
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

// GetAlerts will retrieve the alerts for a specific incident
func (c *SdkClient) GetAlerts(incidentID string) ([]Alert, error) {
	ctx, cancel := context.WithTimeout(context.Background(), pagerDutyTimeout)
	defer cancel()

	o := sdk.ListIncidentAlertsOptions{}

	alerts, err := c.sdkClient.ListIncidentAlertsWithContext(ctx, incidentID, o)

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

// extractExternalIDFromCHGMAlertBody extracts from an Alert body until an external ID
func extractExternalIDFromCHGMAlertBody(data map[string]interface{}) (string, error) {
	var err error

	externalBody, err := extractNotesFromBody(data)
	if err != nil {
		return "", fmt.Errorf("cannot marshal externalCHGMAlertBody: %w", err)
	}

	if externalBody == "" {
		return "", AlertBodyDoesNotHaveNotesFieldError{}
	}

	internalBody := internalCHGMAlertBody{}

	err = yaml.Unmarshal([]byte(externalBody), &internalBody)
	if err != nil {
		// TODO: add errcheck for this specific error
		externalBody = strings.ReplaceAll(externalBody, `\n`, "\n")
		err = yaml.Unmarshal([]byte(externalBody), &internalBody)
		if err != nil {
			return "", NotesParseError{Err: err}
		}
	}

	if internalBody.ClusterID == "" {
		return "", AlertNotesDoesNotHaveClusterIDFieldError{}
	}

	return internalBody.ClusterID, nil
}

// TODO(Claudio): https://issues.redhat.com/browse/OSD-17557
// extractExternalIDFromStandardAlertBody extracts the minimal information neededfrom an standard alert's body
// this should become the default extracting function after we unify all alerts custom details.
// For now, it's duplicate code with minor tweaks, this will facilitate removal later though.
func extractExternalIDFromStandardAlertBody(data map[string]interface{}) (string, error) {
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

	notesInterface, ok := details["cluster_id"]
	if !ok {
		return "", AlertBodyExternalParseError{FailedProperty: ".details.cluster_id"}
	}

	notes, ok := notesInterface.(string)
	if !ok {
		err := AlertBodyExternalCastError{
			FailedProperty:     ".details.cluster_id",
			ExpectedType:       "string",
			ActualType:         reflect.TypeOf(details["cluster_id"]).String(),
			ActualBodyResource: fmt.Sprintf("%v", details["cluster_id"]),
		}
		return "", err
	}

	return notes, nil
}

// extractNotesFromBody will extract from map[string]interface{} the '.details.notes' while doing type checks
// this is better than a third party as it is better maintained and required less dependencies
func extractNotesFromBody(body map[string]interface{}) (string, error) {
	var ok bool
	_, ok = body["details"]
	if !ok {
		return "", AlertBodyExternalParseError{FailedProperty: ".details"}
	}

	details, ok := body["details"].(map[string]interface{})
	if !ok {
		err := AlertBodyExternalCastError{
			FailedProperty:     ".details",
			ExpectedType:       "map[string]interface{}",
			ActualType:         reflect.TypeOf(body["details"]).String(),
			ActualBodyResource: fmt.Sprintf("%v", body["details"]),
		}
		return "", err
	}

	notesInterface, ok := details["notes"]
	if !ok {
		return "", AlertBodyExternalParseError{FailedProperty: ".details.notes"}
	}

	notes, ok := notesInterface.(string)
	if !ok {
		err := AlertBodyExternalCastError{
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
func (c *SdkClient) toLocalAlert(sdkAlert sdk.IncidentAlert) (Alert, error) {
	var localErr error

	logging.Debugf("Attempting to extract external ID from CHGM alert body: %s", sdkAlert.Body)
	externalID, err := extractExternalIDFromCHGMAlertBody(sdkAlert.Body)
	if err != nil {
		localErr = err

		logging.Debugf("Attempting to extract external ID from standard alert body: %s", sdkAlert.Body)
		externalID, err = extractExternalIDFromStandardAlertBody(sdkAlert.Body)
		if err != nil {
			return Alert{}, fmt.Errorf("failed to extractExternalIDFromCHGMAlertBody: %s - failed to extractExternalIDFromStandardAlertBody: %s", localErr.Error(), err.Error())
		}
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
			return fmt.Errorf("failed to attach notes to CHGM incident: %w", err)
		}
	}
	return c.MoveToEscalationPolicy(escalationPolicy)
}

func (c *SdkClient) listActiveServiceIncidents() ([]pagerduty.Incident, error) {
	logging.Debug("Fetching active incidents for service...")
	var incidents []pagerduty.Incident

	opts := sdk.ListIncidentsOptions{
		ServiceIDs: []string{c.GetServiceID()},
		Statuses:   []string{"triggered", "acknowledged"},
	}

	items, err := c.sdkClient.ListIncidentsWithContext(context.Background(), opts)
	if err != nil {
		return nil, err
	}
	incidents = append(incidents, items.Incidents...)

	for items.APIListObject.More {
		logging.Debugf("Fetching more incidents (pagination) - currently %d fetched...", len(incidents))
		opts.Offset = uint(len(incidents))
		items, err = c.sdkClient.ListIncidentsWithContext(context.Background(), opts)
		if err != nil {
			return nil, err
		}
		incidents = append(incidents, items.Incidents...)
	}

	logging.Debugf("listActiveServiceIncidents found %d active incidents for service '%s'", len(incidents), c.GetServiceName())

	return incidents, nil
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

// ResolveAlertsForCluster resolve all alerts for client's service
// with a matching custom details cluster_id field
func (c *SdkClient) ResolveAlertsForCluster(clusterID string) error {
	logging.Infof("Resolving incidents related to cluster '%s' on pagerduty service '%s.", clusterID, c.GetServiceName())
	incidents, err := c.listActiveServiceIncidents()
	if err != nil {
		return err
	}

	for i, incident := range incidents {
		// We should not resolve the SilenceAlert
		if incident.ID == c.incidentData.IncidentID {
			logging.Infof("Skipping incident '%s', as it is the SilenceAlert incident.", incident.ID)
			continue
		}

		// Get all alerts contained in the incident
		incidentAlerts, err := c.GetAlerts(incident.ID)
		if err != nil {
			if strings.Contains(err.Error(), "failed to extractExternalIDFromStandardAlertBody") {
				logging.Debugf("Alert '%s' could not be parsed, alert is possibly in an old format not implemented in CAD. Skipping.", incident.ID)
				continue
			}

			return fmt.Errorf("Could not resolve alerts for cluster, failed to get incident alerts: %w", err)
		}
		logging.Debugf("Incident '%s' has %d alerts attached to it.", incident.ID, len(incidentAlerts))

		// Resolve all incidents for the same clusterID as the SilenceAlert
		for _, alert := range incidentAlerts {
			logging.Debugf("Alert '%s' has custom details clusterID '%s'", alert.ID, alert.ExternalID)
			if alert.ExternalID != clusterID {
				logging.Debugf("Skipping resolve of incident '%s', clusterID for alert '%s' contained in the incident did not match: %s and %s.", incident.ID, alert.ID, alert.ExternalID, clusterID)
				continue
			}
			logging.Infof("Resolving incident %s.", incident.ID)
			err := c.ResolveIncident(&incidents[i])
			if err != nil {
				logging.Warnf("Failed to resolve incident '%s': %s. Skipping...", incident.ID, err.Error())
			}

			err = c.AddNoteToIncident(incident.ID, "🤖 Alert resolved: inhibited by SilenceAlert 🤖\n")
			if err != nil {
				logging.Warnf("Failed to attach note to incident '%s': %s. Skipping...", incident.ID, err.Error())
			}
		}
	}
	return nil
}

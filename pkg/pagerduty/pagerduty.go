// Package pagerduty contains wrappers for pagerduty api calls
package pagerduty

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
	"gopkg.in/yaml.v2"

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
	SilenceIncident() error
	SilenceIncidentWithNote(notes string) error
	AddNote(notes string) error
	GetServiceID() string
	EscalateIncidentWithNote(notes string) error
	EscalateIncident() error
}

// SdkClient will hold all the required fields for any SdkClient Operation
type SdkClient struct {
	// c is the PagerDuty client
	sdkClient *sdk.Client
	// silentEscalationPolicy
	silentEscalationPolicy string
	// incidentData
	incidentData *IncidentData
	// clusterID ( only gets initialized after the first GetclusterID call )
	clusterID *string
}

// GetPDClient will retrieve the PagerDuty from the 'pagerduty' package
func GetPDClient(webhookPayload []byte) (*SdkClient, error) {
	cadPD, hasCadPD := os.LookupEnv("CAD_PD_TOKEN")
	cadSilentPolicy, hasCadSilentPolicy := os.LookupEnv("CAD_SILENT_POLICY")

	if !hasCadSilentPolicy || !hasCadPD {
		return nil, fmt.Errorf("one of the required envvars in the list '(CAD_SILENT_POLICY CAD_PD_TOKEN)' is missing")
	}

	client, err := NewWithToken(cadSilentPolicy, webhookPayload, cadPD)
	if err != nil {
		return nil, fmt.Errorf("could not initialize the client: %w", err)
	}

	return client, nil
}

// IncidentData represents the data contained in an incident
type IncidentData struct {
	IncidentTitle  string // e.g. InfraNodesNeedResizingSRE CRITICAL (1)
	IncidentID     string // e.g. Q2I4AV3ZURABC
	IncidentRef    string // e.g. https://<>.pagerduty.com/incidents/Q2I4AV3ZURABC
	ServiceID      string // e.g. PCH1XGB
	ServiceSummary string // e.g. prod-deadmanssnitch
}

func (c *SdkClient) initializeIncidentData(payload []byte) (*IncidentData, error) {
	incidentData := &IncidentData{}

	logging.Debug("Attempting to unmarshal webhookV3...")
	unmarshalled, err := unmarshalWebhookV3(payload)
	if err == nil {
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
func NewWithToken(silentPolicy string, webhookPayload []byte, authToken string, options ...sdk.ClientOptions) (*SdkClient, error) {
	c := SdkClient{
		sdkClient: sdk.NewClient(authToken, options...),

		// All two of the below should be moved out of the SDK.
		// These are static values that should not be part of an sdk
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

// moveToEscalationPolicy will move the incident's EscalationPolicy to the new EscalationPolicy
func (c *SdkClient) moveToEscalationPolicy(escalationPolicyID string) error {
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
	logging.Infof("Attaching Note: %s", noteContent)
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

type notesData struct {
	ClusterID string `yaml:"cluster_id"`
}

func extractClusterIDFromAlertBody(data map[string]interface{}) (string, error) {
	details, found := data["details"].(map[string]interface{})
	if !found {
		return "", errors.New("could not find alert details field")
	}

	// PARSE OPTION 1 (new format): cluster_id directly contained in custom details
	clusterID, found := details["cluster_id"].(string)
	if !found {
		logging.Warn("Unable to parse cluster_id as direct field directly from the alert details.")
	} else {
		return clusterID, nil
	}

	// PARSE OPTION 2 (old format: OSD-18006): cluster_id contained in custom_details[notes]
	// We have quite a few alerts fired from a few months ago that still are in this format.
	// We will have to wait a bit until we remove the backwards compatibility.
	// In theory, it's not a big issue that the alerts fail to get handled by CAD, as this
	// only affects alerts that already exist, and re-pass CAD for the 'resolve' state.
	// We still don't want to many failing pipelines though.
	logging.Warn("Trying to parse cluster_id from the notes field...")

	notes, found := details["notes"].(string)
	if !found {
		return "", errors.New("could not find notes field")
	}

	var notesUnmarshalled notesData
	if err := yaml.Unmarshal([]byte(notes), &notesUnmarshalled); err != nil {
		return "", fmt.Errorf("error decoding notes YAML: %w", err)
	}

	clusterID = notesUnmarshalled.ClusterID
	if clusterID == "" {
		return "", errors.New("could not find cluster_id field in notes")
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

// SilenceIncident silences the alert by assigning the "Silent Test" escalation policy
func (c *SdkClient) SilenceIncident() error {
	return c.moveToEscalationPolicy(c.GetSilentEscalationPolicy())
}

// SilenceIncidentWithNote annotates the PagerDuty alert with the given notes and silences it by
// assigning the "Silent Test" escalation policy
func (c *SdkClient) SilenceIncidentWithNote(notes string) error {
	if notes != "" {
		err := c.AddNote(notes)
		if err != nil {
			return fmt.Errorf("failed to attach notes to incident: %w", err)
		}
	}

	return c.SilenceIncident()
}

// EscalateIncidentWithNote annotates the PagerDuty alert with the given notes and escalates it by
// assigning to the on call escalation policy
func (c *SdkClient) EscalateIncidentWithNote(notes string) error {
	if notes != "" {
		err := c.AddNote(notes)
		if err != nil {
			return fmt.Errorf("failed to attach notes to incident: %w", err)
		}
	}
	return c.EscalateIncident()
}

// EscalateIncident escalates an incident to incident level 2.
// This currently assumes that we are always at level 1.
func (c *SdkClient) EscalateIncident() error {
	o := []pagerduty.ManageIncidentsOptions{
		{
			ID:              c.GetIncidentID(),
			EscalationLevel: 2, // TODO: This is hardcoded because there's no way to check the "current" level. Ideally this should be `current + 1`
		},
	}

	err := c.updateIncident(o)
	if err != nil {
		if strings.Contains(err.Error(), "Incident Already Resolved") {
			logging.Infof("Skipped escalating incident as it is already resolved.")
			return nil
		}
		return fmt.Errorf("could not escalate the incident: %w", err)
	}
	return nil
}

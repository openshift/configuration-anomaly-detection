package pagerduty

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"reflect"
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
)

// PagerDuty will hold all of the required fields for any PagerDuty Operation
type PagerDuty struct {
	// c is the PagerDuty client
	c *sdk.Client
	// currentUserEmail is the current logged in user's email
	currentUserEmail string
}

// NewWithToken is similar to New but you only need to supply to authentication token to start
// The token can be created using the docs https://support.pagerduty.com/docs/api-access-keys#section-generate-a-user-token-rest-api-key
func NewWithToken(authToken string) (PagerDuty, error) {
	c := sdk.NewClient(authToken)
	return New(c)
}

// New will create a PagerDuty struct with all of the required fields
func New(client *sdk.Client) (PagerDuty, error) {
	sdkUser, err := getCurrentUser(client)
	if err != nil {
		return PagerDuty{}, fmt.Errorf("could not create a new client: %w", err)
	}

	resp := PagerDuty{
		c:                client,
		currentUserEmail: sdkUser.Email,
	}

	return resp, nil
}

// MoveToEscalationPolicy will move the incident's EscalationPolicy to the new EscalationPolicy
func (p PagerDuty) MoveToEscalationPolicy(incidentID string, escalationPolicyID string) error {
	o := []sdk.ManageIncidentsOptions{
		{
			ID: incidentID,
			EscalationPolicy: &sdk.APIReference{
				Type: "escalation_policy_reference",
				ID:   escalationPolicyID,
			},
		},
	}
	err := p.manageIncident(o)
	if err != nil {
		return fmt.Errorf("could not update the escalation policy: %w", err)
	}
	return nil
}

// AssignToUser will assign the incident to the provided user
func (p PagerDuty) AssignToUser(incidentID string, userID string) error {
	o := []sdk.ManageIncidentsOptions{{
		ID: incidentID,
		Assignments: []sdk.Assignee{{
			Assignee: sdk.APIObject{
				Type: "user_reference",
				ID:   userID,
			},
		}},
	}}
	err := p.manageIncident(o)
	if err != nil {
		return fmt.Errorf("could not assign to user: %w", err)
	}
	return nil
}

// AcknowledgeIncident will acknowledge an incident
func (p PagerDuty) AcknowledgeIncident(incidentID string) error {
	o := []sdk.ManageIncidentsOptions{
		{
			ID:     incidentID,
			Status: "acknowledged",
		},
	}
	err := p.manageIncident(o)
	if err != nil {
		return fmt.Errorf("could not acknowledge the incident: %w", err)
	}
	return nil
}

// AddNote will add a note to an incident
func (p PagerDuty) AddNote(incidentID string, noteContent string) error {
	ctx, cancel := context.WithTimeout(context.Background(), pagerDutyTimeout)
	defer cancel()
	sdkNote := sdk.IncidentNote{
		Content: noteContent,
	}

	_, err := p.c.CreateIncidentNoteWithContext(ctx, incidentID, sdkNote)

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

// GetAlerts will retrieve the alerts for a specific incident
func (p PagerDuty) GetAlerts(incidentID string) ([]Alert, error) {
	ctx, cancel := context.WithTimeout(context.Background(), pagerDutyTimeout)
	defer cancel()

	o := sdk.ListIncidentAlertsOptions{}

	alerts, err := p.c.ListIncidentAlertsWithContext(ctx, incidentID, o)

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
		localAlert, err := p.toLocalAlert(alert)
		if err != nil {
			return nil, fmt.Errorf("could not convert alert toLocalAlert: %w", err)
		}
		res = append(res, localAlert)
	}
	return res, nil
}

// ExtractIDFromCHGM extracts from an Alert body until an external ID
// the function is a member function but doesn't use any of the other funcs / types in the PagerDuty struct
func (_ PagerDuty) ExtractIDFromCHGM(data map[string]interface{}) (string, error) {
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
		return "", NotesParseErr{Err: err}
	}

	if internalBody.ClusterID == "" {
		return "", AlertNotesDoesNotHaveClusterIDFieldErr{}
	}

	return internalBody.ClusterID, nil
}

// fileReader will wrap the os or fstest.MapFS stucts so we are not locked in
type fileReader interface {
	ReadFile(name string) ([]byte, error)
}

type RealFileReader struct{}

func (_ RealFileReader) ReadFile(name string) ([]byte, error) {
	return os.ReadFile(name)
}

type WebhookPayloadToIncidentID struct {
	Event struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	} `json:"event"`
}

// ExtractExternalIDFromPayload will retrieve the payloadFilePath and return the externalID
func (p PagerDuty) ExtractExternalIDFromPayload(payloadFilePath string, reader fileReader) (string, error) {
	data, err := readPayloadFile(payloadFilePath, reader)
	// TODO: if need be, extract the next steps into 'func ExtractExternalIDFromPayload(payload []byte) (string, error)'
	if err != nil {
		return "", fmt.Errorf("could not read the payloadFile: %w", err)
	}
	return p.ExtractExternalIDFromBytes(data)
}

// ExtractExternalIDFromBytes will return the externalID from the bytes[] data
func (p PagerDuty) ExtractExternalIDFromBytes(data []byte) (string, error) {
	var err error
	w := WebhookPayloadToIncidentID{}
	err = json.Unmarshal(data, &w)
	if err != nil {
		return "", UnmarshalErr{Err: err}
	}
	incidentID := w.Event.Data.ID
	if incidentID == "" {
		return "", UnmarshalErr{Err: fmt.Errorf("could not extract incidentID")}
	}

	alerts, err := p.GetAlerts(incidentID)
	if err != nil {
		return "", fmt.Errorf("could not retrieve alerts for incident '%s': %w", incidentID, err)
	}

	// there should be only one alert
	for _, a := range alerts {
		// that one alert should have a valid ExternalID
		if a.ExternalID != "" {
			return a.ExternalID, nil
		}
	}

	return "", fmt.Errorf("could not find an ExternalID in the given alerts")
}

// readPayloadFile is a temporary function soley responsible to retrieve the payload data from somewhere.
// if we choose to pivot and use a different way of pulling the payload data we can change this function and ExtractExternalIDFromPayload inputs
func readPayloadFile(payloadFilePath string, reader fileReader) ([]byte, error) {
	data, err := reader.ReadFile(payloadFilePath)
	if err != nil {
		ok := isPathError(err)
		if ok {
			return nil, FileNotFoundErr{FilePath: payloadFilePath, Err: err}
		}
		return nil, err
	}
	return data, nil
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

// manageIncident will run the API call to PagerDuty for updating the incident, and handle the error codes that arise
// the reason we send an array instead of a single item is to be compatible with the sdk
// the customErrorString is a nice touch so when the error bubbles up it's clear who called it (if it's an unknown error)
func (p PagerDuty) manageIncident(o []sdk.ManageIncidentsOptions) error {
	ctx, cancel := context.WithTimeout(context.Background(), pagerDutyTimeout)
	defer cancel()
	_, err := p.c.ManageIncidentsWithContext(ctx, p.currentUserEmail, o)

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

// getCurrentUser retrieves the current pagerduty user
func getCurrentUser(client *sdk.Client) (*sdk.User, error) {
	opts := sdk.GetCurrentUserOptions{}
	ctx, cancel := context.WithTimeout(context.Background(), pagerDutyTimeout)
	defer cancel()
	user, err := client.GetCurrentUserWithContext(ctx, opts)

	sdkErr := sdk.APIError{}
	if errors.As(err, &sdkErr) {
		if sdkErr.StatusCode == http.StatusUnauthorized {
			return nil, InvalidTokenErr{Err: err}
		}
	}

	if err != nil {

		return nil, fmt.Errorf("could not retrieve the current user: %w", err)
	}
	return user, nil
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

// toLocalAlert will convert an sdk.IncidentAlert to a local Alert resource
func (p PagerDuty) toLocalAlert(sdkAlert sdk.IncidentAlert) (Alert, error) {
	externalID, err := p.ExtractIDFromCHGM(sdkAlert.Body)
	if err != nil {
		return Alert{}, fmt.Errorf("could not ExtractIDFromCHGM: %w", err)
	}
	alert := Alert{
		ID:         sdkAlert.APIObject.ID,
		ExternalID: externalID,
	}
	return alert, nil
}

func isPathError(err error) bool {
	_, ok := err.(*fs.PathError)
	return ok
}

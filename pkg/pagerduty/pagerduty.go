package pagerduty

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	sdk "github.com/PagerDuty/go-pagerduty"
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

// MoveToEscalationPolicy will move the alerts EscalationPolicy to the new EscalationPolicy
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

// manageIncident will run the API call to PagerDuty for updating the incident, and handle the error codes that arise
// the reason we send an array instead of a single item is to be compatible with the sdk
// the customErrorString is a nice touch so when the error bubbles up it's clear who called it (if it's an unknown error)
func (p PagerDuty) manageIncident(o []sdk.ManageIncidentsOptions) error {
	ctx, cancel := context.WithTimeout(context.Background(), pagerDutyTimeout)
	defer cancel()
	_, err := p.c.ManageIncidentsWithContext(ctx, p.currentUserEmail, o)

	if err != nil {
		perr := sdk.APIError{}
		if errors.As(err, &perr) {
			switch perr.StatusCode {
			case http.StatusUnauthorized:
				return InvalidTokenErr{Err: err}
			case http.StatusBadRequest:
				isAnInvalidInputErr := perr.APIError.Valid &&
					perr.APIError.ErrorObject.Code == InvalidInputParamsErrorCode
				if isAnInvalidInputErr {
					return InvalidInputParamsErr{Err: err}
				}
			}
		}
		return UnknownUpdateIncidentError{Err: err}
	}

	return nil
}

// getCurrentUser retrieves the current pagerduty user
func getCurrentUser(client *sdk.Client) (*sdk.User, error) {
	opts := sdk.GetCurrentUserOptions{}
	ctx, cancel := context.WithTimeout(context.Background(), pagerDutyTimeout)
	defer cancel()
	user, err := client.GetCurrentUserWithContext(ctx, opts)
	if err != nil {
		perr := sdk.APIError{}
		if errors.As(err, &perr) {
			if perr.StatusCode == http.StatusUnauthorized {
				return nil, InvalidTokenErr{Err: err}
			}
		}

		return nil, fmt.Errorf("could not retrieve the current user: %w", err)
	}
	return user, nil
}

package pagerduty

import (
	"context"
	"errors"
	"net/http"
	"time"

	pkgerrors "github.com/pkg/errors"

	sdk "github.com/PagerDuty/go-pagerduty"
)

const (
	// InvalidInputParamsErrorCode is exposed from the pagerduties API error response, used to distinguish between different error codes.
	// for more details see https://developer.pagerduty.com/docs/ZG9jOjExMDI5NTYz-errors#pagerduty-error-codes
	InvalidInputParamsErrorCode = 2001
	// pagerDutyTimeout is the chosen timeout for api requests, can be changed later
	pagerDutyTimeout = time.Second * 30
)

// PagerDuty will hold all of the required fields for any PagerDuty Operation
type PagerDuty struct {
	// c is the PagerDuty client
	c *sdk.Client
	// userEmail is the user that will run the commands
	userEmail string
}

// NewWithToken is similar to New but you only need to supply to authentication token to start
// The token can be created using the docs https://support.pagerduty.com/docs/api-access-keys#section-generate-a-user-token-rest-api-key
func NewWithToken(authToken string) (PagerDuty, error) {
	c := sdk.NewClient(authToken)
	return New(c)
}

// New will create a PagerDuty struct with all of the required fields
func New(client *sdk.Client) (PagerDuty, error) {
	user, err := getCurrentUser(client)
	if err != nil {
		return PagerDuty{}, pkgerrors.Wrap(err, "could not retrieve the current user")
	}

	resp := PagerDuty{
		c:         client,
		userEmail: user.Email,
	}

	return resp, nil
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
				return nil, pkgerrors.Wrap(err, "the authToken that was provided is invalid")
			}
		}

		return nil, pkgerrors.Wrap(err, "could not retrieve the current user")
	}
	return user, nil
}

// MoveToEscalationPolicy will move the alerts EscalationPolicy to the new EscalationPolicy
func (p PagerDuty) MoveToEscalationPolicy(incident Incident, escalationPolicy EscalationPolicy) error {
	if incident.EscalationPolicy == escalationPolicy {
		return nil
	}
	incident.EscalationPolicy = escalationPolicy

	o := []sdk.ManageIncidentsOptions{
		{
			ID: incident.ID,
			EscalationPolicy: &sdk.APIReference{
				Type: "escalation_policy_reference",
				ID:   incident.EscalationPolicy.ID,
			},
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), pagerDutyTimeout)
	defer cancel()
	_, err := p.c.ManageIncidentsWithContext(ctx, p.userEmail, o)

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
		return pkgerrors.Wrap(err, "could not update the escalation policy")
	}

	return nil
}

package interceptor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/PagerDuty/go-pagerduty/webhookv3"
	investigations "github.com/openshift/configuration-anomaly-detection/pkg/investigations"
	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
	"github.com/openshift/configuration-anomaly-detection/pkg/pagerduty"
	triggersv1 "github.com/tektoncd/triggers/pkg/apis/triggers/v1beta1"
	"github.com/tektoncd/triggers/pkg/interceptors"
	"google.golang.org/grpc/codes"
)

// ErrInvalidContentType is returned when the content-type is not a JSON body.
var ErrInvalidContentType = errors.New("form parameter encoding not supported, please change the hook to send JSON payloads")

type PagerDutyInterceptor struct{}

func (pdi PagerDutyInterceptor) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, err := pdi.executeInterceptor(r)
	if err != nil {
		var e Error
		if errors.As(err, &e) {
			logging.Infof("HTTP %d - %s", e.Status(), e)
			http.Error(w, e.Error(), e.Status())
		} else {
			logging.Errorf("Non Status Error: %s", err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		}
	}

	w.Header().Add("Content-Type", "application/json")
	if _, err := w.Write(b); err != nil {
		logging.Errorf("failed to write response: %s", err)
	}
}

// Error represents a handler error. It provides methods for a HTTP status
// code and embeds the built-in error interface.
type Error interface {
	error
	Status() int
}

// HTTPError represents an error with an associated HTTP status code.
type HTTPError struct {
	Code int
	Err  error
}

// Allows HTTPError to satisfy the error interface.
func (se HTTPError) Error() string {
	return se.Err.Error()
}

// Returns our HTTP status code.
func (se HTTPError) Status() int {
	return se.Code
}

func badRequest(err error) HTTPError {
	return HTTPError{Code: http.StatusBadRequest, Err: err}
}

func internal(err error) HTTPError {
	return HTTPError{Code: http.StatusInternalServerError, Err: err}
}

func (pdi *PagerDutyInterceptor) executeInterceptor(r *http.Request) ([]byte, error) {
	// Create a context
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	var body bytes.Buffer
	defer r.Body.Close() //nolint:errcheck
	if _, err := io.Copy(&body, r.Body); err != nil {
		return nil, internal(fmt.Errorf("failed to read body: %w", err))
	}
	r.Body = io.NopCloser(bytes.NewReader(body.Bytes()))

	// originalReq is the original request that was sent to the interceptor,
	// due to be unwrapped into a new header and body for signature verification.
	var originalReq struct {
		Body   string              `json:"body"`
		Header map[string][]string `json:"header"`
	}
	if err := json.Unmarshal(body.Bytes(), &originalReq); err != nil {
		return nil, badRequest(fmt.Errorf("failed to parse request body: %w", err))
	}

	extractedRequest, err := http.NewRequestWithContext(ctx, r.Method, r.URL.String(), bytes.NewReader([]byte(originalReq.Body)))
	if err != nil {
		return nil, internal(fmt.Errorf("malformed body/header in unwrapped request: %w", err))
	}

	for k, v := range originalReq.Header {
		for _, v := range v {
			extractedRequest.Header.Add(k, v)
		}
	}

	var ireq triggersv1.InterceptorRequest

	logging.Debug("Unwrapped Request body: ", originalReq.Body)

	token, _ := os.LookupEnv("PD_SIGNATURE")

	err = webhookv3.VerifySignature(extractedRequest, token)
	if err != nil {
		return nil, badRequest(fmt.Errorf("failed to verify signature: %w", err))
	}

	logging.Info("Signature verified successfully")

	if err := json.Unmarshal(body.Bytes(), &ireq); err != nil {
		return nil, badRequest(fmt.Errorf("failed to parse body as InterceptorRequest: %w", err))
	}
	logging.Debugf("Interceptor request body is: %s", ireq.Body)

	iresp := pdi.Process(ctx, &ireq)
	logging.Debugf("Interceptor response is: %+v", iresp)
	respBytes, err := json.Marshal(iresp)
	if err != nil {
		return nil, internal(err)
	}
	return respBytes, nil
}

func (pdi *PagerDutyInterceptor) Process(ctx context.Context, r *triggersv1.InterceptorRequest) *triggersv1.InterceptorResponse {
	pdClient, err := pagerduty.GetPDClient([]byte(r.Body))
	if err != nil {
		return interceptors.Failf(codes.InvalidArgument, "could not initialize pagerduty client: %v", err)
	}

	experimentalEnabledVar := os.Getenv("CAD_EXPERIMENTAL_ENABLED")
	cadExperimentalEnabled, _ := strconv.ParseBool(experimentalEnabledVar)

	investigation := investigations.GetInvestigation(pdClient.GetTitle(), cadExperimentalEnabled)
	// If the alert is not in the whitelist, return `Continue: false` as interceptor response
	// and escalate the alert to SRE
	if investigation == nil {
		logging.Infof("Incident %s is not mapped to an investigation, escalating incident and returning InterceptorResponse `Continue: false`.", pdClient.GetIncidentID())
		err = pdClient.EscalateIncidentWithNote("🤖 No automation implemented for this alert; escalated to SRE. 🤖")
		if err != nil {
			logging.Errorf("failed to escalate incident '%s': %w", pdClient.GetIncidentID(), err)
		}

		return &triggersv1.InterceptorResponse{
			Continue: false,
		}
	}

	logging.Infof("Incident %s is mapped to investigation '%s', returning InterceptorResponse `Continue: true`.", pdClient.GetIncidentID(), investigation.Name())
	return &triggersv1.InterceptorResponse{
		Continue: true,
	}
}

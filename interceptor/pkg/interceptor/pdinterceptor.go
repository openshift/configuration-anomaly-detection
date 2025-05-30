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

type ErrorCodeWithReason struct {
	ErrorCode int
	Reason    string
}

type InterceptorStats struct {
	RequestsCount               uint64
	CodeWithReasonToErrorsCount map[ErrorCodeWithReason]int
}

func CreateInterceptorStats() *InterceptorStats {
	return &InterceptorStats{CodeWithReasonToErrorsCount: make(map[ErrorCodeWithReason]int)}
}

type interceptorHandler struct {
	stats *InterceptorStats
}

func CreateInterceptorHandler(stats *InterceptorStats) http.Handler {
	return &interceptorHandler{stats}
}

func (pdi interceptorHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	pdi.stats.RequestsCount++

	b, httpErr := pdi.executeInterceptor(r)
	if httpErr != nil {
		logging.Infof("HTTP %d - %s", httpErr.code, httpErr.err)
		http.Error(w, httpErr.err.Error(), httpErr.code)
	}

	w.Header().Add("Content-Type", "application/json")
	if _, err := w.Write(b); err != nil {
		logging.Errorf("failed to write response: %s", err)
	}
}

// httpError represents an error with an associated HTTP status code.
type httpError struct {
	code int
	err  error
}

func (pdi *interceptorHandler) httpError(errorCode int, reason string, err error) *httpError {
	pdi.stats.CodeWithReasonToErrorsCount[ErrorCodeWithReason{errorCode, reason}]++

	return &httpError{code: errorCode, err: fmt.Errorf("%s: %w", reason, err)}
}

func (pdi *interceptorHandler) badRequest(reason string, err error) *httpError {
	return pdi.httpError(http.StatusBadRequest, reason, err)
}

func (pdi *interceptorHandler) internal(reason string, err error) *httpError {
	return pdi.httpError(http.StatusInternalServerError, reason, err)
}

func (pdi *interceptorHandler) executeInterceptor(r *http.Request) ([]byte, *httpError) {
	// Create a context
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	var body bytes.Buffer
	defer r.Body.Close() //nolint:errcheck
	if _, err := io.Copy(&body, r.Body); err != nil {
		return nil, pdi.internal("failed to read body", err)
	}
	r.Body = io.NopCloser(bytes.NewReader(body.Bytes()))

	// originalReq is the original request that was sent to the interceptor,
	// due to be unwrapped into a new header and body for signature verification.
	var originalReq struct {
		Body   string              `json:"body"`
		Header map[string][]string `json:"header"`
	}
	if err := json.Unmarshal(body.Bytes(), &originalReq); err != nil {
		return nil, pdi.badRequest("failed to parse body", err)
	}

	extractedRequest, err := http.NewRequestWithContext(ctx, r.Method, r.URL.String(), bytes.NewReader([]byte(originalReq.Body)))
	if err != nil {
		return nil, pdi.internal("malformed body/header in unwrapped request", err)
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
		return nil, pdi.badRequest("failed to verify signature", err)
	}

	logging.Info("Signature verified successfully")

	if err := json.Unmarshal(body.Bytes(), &ireq); err != nil {
		return nil, pdi.badRequest("failed to parse body as InterceptorRequest", err)
	}
	logging.Debugf("Interceptor request body is: %s", ireq.Body)

	iresp := pdi.process(ctx, &ireq)
	logging.Debugf("Interceptor response is: %+v", iresp)
	respBytes, err := json.Marshal(iresp)
	if err != nil {
		return nil, pdi.internal("failed to encode response", err)
	}
	return respBytes, nil
}

func (pdi *interceptorHandler) process(ctx context.Context, r *triggersv1.InterceptorRequest) *triggersv1.InterceptorResponse {
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

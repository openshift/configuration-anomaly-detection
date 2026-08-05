package interceptor

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/PagerDuty/go-pagerduty/webhookv3"
	"github.com/openshift/configuration-anomaly-detection/pkg/config"
	investigations "github.com/openshift/configuration-anomaly-detection/pkg/investigations"
	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
	"github.com/openshift/configuration-anomaly-detection/pkg/ocm"
	"github.com/openshift/configuration-anomaly-detection/pkg/pagerduty"
	"github.com/prometheus/client_golang/prometheus"
	triggersv1 "github.com/tektoncd/triggers/pkg/apis/triggers/v1beta1"
	"github.com/tektoncd/triggers/pkg/interceptors"
	"google.golang.org/grpc/codes"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

// ErrInvalidContentType is returned when the content-type is not a JSON body.
var ErrInvalidContentType = errors.New("form parameter encoding not supported, please change the hook to send JSON payloads")

var (
	requestsCounter = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "cad_interceptor_requests_total",
		Help: "Number of times CAD interceptor has been called (through a PagerDuty webhook, normally)",
	})

	errorsCounter = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "cad_interceptor_errors_total",
		Help: "Number of times CAD interceptor has been failed to process a request",
	}, []string{"error_code", "reason"})
)

func init() {
	metrics.Registry.MustRegister(requestsCounter, errorsCounter)
}

// OrgEscalationMapping represents the structure of the org-to-policy mapping
type OrgEscalationMapping struct {
	Organizations []Organization `json:"organizations"`
}

// Organization represents a customer organization with its escalation policy
type Organization struct {
	Name             string   `json:"name"`
	OrgIDs           []string `json:"org_ids"`
	EscalationPolicy string   `json:"escalation_policy"`
}

type interceptorHandler struct {
	PDTokens []string
	cfg      *config.Config
}

func CreateInterceptorHandler(pdTokens []string, configPath string) (http.Handler, error) {
	cfg, err := config.LoadConfig(configPath, investigations.GetAvailableInvestigationsNames())
	if err != nil {
		return nil, fmt.Errorf("loading investigation config: %w", err)
	}
	return &interceptorHandler{PDTokens: pdTokens, cfg: cfg}, nil
}

func (pdi interceptorHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	requestsCounter.Inc()

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
	errorsCounter.WithLabelValues(strconv.Itoa(errorCode), reason).Inc()

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

	const maxBodyBytes = 5 * 1024 * 1024 // 5 MiB
	bodyBytes, err := io.ReadAll(io.LimitReader(r.Body, int64(maxBodyBytes)+1))
	if err != nil {
		return nil, pdi.internal("failed to read body", err)
	}
	if len(bodyBytes) > maxBodyBytes {
		return nil, pdi.httpError(http.StatusRequestEntityTooLarge, "request body too large", fmt.Errorf("exceeds %d bytes", maxBodyBytes))
	}

	// originalReq is the original request that was sent to the interceptor,
	// due to be unwrapped into a new header and body for signature verification.
	var originalReq struct {
		Body   string              `json:"body"`
		Header map[string][]string `json:"header"`
	}
	if err := json.Unmarshal(bodyBytes, &originalReq); err != nil {
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

	var sigErrs []error
	for _, signature := range pdi.PDTokens {
		err = webhookv3.VerifySignature(extractedRequest, signature)
		if err != nil {
			sigErrs = append(sigErrs, err)
		} else {
			// A signature successfully verified we can continue
			break
		}
	}
	if len(sigErrs) == len(pdi.PDTokens) {
		return nil, pdi.badRequest("failed to verify signature against all signatures", errors.Join(sigErrs...))
	}

	logging.Info("Signature verified successfully")

	if err := json.Unmarshal(bodyBytes, &ireq); err != nil {
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

	// Load org mapping
	orgMap, err := loadOrgEscalationMapping()
	if err != nil {
		logging.Warnf("Failed to load org mapping: %v", err)
		orgMap = make(map[string]string)
	}

	// Create OCM client - required for AI investigations and org routing
	ocmClientID := os.Getenv("CAD_OCM_CLIENT_ID")
	ocmClientSecret := os.Getenv("CAD_OCM_CLIENT_SECRET")
	ocmURL := os.Getenv("CAD_OCM_URL")

	if ocmClientID == "" || ocmClientSecret == "" || ocmURL == "" {
		return interceptors.Failf(codes.FailedPrecondition, "OCM credentials not configured - required environment variables: CAD_OCM_CLIENT_ID, CAD_OCM_CLIENT_SECRET, CAD_OCM_URL")
	}

	ocmClient, err := ocm.New(ocmClientID, ocmClientSecret, ocmURL)
	if err != nil {
		return interceptors.Failf(codes.Internal, "failed to create OCM client: %v", err)
	}

	// Perform org-based routing if org mapping is configured
	if len(orgMap) > 0 {
		reassignToOrgEscalationPolicy(pdClient, ocmClient, orgMap)
	}

	experimentalEnabledVar := os.Getenv("CAD_EXPERIMENTAL_ENABLED")
	experimentalEnabled, _ := strconv.ParseBool(experimentalEnabledVar)

	// Check if an alert config exists for this alert (config loaded at handler creation)
	hasAlert := pdi.cfg != nil && pdi.cfg.GetAlert(pdClient.GetTitle(), experimentalEnabled) != nil

	if hasAlert {
		logging.Infof("Incident %s has a configured alert, returning InterceptorResponse `Continue: true`.", pdClient.GetIncidentID())
		return continueWithEncodedPayload(r.Body)
	}

	// AI fallback: if ai_agent is configured, allow the pipeline to run for AI investigation
	if pdi.cfg != nil && pdi.cfg.AIAgent != nil {
		logging.Infof("No alert match, but AI agent configured — checking cluster existence")
		resp := clusterExists(pdClient, ocmClient)
		if resp != nil {
			return resp
		}
		logging.Infof("Launching AI investigation for incident %s", pdClient.GetIncidentID())
		return continueWithEncodedPayload(r.Body)
	}

	// No chain and no AI — escalate to SRE
	logging.Infof("Incident %s is not mapped to an investigation, escalating incident and returning InterceptorResponse `Continue: false`.", pdClient.GetIncidentID())
	if err = pdClient.EscalateIncidentWithNote("🤖 No automation implemented for this alert; escalated to SRE. 🤖"); err != nil {
		logging.Errorf("failed to escalate incident '%s': %v", pdClient.GetIncidentID(), err)
	}
	return &triggersv1.InterceptorResponse{Continue: false}
}

// continueWithEncodedPayload returns a Continue response with the webhook payload
// base64-encoded as an extension. The TriggerBinding references this extension so
// the payload reaches the Tekton task without shell metacharacter issues.
func continueWithEncodedPayload(body string) *triggersv1.InterceptorResponse {
	return &triggersv1.InterceptorResponse{
		Continue: true,
		Extensions: map[string]interface{}{
			"payload_base64": base64.StdEncoding.EncodeToString([]byte(body)),
		},
	}
}

// clusterExists retrieves the cluster ID from PagerDuty and verifies it
// exists in OCM. It returns the cluster ID on success, or a short-circuit
// InterceptorResponse (Continue: false) on failure.
func clusterExists(pdClient pagerduty.Client, ocmClient ocm.Client) *triggersv1.InterceptorResponse {
	clusterID, err := pdClient.RetrieveClusterID()
	if err != nil {
		logging.Warnf("Could not retrieve cluster id from PD incident")
		return &triggersv1.InterceptorResponse{Continue: false}
	}

	_, err = ocmClient.GetClusterInfo(clusterID)
	if err != nil {
		logging.Warnf("Could not retrieve cluster from OCM: %s", clusterID)
		return &triggersv1.InterceptorResponse{Continue: false}
	}

	return nil
}

func loadOrgEscalationMapping() (map[string]string, error) {
	mappingJSON, hasMappingJSON := os.LookupEnv("CAD_ORG_POLICY_MAPPING")
	if !hasMappingJSON || mappingJSON == "" {
		return make(map[string]string), nil
	}

	var mapping OrgEscalationMapping
	if err := json.Unmarshal([]byte(mappingJSON), &mapping); err != nil {
		return nil, fmt.Errorf("failed to unmarshal org policy mapping: %w", err)
	}

	result := make(map[string]string)
	for _, org := range mapping.Organizations {
		for _, orgID := range org.OrgIDs {
			result[orgID] = org.EscalationPolicy
		}
	}
	return result, nil
}

func reassignToOrgEscalationPolicy(pdClient pagerduty.Client, ocmClient ocm.Client, orgMap map[string]string) {
	if len(orgMap) == 0 {
		return
	}

	clusterID, err := pdClient.RetrieveClusterID()
	if err != nil {
		return
	}

	orgID, err := ocmClient.GetOrganizationID(clusterID)
	if err != nil {
		logging.Warnf("Failed to get org ID for cluster %s: %v", clusterID, err)
		return
	}
	if orgID == "" {
		return
	}

	policy, found := orgMap[orgID]
	if !found {
		return
	}

	if err := pdClient.MoveToEscalationPolicy(policy); err != nil {
		if noteErr := pdClient.AddNote(fmt.Sprintf("This cluster belongs to organization %s and should be escalated to policy %s, but CAD failed to reassign: %v. Please manually route to the appropriate team.", orgID, policy, err)); noteErr != nil {
			logging.Warnf("Failed to add note about reassignment failure: %v", noteErr)
		}
		logging.Errorf("Failed to reassign to org policy %s: %v", policy, err)
		return
	}

	if err := pdClient.AddNote(fmt.Sprintf("Reassigned to organization %s escalation policy.", orgID)); err != nil {
		logging.Warnf("Failed to add note about successful reassignment: %v", err)
	}
}

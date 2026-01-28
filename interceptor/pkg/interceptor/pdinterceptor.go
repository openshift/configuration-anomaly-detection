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
	"github.com/openshift/configuration-anomaly-detection/pkg/aiconfig"
	investigations "github.com/openshift/configuration-anomaly-detection/pkg/investigations"
	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
	"github.com/openshift/configuration-anomaly-detection/pkg/ocm"
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
	cadExperimentalEnabled, _ := strconv.ParseBool(experimentalEnabledVar)

	investigation := investigations.GetInvestigation(pdClient.GetTitle(), cadExperimentalEnabled)

	// If no formal investigation found, check if AI investigation should run
	if investigation == nil {
		if shouldRunAIInvestigation(pdClient, ocmClient) {
			logging.Infof("Launching AI investigation")
			return &triggersv1.InterceptorResponse{Continue: true}
		}

		// No formal investigation and AI not enabled/allowed - escalate to SRE
		logging.Infof("Incident %s is not mapped to an investigation, escalating incident and returning InterceptorResponse `Continue: false`.", pdClient.GetIncidentID())
		err = pdClient.EscalateIncidentWithNote("🤖 No automation implemented for this alert; escalated to SRE. 🤖")
		if err != nil {
			logging.Errorf("failed to escalate incident '%s': %w", pdClient.GetIncidentID(), err)
		}
		return &triggersv1.InterceptorResponse{Continue: false}
	}

	logging.Infof("Incident %s is mapped to investigation '%s', returning InterceptorResponse `Continue: true`.", pdClient.GetIncidentID(), investigation.Name())
	return &triggersv1.InterceptorResponse{
		Continue: true,
	}
}

func shouldRunAIInvestigation(pdClient pagerduty.Client, ocmClient ocm.Client) bool {
	aiConfig, err := aiconfig.ParseAIAgentConfig()
	if err != nil {
		logging.Warnf("Failed to parse AI config: %v", err)
		return false
	}

	if aiConfig == nil || !aiConfig.Enabled {
		return false
	}

	clusterID, err := pdClient.RetrieveClusterID()
	if err != nil {
		logging.Warnf("Cannot run AI investigation: failed to retrieve cluster ID: %v", err)
		return false
	}

	orgID, err := ocmClient.GetOrganizationID(clusterID)
	if err != nil {
		logging.Warnf("Cannot run AI investigation: failed to get org ID for cluster %s: %v", clusterID, err)
		return false
	}

	if !aiConfig.IsAllowedForAI(clusterID, orgID) {
		logging.Debugf("Cluster %s (org: %s) not in AI allowlist", clusterID, orgID)
		return false
	}

	return true
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

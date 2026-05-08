package interceptor

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"

	"testing"

	ocmmock "github.com/openshift/configuration-anomaly-detection/pkg/ocm/mock"
	pdmock "github.com/openshift/configuration-anomaly-detection/pkg/pagerduty/mock"
	"go.uber.org/mock/gomock"
)

func TestReassignToOrgEscalationPolicy(t *testing.T) {
	tests := []struct {
		name                 string
		orgMap               map[string]string
		clusterID            string
		clusterIDErr         error
		orgID                string
		orgIDErr             error
		moveToEPErr          error
		addNoteErr           error
		expectMoveToEP       bool
		expectMoveToEPPolicy string
		expectAddNote        bool
		expectNoteContains   string
	}{
		{
			name:                 "scenario 1: cluster in mapped org should reassign",
			orgMap:               map[string]string{"org-123": "POL123"},
			clusterID:            "cluster-1",
			orgID:                "org-123",
			expectMoveToEP:       true,
			expectMoveToEPPolicy: "POL123",
			expectAddNote:        true,
			expectNoteContains:   "Reassigned to organization org-123",
		},
		{
			name:           "scenario 2: cluster in unmapped org should skip",
			orgMap:         map[string]string{"org-123": "POL123"},
			clusterID:      "cluster-1",
			orgID:          "org-456",
			expectMoveToEP: false,
			expectAddNote:  false,
		},
		{
			name:           "scenario 3: empty org mapping should skip",
			orgMap:         map[string]string{},
			clusterID:      "cluster-1",
			orgID:          "org-123",
			expectMoveToEP: false,
			expectAddNote:  false,
		},
		{
			name:           "scenario 4: retrieve cluster ID fails should skip",
			orgMap:         map[string]string{"org-123": "POL123"},
			clusterIDErr:   errors.New("failed to retrieve cluster ID"),
			expectMoveToEP: false,
			expectAddNote:  false,
		},
		{
			name:           "scenario 5: get org ID fails should skip",
			orgMap:         map[string]string{"org-123": "POL123"},
			clusterID:      "cluster-1",
			orgIDErr:       errors.New("OCM error"),
			expectMoveToEP: false,
			expectAddNote:  false,
		},
		{
			name:                 "scenario 6: move to escalation policy fails should add failure note",
			orgMap:               map[string]string{"org-123": "POL123"},
			clusterID:            "cluster-1",
			orgID:                "org-123",
			moveToEPErr:          errors.New("invalid policy"),
			expectMoveToEP:       true,
			expectMoveToEPPolicy: "POL123",
			expectAddNote:        true,
			expectNoteContains:   "CAD failed to reassign",
		},
		{
			name:           "scenario 7: empty org ID should skip",
			orgMap:         map[string]string{"org-123": "POL123"},
			clusterID:      "cluster-1",
			orgID:          "",
			expectMoveToEP: false,
			expectAddNote:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockPD := pdmock.NewMockClient(ctrl)
			mockOCM := ocmmock.NewMockClient(ctrl)

			// Setup expectations
			switch {
			case len(tt.orgMap) == 0:
				// Empty map, no expectations
			case tt.clusterIDErr != nil:
				mockPD.EXPECT().RetrieveClusterID().Return(tt.clusterID, tt.clusterIDErr).Times(1)
			case tt.orgIDErr != nil || tt.orgID == "":
				mockPD.EXPECT().RetrieveClusterID().Return(tt.clusterID, nil).Times(1)
				mockOCM.EXPECT().GetOrganizationID(tt.clusterID).Return(tt.orgID, tt.orgIDErr).Times(1)
			case tt.expectMoveToEP:
				mockPD.EXPECT().RetrieveClusterID().Return(tt.clusterID, nil).Times(1)
				mockOCM.EXPECT().GetOrganizationID(tt.clusterID).Return(tt.orgID, nil).Times(1)
				mockPD.EXPECT().MoveToEscalationPolicy(tt.expectMoveToEPPolicy).Return(tt.moveToEPErr).Times(1)
				if tt.expectAddNote {
					mockPD.EXPECT().AddNote(gomock.Any()).DoAndReturn(func(note string) error {
						if tt.expectNoteContains != "" && !contains(note, tt.expectNoteContains) {
							t.Errorf("AddNote() note = %q, want to contain %q", note, tt.expectNoteContains)
						}
						return tt.addNoteErr
					}).Times(1)
				}
			default:
				// Org not in mapping
				mockPD.EXPECT().RetrieveClusterID().Return(tt.clusterID, nil).Times(1)
				mockOCM.EXPECT().GetOrganizationID(tt.clusterID).Return(tt.orgID, nil).Times(1)
			}

			// Execute
			reassignToOrgEscalationPolicy(mockPD, mockOCM, tt.orgMap)
		})
	}
}

func TestClusterExists(t *testing.T) {
	tests := []struct {
		name           string
		clusterID      string
		clusterIDErr   error
		clusterInfoErr error
		expectContinue *bool // nil means we expect no response (success)
	}{
		{
			name:           "scenario 1: RetrieveClusterID fails — short-circuit Continue:false",
			clusterIDErr:   errors.New("no cluster ID found"),
			expectContinue: boolPtr(false),
		},
		{
			name:           "scenario 2: RetrieveClusterID ok but GetClusterInfo fails — short-circuit Continue:false",
			clusterID:      "cluster-abc",
			clusterInfoErr: errors.New("cluster not found in OCM"),
			expectContinue: boolPtr(false),
		},
		{
			name:           "scenario 3: both succeed — nil response, clusterID returned",
			clusterID:      "cluster-abc",
			expectContinue: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockPD := pdmock.NewMockClient(ctrl)
			mockOCM := ocmmock.NewMockClient(ctrl)

			// Setup expectations
			if tt.clusterIDErr != nil {
				mockPD.EXPECT().RetrieveClusterID().Return("", tt.clusterIDErr).Times(1)
			} else {
				mockPD.EXPECT().RetrieveClusterID().Return(tt.clusterID, nil).Times(1)
				if tt.clusterInfoErr != nil {
					mockOCM.EXPECT().GetClusterInfo(tt.clusterID).Return(nil, tt.clusterInfoErr).Times(1)
				} else {
					mockOCM.EXPECT().GetClusterInfo(tt.clusterID).Return(nil, nil).Times(1)
				}
			}

			// Execute
			resp := clusterExists(mockPD, mockOCM)

			// Assert response
			if tt.expectContinue == nil {
				if resp != nil {
					t.Errorf("validateCluster() resp = %+v, want nil", resp)
				}
			} else {
				if resp == nil {
					t.Fatal("validateCluster() resp = nil, want non-nil")
				}
				if resp.Continue != *tt.expectContinue {
					t.Errorf("validateCluster() resp.Continue = %v, want %v", resp.Continue, *tt.expectContinue)
				}
			}
		})
	}
}

func boolPtr(b bool) *bool { return &b }

func contains(s, substr string) bool {
	return len(s) >= len(substr) && stringContains(s, substr)
}

func stringContains(s, substr string) bool {
	if len(substr) == 0 {
		return true
	}
	if len(s) < len(substr) {
		return false
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestOversizedRequestBodyIsRejected(t *testing.T) {
	oversizedBody := bytes.Repeat([]byte("A"), 10*1024*1024) // 10 MiB
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(oversizedBody))
	rec := httptest.NewRecorder()

	handler := CreateInterceptorHandler([]string{"TEST"})
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("expected status 413 for oversized body, got %d: %s", rec.Code, rec.Body.String())
	}
}

// pdSignatureFor computes the HMAC-SHA256 signature for a PagerDuty v3 webhook
// body, returning it in the "v1=<hex>" format expected by X-PagerDuty-Signature.
func pdSignatureFor(secret, body string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(body))
	return "v1=" + hex.EncodeToString(mac.Sum(nil))
}

// makeSignedRequest builds an interceptor HTTP request whose body is the
// double-wrapped JSON that executeInterceptor expects:
//
//	{ "body": "<innerBody>", "header": { "X-PagerDuty-Signature": ["v1=<hmac>"] } }
//
// The HMAC is computed over innerBody using signingSecret, exactly as
// webhookv3.VerifySignature validates incoming PagerDuty webhooks.
func makeSignedRequest(t *testing.T, innerBody, signingSecret string) *http.Request {
	t.Helper()
	sig := pdSignatureFor(signingSecret, innerBody)

	outer, err := json.Marshal(map[string]interface{}{
		"body": innerBody,
		"header": map[string][]string{
			"X-PagerDuty-Signature": {sig},
		},
	})
	if err != nil {
		t.Fatalf("makeSignedRequest: marshal: %v", err)
	}
	return httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(outer))
}

// TestSignatureVerification covers the multiple-signature verification loop.
//
// Key behaviours under test:
//   - Backwards compat: a single token still works exactly as before.
//   - Any-one-wins: a request signed by any one of the configured tokens is
//     accepted, even if other tokens don't match.
//   - All-must-fail: a request is rejected only when every configured token
//     fails to verify the signature.
//   - Empty list: a handler with no tokens configured always rejects.
//
// A valid signature causes executeInterceptor to proceed past the 400-returning
// guard and into process(), which always returns an InterceptorResponse (HTTP
// 200). An invalid signature is caught before that and returns HTTP 400 with
// "signature" in the body. This gives a clean binary signal for each case.
//
// Note: webhookv3.VerifySignature restores r.Body after reading it, so
// iterating the same extractedRequest over multiple tokens is safe.
func TestSignatureVerification(t *testing.T) {
	const (
		secret1   = "signing-secret-one"
		secret2   = "signing-secret-two"
		innerBody = `{"__pd_metadata":{"incident":{"id":"QTEST1"}}}`
	)

	tests := []struct {
		name             string
		tokens           []string
		signingSecret    string // secret used to sign the outgoing request
		wantStatus       int
		wantBodyContains string // substring that must appear in the response on failure
	}{
		// Backwards-compatibility: existing single-token deployments must still work.
		{
			name:          "single valid token — request accepted",
			tokens:        []string{secret1},
			signingSecret: secret1,
			wantStatus:    http.StatusOK,
		},
		{
			name:             "single invalid token — request rejected",
			tokens:           []string{"wrong-secret"},
			signingSecret:    secret1,
			wantStatus:       http.StatusBadRequest,
			wantBodyContains: "signature",
		},
		// Multi-token: accepted when the first configured token matches.
		{
			name:          "multiple tokens, first matches — request accepted",
			tokens:        []string{secret1, secret2},
			signingSecret: secret1,
			wantStatus:    http.StatusOK,
		},
		// Multi-token: accepted when the second configured token matches (first fails).
		// This is the core new behaviour: the loop must continue past the first failure.
		{
			name:          "multiple tokens, second matches — request accepted",
			tokens:        []string{secret2, secret1},
			signingSecret: secret1,
			wantStatus:    http.StatusOK,
		},
		// Multi-token: rejected only when every token fails.
		{
			name:             "multiple tokens, none match — request rejected",
			tokens:           []string{"wrong-one", "wrong-two"},
			signingSecret:    secret1,
			wantStatus:       http.StatusBadRequest,
			wantBodyContains: "signature",
		},
		// Edge case: no tokens configured — nothing can ever verify, reject all.
		{
			name:             "empty token list — request rejected",
			tokens:           []string{},
			signingSecret:    secret1,
			wantStatus:       http.StatusBadRequest,
			wantBodyContains: "signature",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := makeSignedRequest(t, innerBody, tt.signingSecret)
			rec := httptest.NewRecorder()

			CreateInterceptorHandler(tt.tokens).ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d (body: %s)", rec.Code, tt.wantStatus, rec.Body.String())
			}
			if tt.wantBodyContains != "" && !stringContains(rec.Body.String(), tt.wantBodyContains) {
				t.Errorf("body = %q, want it to contain %q", rec.Body.String(), tt.wantBodyContains)
			}
		})
	}
}

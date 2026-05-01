package interceptor

import (
	"errors"
	"os"
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
		expectContinue *bool                // nil means we expect no response (success)
		expectErrorKey *ErrorCodeWithReason // nil means no error stat expected
	}{
		{
			name:           "scenario 1: RetrieveClusterID fails — short-circuit Continue:false",
			clusterIDErr:   errors.New("no cluster ID found"),
			expectContinue: boolPtr(false),
			expectErrorKey: &ErrorCodeWithReason{404, "no cluster id in pagerduty"},
		},
		{
			name:           "scenario 2: RetrieveClusterID ok but GetClusterInfo fails — short-circuit Continue:false",
			clusterID:      "cluster-abc",
			clusterInfoErr: errors.New("cluster not found in OCM"),
			expectContinue: boolPtr(false),
			expectErrorKey: &ErrorCodeWithReason{404, "no cluster in OCM"},
		},
		{
			name:           "scenario 3: both succeed — nil response, clusterID returned",
			clusterID:      "cluster-abc",
			expectContinue: nil,
			expectErrorKey: nil,
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

func TestShouldRunAIInvestigation(t *testing.T) {
	// Helper to write a filter config file and set the env var.
	setupFilterConfig := func(t *testing.T, yaml string) {
		t.Helper()
		path := t.TempDir() + "/filter.yaml"
		if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Setenv("CAD_INVESTIGATION_CONFIG_PATH", path)
	}

	tests := []struct {
		name         string
		filterYAML   string // empty = no filter config
		expectResult bool
	}{
		{
			name:         "no filter config — AI disabled",
			filterYAML:   "",
			expectResult: false,
		},
		{
			name: "filter config without aiassisted entry — AI disabled",
			filterYAML: `
filters:
  - investigation: mustgather
    when:
      field: CloudProvider
      operator: in
      values: ["aws"]
`,
			expectResult: false,
		},
		{
			name: "no ai_agent config — AI disabled",
			filterYAML: `
filters:
  - investigation: mustgather
    when:
      field: CloudProvider
      operator: in
      values: ["aws"]
`,
			expectResult: false,
		},
		{
			name: "ai_agent and aiassisted filter present — AI enabled",
			filterYAML: `
ai_agent:
  runtime_arn: "arn:test"
  user_id: "test"
  region: "us-east-1"
filters:
  - investigation: aiassisted
    when:
      or:
        - field: ClusterID
          operator: in
          values: ["cluster-1"]
`,
			expectResult: true,
		},
		{
			name: "aiassisted with no filter tree — AI disabled (filter required)",
			filterYAML: `
ai_agent:
  runtime_arn: "arn:test"
  user_id: "test"
  region: "us-east-1"
filters:
  - investigation: aiassisted
`,
			expectResult: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.filterYAML != "" {
				setupFilterConfig(t, tt.filterYAML)
			} else {
				t.Setenv("CAD_INVESTIGATION_CONFIG_PATH", "")
			}

			result := shouldRunAIInvestigation()

			if result != tt.expectResult {
				t.Errorf("shouldRunAIInvestigation() = %v, want %v", result, tt.expectResult)
			}
		})
	}
}

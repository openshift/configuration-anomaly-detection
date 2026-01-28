package interceptor

import (
	"errors"
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
	tests := []struct {
		name         string
		aiConfigEnv  string
		clusterID    string
		clusterIDErr error
		orgID        string
		orgIDErr     error
		expectResult bool
	}{
		{
			name:         "AI config not set",
			aiConfigEnv:  "",
			expectResult: false,
		},
		{
			name:         "AI disabled",
			aiConfigEnv:  `{"enabled":false,"runtime_arn":"test","region":"us-east-1","user_id":"test"}`,
			expectResult: false,
		},
		{
			name:         "cluster ID retrieval fails",
			aiConfigEnv:  `{"enabled":true,"runtime_arn":"test","region":"us-east-1","user_id":"test","clusters":[],"organizations":["org-123"]}`,
			clusterIDErr: errors.New("cluster not found"),
			expectResult: false,
		},
		{
			name:         "org ID retrieval fails",
			aiConfigEnv:  `{"enabled":true,"runtime_arn":"test","region":"us-east-1","user_id":"test","clusters":[],"organizations":["org-123"]}`,
			clusterID:    "cluster-1",
			orgIDErr:     errors.New("org not found"),
			expectResult: false,
		},
		{
			name:         "cluster not in allowlist",
			aiConfigEnv:  `{"enabled":true,"runtime_arn":"test","region":"us-east-1","user_id":"test","clusters":["other-cluster"],"organizations":[]}`,
			clusterID:    "cluster-1",
			orgID:        "org-123",
			expectResult: false,
		},
		{
			name:         "org not in allowlist",
			aiConfigEnv:  `{"enabled":true,"runtime_arn":"test","region":"us-east-1","user_id":"test","clusters":[],"organizations":["other-org"]}`,
			clusterID:    "cluster-1",
			orgID:        "org-123",
			expectResult: false,
		},
		{
			name:         "cluster in allowlist",
			aiConfigEnv:  `{"enabled":true,"runtime_arn":"test","region":"us-east-1","user_id":"test","clusters":["cluster-1"],"organizations":[]}`,
			clusterID:    "cluster-1",
			orgID:        "org-123",
			expectResult: true,
		},
		{
			name:         "org in allowlist",
			aiConfigEnv:  `{"enabled":true,"runtime_arn":"test","region":"us-east-1","user_id":"test","clusters":[],"organizations":["org-123"]}`,
			clusterID:    "cluster-1",
			orgID:        "org-123",
			expectResult: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set up environment - always set it to ensure clean state per test
			t.Setenv("CAD_AI_AGENT_CONFIG", tt.aiConfigEnv)

			// Create mocks
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockPD := pdmock.NewMockClient(ctrl)
			mockOCM := ocmmock.NewMockClient(ctrl)

			// Set up expectations
			if tt.aiConfigEnv != "" && stringContains(tt.aiConfigEnv, `"enabled":true`) {
				if tt.clusterIDErr != nil {
					mockPD.EXPECT().RetrieveClusterID().Return("", tt.clusterIDErr).Times(1)
				} else if tt.clusterID != "" {
					mockPD.EXPECT().RetrieveClusterID().Return(tt.clusterID, nil).Times(1)
					if tt.orgIDErr != nil {
						mockOCM.EXPECT().GetOrganizationID(tt.clusterID).Return("", tt.orgIDErr).Times(1)
					} else {
						mockOCM.EXPECT().GetOrganizationID(tt.clusterID).Return(tt.orgID, nil).Times(1)
					}
				}
			}

			// Execute
			result := shouldRunAIInvestigation(mockPD, mockOCM)

			// Verify
			if result != tt.expectResult {
				t.Errorf("shouldRunAIInvestigation() = %v, want %v", result, tt.expectResult)
			}
		})
	}
}

package ocmagentresponsefailure

import (
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"

	cmv1 "github.com/openshift-online/ocm-sdk-go/clustersmgmt/v1"
	awsmock "github.com/openshift/configuration-anomaly-detection/pkg/aws/mock"
	"github.com/openshift/configuration-anomaly-detection/pkg/executor"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/investigation"
	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
	"github.com/openshift/configuration-anomaly-detection/pkg/notewriter"
	"github.com/openshift/configuration-anomaly-detection/pkg/ocm"
	ocmmock "github.com/openshift/configuration-anomaly-detection/pkg/ocm/mock"
	pdmock "github.com/openshift/configuration-anomaly-detection/pkg/pagerduty/mock"
	"github.com/openshift/configuration-anomaly-detection/pkg/types"
	"go.uber.org/mock/gomock"
)

type testMocks struct {
	ctrl      *gomock.Controller
	ocmClient *ocmmock.MockClient
	awsClient *awsmock.MockClient
	pdClient  *pdmock.MockClient
	cluster   *cmv1.Cluster
}

func Test_checkUserBanStatus(t *testing.T) {
	tests := []struct {
		name                string
		want                investigation.InvestigationResult
		wantErr             bool
		cluster             func() *cmv1.Cluster
		setupMocks          func(*testMocks)
		experimentalEnabled bool
	}{
		{
			// this will eventually send out a Service Log
			name: "banned user",
			want: investigation.InvestigationResult{
				Actions: []types.Action{
					&executor.BackplaneReportAction{},
					&executor.PagerDutyNoteAction{},
					&executor.EscalateIncidentAction{},
				},
			},
			setupMocks: func(m *testMocks) {
				m.ocmClient.EXPECT().
					CheckIfUserBanned(m.cluster).
					Return(ocm.UserBannedError{
						Code:        "some_reason",
						Description: "Some reason",
					})
			},
		},
		{
			name: "banned user experimental mode",
			want: investigation.InvestigationResult{
				Actions: []types.Action{
					&executor.BackplaneReportAction{},
					&executor.PagerDutyNoteAction{},
					&executor.ServiceLogAction{},
					&executor.EscalateIncidentAction{},
				},
			},
			setupMocks: func(m *testMocks) {
				m.ocmClient.EXPECT().
					CheckIfUserBanned(m.cluster).
					Return(ocm.UserBannedError{
						Code:        "some_reason",
						Description: "Some reason",
					})
			},
			experimentalEnabled: true,
		},
		{
			name: "export control compliance",
			want: investigation.InvestigationResult{
				Actions: []types.Action{
					&executor.BackplaneReportAction{},
					&executor.PagerDutyNoteAction{},
					&executor.EscalateIncidentAction{},
				},
			},
			setupMocks: func(m *testMocks) {
				m.ocmClient.EXPECT().
					CheckIfUserBanned(m.cluster).
					Return(ocm.UserBannedError{
						Code:        "export_control_compliance",
						Description: "Export Control Compliance",
					})
			},
		},
		{
			name: "user is not banned",
			want: investigation.InvestigationResult{
				Actions: []types.Action{},
			},
			setupMocks: func(m *testMocks) {
				m.ocmClient.EXPECT().
					CheckIfUserBanned(m.cluster).
					Return(nil)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			// Create the mocks struct
			m := &testMocks{
				ctrl:      ctrl,
				ocmClient: ocmmock.NewMockClient(ctrl),
				pdClient:  pdmock.NewMockClient(ctrl),
				awsClient: awsmock.NewMockClient(ctrl),
				cluster:   newTestCluster(),
			}

			// Override cluster if test provides custom one
			if tt.cluster != nil {
				m.cluster = tt.cluster()
			}

			// Let test configure its specific mocks
			tt.setupMocks(m)

			// Build resources
			resources := &investigation.Resources{
				Cluster:   m.cluster,
				OcmClient: m.ocmClient,
				PdClient:  m.pdClient,
				AwsClient: m.awsClient,
				Notes:     notewriter.New(tt.name, logging.RawLogger),
			}

			if tt.experimentalEnabled {
				os.Setenv("CAD_EXPERIMENTAL_ENABLED", "true")
			}

			got, err := checkUserBanStatus(resources)

			if (err != nil) != tt.wantErr {
				t.Errorf("wanted error = %v, got %v", tt.wantErr, err)
			}

			assertActionsEqual(t, got.actions, tt.want.Actions)
		})
	}
}

func newTestCluster() *cmv1.Cluster {
	cluster, _ := cmv1.NewCluster().
		ID("test-cluster").
		InfraID("test-infra-id").
		Build()
	return cluster
}

// assertActionsEqual validates the number of expected vs. got actions is equal
// as well as that their types match. Action fields are not validated to keep
// this check simple and decoupled from any specific action type.
func assertActionsEqual(t *testing.T, a1, a2 []types.Action) {
	t.Helper()

	if !slices.EqualFunc(a1, a2, func(a1, a2 types.Action) bool {
		return reflect.TypeOf(a1) == reflect.TypeOf(a2)
	}) {
		fmtTypes := func(actions []types.Action) string {
			s := make([]string, len(actions))
			for i, a := range actions {
				s[i] = reflect.TypeOf(a).String()
			}
			return "[" + strings.Join(s, ", ") + "]"
		}
		t.Errorf("action types mismatch:\n  %s\ndoes not equal\n  %s", fmtTypes(a1), fmtTypes(a2))
	}
}

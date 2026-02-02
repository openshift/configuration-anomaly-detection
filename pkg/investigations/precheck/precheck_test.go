package precheck

import (
	"errors"
	"testing"

	cmv1 "github.com/openshift-online/ocm-sdk-go/clustersmgmt/v1"
	"github.com/openshift/configuration-anomaly-detection/pkg/executor"
	investigation "github.com/openshift/configuration-anomaly-detection/pkg/investigations/investigation"
	ocmmock "github.com/openshift/configuration-anomaly-detection/pkg/ocm/mock"
	pdmock "github.com/openshift/configuration-anomaly-detection/pkg/pagerduty/mock"
	"github.com/openshift/configuration-anomaly-detection/pkg/types"
	"go.uber.org/mock/gomock"
)

func TestInvestigation_Run(t *testing.T) {
	type args struct {
		rb *investigation.ResourceBuilderMock
	}
	tests := []struct {
		name       string
		c          *ClusterStatePrecheck
		args       args
		want       investigation.InvestigationResult
		wantErr    bool
		setupMocks func(*gomock.Controller) (*pdmock.MockClient, *ocmmock.MockClient, *cmv1.Cluster)
	}{
		{
			name: "cloud provider unsupported stops investigation and escalates the alert",
			c:    &ClusterStatePrecheck{},
			want: investigation.InvestigationResult{
				Actions: []types.Action{
					executor.Escalate("CAD could not run an automated investigation on this cluster: unsupported cloud provider."),
				},
				StopInvestigations: errors.New("unsupported cloud provider (non-AWS)"),
			},
			wantErr: false,
			setupMocks: func(ctrl *gomock.Controller) (*pdmock.MockClient, *ocmmock.MockClient, *cmv1.Cluster) {
				pdClient := pdmock.NewMockClient(ctrl)
				ocmClient := ocmmock.NewMockClient(ctrl)
				builder := cmv1.NewCluster()
				builder.State(cmv1.ClusterStateReady)
				builder.GCP(cmv1.NewGCP())
				cluster, _ := builder.Build()

				return pdClient, ocmClient, cluster
			},
		},
		{
			name: "cluster is uninstalling stops investigation and silences the alert",
			c:    &ClusterStatePrecheck{},
			want: investigation.InvestigationResult{
				Actions: []types.Action{
					executor.Silence("CAD: Cluster is already uninstalling"),
				},
				StopInvestigations: errors.New("cluster is already uninstalling"),
			},
			wantErr: false,
			setupMocks: func(ctrl *gomock.Controller) (*pdmock.MockClient, *ocmmock.MockClient, *cmv1.Cluster) {
				pdClient := pdmock.NewMockClient(ctrl)
				ocmClient := ocmmock.NewMockClient(ctrl)

				builder := cmv1.NewCluster()
				builder.State(cmv1.ClusterStateUninstalling)
				cluster, _ := builder.Build()

				return pdClient, ocmClient, cluster
			},
		},
		{
			name: "access protection status unknown escalates",
			c:    &ClusterStatePrecheck{},
			want: investigation.InvestigationResult{
				Actions: []types.Action{
					executor.Escalate("CAD could not determine access protection status for this cluster, as CAD is unable to run against access protected clusters, please investigate manually."),
				},
				StopInvestigations: errors.New("access protection could not be determined"),
			},
			wantErr: false,
			setupMocks: func(ctrl *gomock.Controller) (*pdmock.MockClient, *ocmmock.MockClient, *cmv1.Cluster) {
				pdClient := pdmock.NewMockClient(ctrl)
				ocmClient := ocmmock.NewMockClient(ctrl)

				builder := cmv1.NewCluster()
				builder.State(cmv1.ClusterStateReady)
				builder.AWS(cmv1.NewAWS())
				cluster, _ := builder.Build()

				ocmClient.EXPECT().IsAccessProtected(cluster).Return(false, errors.New("API error"))

				return pdClient, ocmClient, cluster
			},
		},
		{
			name: "access protection enabled escalates",
			c:    &ClusterStatePrecheck{},
			want: investigation.InvestigationResult{
				Actions: []types.Action{
					executor.Escalate("CAD is unable to run against access protected clusters. Please investigate."),
				},
				StopInvestigations: errors.New("cluster is access protected"),
			},
			wantErr: false,
			setupMocks: func(ctrl *gomock.Controller) (*pdmock.MockClient, *ocmmock.MockClient, *cmv1.Cluster) {
				pdClient := pdmock.NewMockClient(ctrl)
				ocmClient := ocmmock.NewMockClient(ctrl)

				builder := cmv1.NewCluster()
				builder.State(cmv1.ClusterStateReady)
				builder.AWS(cmv1.NewAWS())
				cluster, _ := builder.Build()

				ocmClient.EXPECT().IsAccessProtected(cluster).Return(true, nil)

				return pdClient, ocmClient, cluster
			},
		},
		{
			name:    "access protection disabled continues investigation",
			c:       &ClusterStatePrecheck{},
			want:    investigation.InvestigationResult{StopInvestigations: nil},
			wantErr: false,
			setupMocks: func(ctrl *gomock.Controller) (*pdmock.MockClient, *ocmmock.MockClient, *cmv1.Cluster) {
				pdClient := pdmock.NewMockClient(ctrl)
				ocmClient := ocmmock.NewMockClient(ctrl)

				builder := cmv1.NewCluster()
				builder.State(cmv1.ClusterStateReady)
				builder.AWS(cmv1.NewAWS())
				cluster, _ := builder.Build()

				ocmClient.EXPECT().IsAccessProtected(cluster).Return(false, nil)

				return pdClient, ocmClient, cluster
			},
		},
		{
			name: "cloud provider unsupported stops investigation",
			c:    &ClusterStatePrecheck{},
			want: investigation.InvestigationResult{
				Actions: []types.Action{
					executor.Escalate("CAD could not run an automated investigation on this cluster: unsupported cloud provider."),
				},
				StopInvestigations: errors.New("unsupported cloud provider (non-AWS)"),
			},
			setupMocks: func(ctrl *gomock.Controller) (*pdmock.MockClient, *ocmmock.MockClient, *cmv1.Cluster) {
				pdClient := pdmock.NewMockClient(ctrl)
				ocmClient := ocmmock.NewMockClient(ctrl)

				builder := cmv1.NewCluster()
				builder.State(cmv1.ClusterStateReady)
				builder.GCP(cmv1.NewGCP())
				cluster, _ := builder.Build()
				return pdClient, ocmClient, cluster
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockCtrl := gomock.NewController(t)
			defer mockCtrl.Finish()

			pdClient, ocmClient, cluster := tt.setupMocks(mockCtrl)

			tt.args.rb = &investigation.ResourceBuilderMock{
				Resources: &investigation.Resources{
					Cluster:   cluster,
					OcmClient: ocmClient,
					PdClient:  pdClient,
				},
			}

			c := &ClusterStatePrecheck{}
			got, err := c.Run(tt.args.rb)
			if (err != nil) != tt.wantErr {
				t.Errorf("Investigation.Run() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			// Check StopInvestigations error
			if tt.want.StopInvestigations != nil {
				if got.StopInvestigations == nil || got.StopInvestigations.Error() != tt.want.StopInvestigations.Error() {
					t.Errorf("Investigation.Run() StopInvestigations = %v, want %v", got.StopInvestigations, tt.want.StopInvestigations)
				}
			} else if got.StopInvestigations != nil {
				t.Errorf("Investigation.Run() StopInvestigations = %v, want nil", got.StopInvestigations)
			}

			// Check Actions
			if len(tt.want.Actions) != len(got.Actions) {
				t.Errorf("Investigation.Run() Actions length = %d, want %d", len(got.Actions), len(tt.want.Actions))
				return
			}
			for i, wantAction := range tt.want.Actions {
				if got.Actions[i].Type() != wantAction.Type() {
					t.Errorf("Investigation.Run() Actions[%d].Type() = %s, want %s", i, got.Actions[i].Type(), wantAction.Type())
				}
			}
		})
	}
}

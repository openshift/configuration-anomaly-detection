package precheck

import (
	"errors"
	"reflect"
	"testing"

	cmv1 "github.com/openshift-online/ocm-sdk-go/clustersmgmt/v1"
	investigation "github.com/openshift/configuration-anomaly-detection/pkg/investigations/investigation"
	ocmmock "github.com/openshift/configuration-anomaly-detection/pkg/ocm/mock"
	pdmock "github.com/openshift/configuration-anomaly-detection/pkg/pagerduty/mock"
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
			name:    "cloud provider unsupported stops investigation and escalates the alert",
			c:       &ClusterStatePrecheck{},
			want:    investigation.InvestigationResult{StopInvestigations: errors.New("unsupported cloud provider (non-AWS)")},
			wantErr: false,
			setupMocks: func(ctrl *gomock.Controller) (*pdmock.MockClient, *ocmmock.MockClient, *cmv1.Cluster) {
				pdClient := pdmock.NewMockClient(ctrl)
				ocmClient := ocmmock.NewMockClient(ctrl)
				builder := cmv1.NewCluster()
				builder.State(cmv1.ClusterStateReady)
				builder.GCP(cmv1.NewGCP())
				cluster, _ := builder.Build()

				pdClient.EXPECT().EscalateIncidentWithNote("CAD could not run an automated investigation on this cluster: unsupported cloud provider.").Return(nil)

				return pdClient, ocmClient, cluster
			},
		},
		{
			name:    "cluster is uninstalling stops investigation and silences the alert",
			c:       &ClusterStatePrecheck{},
			want:    investigation.InvestigationResult{StopInvestigations: errors.New("cluster is already uninstalling")},
			wantErr: false,
			setupMocks: func(ctrl *gomock.Controller) (*pdmock.MockClient, *ocmmock.MockClient, *cmv1.Cluster) {
				pdClient := pdmock.NewMockClient(ctrl)
				ocmClient := ocmmock.NewMockClient(ctrl)

				builder := cmv1.NewCluster()
				builder.State(cmv1.ClusterStateUninstalling)
				cluster, _ := builder.Build()

				pdClient.EXPECT().SilenceIncidentWithNote("CAD: Cluster is already uninstalling, silencing alert.").Return(nil)

				return pdClient, ocmClient, cluster
			},
		},
		{
			name:    "access protection status unknown escalates",
			c:       &ClusterStatePrecheck{},
			want:    investigation.InvestigationResult{StopInvestigations: errors.New("access protection could not be determined")},
			wantErr: false,
			setupMocks: func(ctrl *gomock.Controller) (*pdmock.MockClient, *ocmmock.MockClient, *cmv1.Cluster) {
				pdClient := pdmock.NewMockClient(ctrl)
				ocmClient := ocmmock.NewMockClient(ctrl)

				builder := cmv1.NewCluster()
				builder.State(cmv1.ClusterStateReady)
				builder.AWS(cmv1.NewAWS())
				cluster, _ := builder.Build()

				ocmClient.EXPECT().IsAccessProtected(cluster).Return(false, errors.New("API error"))
				pdClient.EXPECT().EscalateIncidentWithNote("CAD could not determine access protection status for this cluster, as CAD is unable to run against access protected clusters, please investigate manually.").Return(nil)

				return pdClient, ocmClient, cluster
			},
		},
		{
			name:    "access protection enabled escalates",
			c:       &ClusterStatePrecheck{},
			want:    investigation.InvestigationResult{StopInvestigations: errors.New("cluster is access protected")},
			wantErr: false,
			setupMocks: func(ctrl *gomock.Controller) (*pdmock.MockClient, *ocmmock.MockClient, *cmv1.Cluster) {
				pdClient := pdmock.NewMockClient(ctrl)
				ocmClient := ocmmock.NewMockClient(ctrl)

				builder := cmv1.NewCluster()
				builder.State(cmv1.ClusterStateReady)
				builder.AWS(cmv1.NewAWS())
				cluster, _ := builder.Build()

				ocmClient.EXPECT().IsAccessProtected(cluster).Return(true, nil)
				pdClient.EXPECT().EscalateIncidentWithNote("CAD is unable to run against access protected clusters. Please investigate.").Return(nil)

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
			{
				"cloud provider unsupported stops investigation",
				&ClusterStatePrecheck{},
				args{rb: &investigation.ResourceBuilderMock{
					Resources: &investigation.Resources{
						Cluster:   &cmv1.Cluster{},
						OcmClient: ocmmock.NewMockClient(mockCtrl),
						PdClient:  pdClient,
					},
				}},
				investigation.InvestigationResult{StopInvestigations: errors.New("unsupported cloud provider (non-AWS)")},
				false,
			},
		},
		{
			name: "cloud provider unsupported stops investigation",
			c:    &ClusterStatePrecheck{},
			want: investigation.InvestigationResult{StopInvestigations: errors.New("unsupported cloud provider (non-AWS)")},
			setupMocks: func(ctrl *gomock.Controller) (*pdmock.MockClient, *ocmmock.MockClient, *cmv1.Cluster) {
				pdClient := pdmock.NewMockClient(ctrl)
				pdClient.EXPECT().EscalateIncidentWithNote(gomock.Any())
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
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Investigation.Run() = %v, want %v", got, tt.want)
			}
		})
	}
}

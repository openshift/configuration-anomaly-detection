package precheck

import (
	"reflect"
	"testing"

	cmv1 "github.com/openshift-online/ocm-sdk-go/clustersmgmt/v1"
	investigation "github.com/openshift/configuration-anomaly-detection/pkg/investigations/investigation"
	ocmmock "github.com/openshift/configuration-anomaly-detection/pkg/ocm/mock"
	pdmock "github.com/openshift/configuration-anomaly-detection/pkg/pagerduty/mock"
	"go.uber.org/mock/gomock"
)

func TestInvestigation_Run(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	pdClient := pdmock.NewMockClient(mockCtrl)
	pdClient.EXPECT().EscalateIncidentWithNote(gomock.Any()).Return(nil)
	type args struct {
		rb *investigation.ResourceBuilderMock
	}
	tests := []struct {
		name    string
		c       *ClusterStatePrecheck
		args    args
		want    investigation.InvestigationResult
		wantErr bool
	}{
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
			investigation.InvestigationResult{StopInvestigations: true},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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

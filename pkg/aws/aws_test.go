package aws_test

import (
	"context"
	"errors"
	"testing"

	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	cloudtrailv2 "github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	cloudtrailtypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	ec2v2 "github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2v2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"go.uber.org/mock/gomock"

	cadaws "github.com/openshift/configuration-anomaly-detection/pkg/aws"
	awsmock "github.com/openshift/configuration-anomaly-detection/pkg/aws/mock"
)

func TestSdkClient_FindInstanceStopEvent(t *testing.T) {
	ctrl := gomock.NewController(t)
	cloudtrail := awsmock.NewMockCloudTrailAPI(ctrl)
	cloudtrail.EXPECT().LookupEvents(gomock.Any(), gomock.Cond(func(in *cloudtrailv2.LookupEventsInput) bool {
		return len(in.LookupAttributes) == 1 &&
			in.LookupAttributes[0].AttributeKey == cloudtrailtypes.LookupAttributeKeyResourceName &&
			awsv2.ToString(in.LookupAttributes[0].AttributeValue) == "i-0stopped" &&
			in.StartTime != nil
	}), gomock.Any()).Return(&cloudtrailv2.LookupEventsOutput{
		Events:    []cloudtrailtypes.Event{{EventName: awsv2.String("DescribeInstances")}},
		NextToken: awsv2.String("page-2"),
	}, nil)
	cloudtrail.EXPECT().LookupEvents(gomock.Any(), gomock.Cond(func(in *cloudtrailv2.LookupEventsInput) bool {
		return awsv2.ToString(in.NextToken) == "page-2"
	}), gomock.Any()).Return(&cloudtrailv2.LookupEventsOutput{
		Events: []cloudtrailtypes.Event{{EventName: awsv2.String("StopInstances"), CloudTrailEvent: awsv2.String(`{}`)}},
	}, nil)

	client := &cadaws.SdkClient{CloudtrailClient: cloudtrail}
	event, err := client.FindInstanceStopEvent(context.Background(), "i-0stopped")
	if err != nil {
		t.Fatal(err)
	}
	if event == nil || awsv2.ToString(event.EventName) != "StopInstances" {
		t.Fatalf("expected the instance StopInstances event, got %v", event)
	}
}

func TestSdkClient_FindInstanceStopEventRejectsOldAndFailedStops(t *testing.T) {
	tests := []struct {
		name   string
		events []cloudtrailtypes.Event
		want   bool
	}{
		{
			name: "a later successful start invalidates an earlier stop",
			events: []cloudtrailtypes.Event{
				{EventName: awsv2.String("StartInstances"), CloudTrailEvent: awsv2.String(`{}`)},
				{EventName: awsv2.String("StopInstances"), CloudTrailEvent: awsv2.String(`{}`)},
			},
		},
		{
			name: "a failed stop is not evidence",
			events: []cloudtrailtypes.Event{
				{EventName: awsv2.String("StopInstances"), CloudTrailEvent: awsv2.String(`{"errorCode":"DryRunOperation"}`)},
			},
		},
		{
			name: "a failed stop does not hide an earlier successful stop",
			events: []cloudtrailtypes.Event{
				{EventName: awsv2.String("StopInstances"), CloudTrailEvent: awsv2.String(`{"errorCode":"UnauthorizedOperation"}`)},
				{EventName: awsv2.String("StopInstances"), CloudTrailEvent: awsv2.String(`{}`)},
			},
			want: true,
		},
		{
			name: "a failed start does not invalidate a successful stop",
			events: []cloudtrailtypes.Event{
				{EventName: awsv2.String("StartInstances"), CloudTrailEvent: awsv2.String(`{"errorCode":"UnauthorizedOperation"}`)},
				{EventName: awsv2.String("StopInstances"), CloudTrailEvent: awsv2.String(`{}`)},
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			cloudtrail := awsmock.NewMockCloudTrailAPI(ctrl)
			cloudtrail.EXPECT().LookupEvents(gomock.Any(), gomock.Any(), gomock.Any()).Return(&cloudtrailv2.LookupEventsOutput{Events: tt.events}, nil)
			client := &cadaws.SdkClient{CloudtrailClient: cloudtrail}
			event, err := client.FindInstanceStopEvent(context.Background(), "i-0stopped")
			if tt.want && err != nil {
				t.Fatal(err)
			}
			if !tt.want && !errors.Is(err, cadaws.ErrNoCurrentStopEvent) {
				t.Fatalf("got error %v, want no-current-stop sentinel", err)
			}
			if (event != nil) != tt.want {
				t.Fatalf("got stop event %v, want event=%t", event, tt.want)
			}
		})
	}
}

func setupInstanceMock(t *testing.T, describeResp *ec2v2.DescribeInstancesOutput, describeErr error) cadaws.EC2API {
	t.Helper()
	ctrl := gomock.NewController(t)
	ec2api := awsmock.NewMockEC2API(ctrl)
	ec2api.EXPECT().DescribeInstances(gomock.Any(), gomock.Any()).Return(describeResp, describeErr)
	return ec2api
}

func TestSdkClient_GetInstanceByID(t *testing.T) {
	type fields struct {
		Region           string
		StsClient        cadaws.StsAPI
		Ec2Client        cadaws.EC2API
		CloudTrailClient cadaws.CloudTrailAPI
		BaseConfig       awsv2.Config
	}
	type args struct {
		instanceID string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantID  string
		wantErr bool
	}{
		{
			name: "An existing instance ID returns the matching instance",
			fields: fields{
				Region:           "us-east-1",
				StsClient:        nil,
				Ec2Client:        setupInstanceMock(t, &ec2v2.DescribeInstancesOutput{Reservations: []ec2v2types.Reservation{{Instances: []ec2v2types.Instance{{InstanceId: awsv2.String("i-0abc123")}}}}}, nil),
				CloudTrailClient: nil,
				BaseConfig:       awsv2.Config{},
			},
			args:    args{instanceID: "i-0abc123"},
			wantID:  "i-0abc123",
			wantErr: false,
		},
		{
			// AWS returns an empty reservation list rather than an error for an
			// unknown instance ID, so the method must surface its own not-found error.
			name: "An unknown instance ID returns an error",
			fields: fields{
				Region:           "us-east-1",
				StsClient:        nil,
				Ec2Client:        setupInstanceMock(t, &ec2v2.DescribeInstancesOutput{Reservations: []ec2v2types.Reservation{}}, nil),
				CloudTrailClient: nil,
				BaseConfig:       awsv2.Config{},
			},
			args:    args{instanceID: "i-0missing"},
			wantErr: true,
		},
		{
			name: "An SDK error is propagated",
			fields: fields{
				Region:           "us-east-1",
				StsClient:        nil,
				Ec2Client:        setupInstanceMock(t, nil, errors.New("api down")),
				CloudTrailClient: nil,
				BaseConfig:       awsv2.Config{},
			},
			args:    args{instanceID: "i-0abc123"},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &cadaws.SdkClient{
				Region:           tt.fields.Region,
				StsClient:        tt.fields.StsClient,
				Ec2Client:        tt.fields.Ec2Client,
				CloudtrailClient: tt.fields.CloudTrailClient,
				BaseConfig:       &tt.fields.BaseConfig,
			}
			got, err := c.GetInstanceByID(context.Background(), tt.args.instanceID)
			if (err != nil) != tt.wantErr {
				t.Errorf("SdkClient.GetInstanceByID() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}
			if got.InstanceId == nil || *got.InstanceId != tt.wantID {
				t.Errorf("SdkClient.GetInstanceByID() = %v, want id %v", got.InstanceId, tt.wantID)
			}
		})
	}
}

func setupSubnetMock(t *testing.T, gatewayId *string, mapPublicIps bool) cadaws.EC2API {
	t.Helper()
	ctrl := gomock.NewController(t)
	rtb := []ec2v2types.Route{
		{
			DestinationCidrBlock: awsv2.String("0.0.0.0/0"),
			GatewayId:            gatewayId,
		},
	}
	ec2api := awsmock.NewMockEC2API(ctrl)
	ec2api.EXPECT().DescribeSubnets(gomock.Any(), gomock.Any()).Return(&ec2v2.DescribeSubnetsOutput{
		Subnets: []ec2v2types.Subnet{
			{
				MapPublicIpOnLaunch: awsv2.Bool(mapPublicIps),
				SubnetId:            awsv2.String("subnet-1"),
			},
		},
	}, nil)
	ec2api.EXPECT().DescribeRouteTables(gomock.Any(), gomock.Any()).Return(&ec2v2.DescribeRouteTablesOutput{
		RouteTables: []ec2v2types.RouteTable{
			{
				Routes: rtb,
			},
		},
	}, nil)
	return ec2api
}

func TestSdkClient_IsSubnetPrivate(t *testing.T) {
	type fields struct {
		Region           string
		StsClient        cadaws.StsAPI
		Ec2Client        cadaws.EC2API
		CloudTrailClient cadaws.CloudTrailAPI
		BaseConfig       awsv2.Config
	}
	type args struct {
		subnet string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    bool
		wantErr bool
	}{
		{
			name: "A subnet without a GatewayID is considered private",
			fields: fields{
				Region:           "us-east-1",
				StsClient:        nil,
				Ec2Client:        setupSubnetMock(t, nil, false),
				CloudTrailClient: nil,
				BaseConfig:       awsv2.Config{},
			},
			args: args{
				subnet: "subnet-1",
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "A subnet with an internet gateway ID is considered public",
			fields: fields{
				Region:           "us-east-1",
				StsClient:        nil,
				Ec2Client:        setupSubnetMock(t, awsv2.String("igw-1"), true),
				CloudTrailClient: nil,
				BaseConfig:       awsv2.Config{},
			},
			args: args{
				subnet: "subnet-1",
			},
			want:    false,
			wantErr: false,
		},
		{
			name: "A subnet with an internet gateway ID is public even when MapPublicIpOnLaunch is false",
			fields: fields{
				Region:           "us-east-1",
				StsClient:        nil,
				Ec2Client:        setupSubnetMock(t, awsv2.String("igw-1"), false),
				CloudTrailClient: nil,
				BaseConfig:       awsv2.Config{},
			},
			args: args{
				subnet: "subnet-1",
			},
			want:    false,
			wantErr: false,
		},
		{
			name: "A subnet with an virtual private gateway ID is considered private",
			fields: fields{
				Region:           "us-east-1",
				StsClient:        nil,
				Ec2Client:        setupSubnetMock(t, awsv2.String("vgw-1"), false),
				CloudTrailClient: nil,
				BaseConfig:       awsv2.Config{},
			},
			args: args{
				subnet: "subnet-1",
			},
			want:    true,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &cadaws.SdkClient{
				Region:           tt.fields.Region,
				StsClient:        tt.fields.StsClient,
				Ec2Client:        tt.fields.Ec2Client,
				CloudtrailClient: tt.fields.CloudTrailClient,
				BaseConfig:       &tt.fields.BaseConfig,
			}
			got, err := c.IsSubnetPrivate(tt.args.subnet)
			if (err != nil) != tt.wantErr {
				t.Errorf("SdkClient.IsSubnetPrivate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("SdkClient.IsSubnetPrivate() = %v, want %v", got, tt.want)
			}
		})
	}
}

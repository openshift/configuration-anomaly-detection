// Package aws contains functions related to aws sdk
package aws

import (
	"testing"

	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	ec2v2 "github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2v2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"go.uber.org/mock/gomock"

	awsmock "github.com/openshift/configuration-anomaly-detection/pkg/aws/mock"
)

func setupSubnetMock(t *testing.T, gatewayId *string, mapPublicIps bool) EC2API {
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
		StsClient        StsAPI
		Ec2Client        EC2API
		CloudTrailClient CloudTrailAPI
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
			c := &SdkClient{
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

package aws_test

import (
	"context"
	"errors"
	"testing"

	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	ec2v2 "github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2v2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"go.uber.org/mock/gomock"

	cadaws "github.com/openshift/configuration-anomaly-detection/pkg/aws"
	awsmock "github.com/openshift/configuration-anomaly-detection/pkg/aws/mock"
)

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

func TestSdkClient_GetVpcDhcpConfiguration(t *testing.T) {
	dhcpOut := &ec2v2.DescribeDhcpOptionsOutput{
		DhcpOptions: []ec2v2types.DhcpOptions{{
			DhcpConfigurations: []ec2v2types.DhcpConfiguration{{
				Key:    awsv2.String("domain-name-servers"),
				Values: []ec2v2types.AttributeValue{{Value: awsv2.String("AmazonProvidedDNS")}},
			}},
		}},
	}
	vpc := ec2v2types.Vpc{VpcId: awsv2.String("vpc-1"), DhcpOptionsId: awsv2.String("dopt-1")}

	tests := []struct {
		name      string
		subnetIDs []string
		setup     func(m *awsmock.MockEC2API)
		want      []string
		wantErr   bool
	}{
		{
			name: "Installer-provisioned VPC is resolved via infra ID tag",
			setup: func(m *awsmock.MockEC2API) {
				m.EXPECT().DescribeVpcs(gomock.Any(), &ec2v2.DescribeVpcsInput{
					Filters: []ec2v2types.Filter{{
						Name:   awsv2.String("tag-key"),
						Values: []string{"kubernetes.io/cluster/infra-1"},
					}},
				}).Return(&ec2v2.DescribeVpcsOutput{Vpcs: []ec2v2types.Vpc{vpc}}, nil)
				m.EXPECT().DescribeDhcpOptions(gomock.Any(), gomock.Any()).Return(dhcpOut, nil)
			},
			want: []string{"AmazonProvidedDNS"},
		},
		{
			name:      "BYOVPC is resolved via subnets",
			subnetIDs: []string{"subnet-1", "subnet-2"},
			setup: func(m *awsmock.MockEC2API) {
				m.EXPECT().DescribeSubnets(gomock.Any(), &ec2v2.DescribeSubnetsInput{
					Filters: []ec2v2types.Filter{{
						Name:   awsv2.String("subnet-id"),
						Values: []string{"subnet-1", "subnet-2"},
					}},
				}).Return(&ec2v2.DescribeSubnetsOutput{
					Subnets: []ec2v2types.Subnet{{SubnetId: awsv2.String("subnet-1"), VpcId: awsv2.String("vpc-1")}},
				}, nil)
				m.EXPECT().DescribeVpcs(gomock.Any(), &ec2v2.DescribeVpcsInput{
					VpcIds: []string{"vpc-1"},
				}).Return(&ec2v2.DescribeVpcsOutput{Vpcs: []ec2v2types.Vpc{vpc}}, nil)
				m.EXPECT().DescribeDhcpOptions(gomock.Any(), gomock.Any()).Return(dhcpOut, nil)
			},
			want: []string{"AmazonProvidedDNS"},
		},
		{
			name:      "BYOVPC subnet lookup error is returned",
			subnetIDs: []string{"subnet-1"},
			setup: func(m *awsmock.MockEC2API) {
				m.EXPECT().DescribeSubnets(gomock.Any(), gomock.Any()).Return(nil, errors.New("access denied"))
			},
			wantErr: true,
		},
		{
			name:      "BYOVPC with no subnets found returns error",
			subnetIDs: []string{"subnet-1"},
			setup: func(m *awsmock.MockEC2API) {
				m.EXPECT().DescribeSubnets(gomock.Any(), gomock.Any()).Return(&ec2v2.DescribeSubnetsOutput{}, nil)
			},
			wantErr: true,
		},
		{
			name: "No tagged VPC returns error",
			setup: func(m *awsmock.MockEC2API) {
				m.EXPECT().DescribeVpcs(gomock.Any(), gomock.Any()).Return(&ec2v2.DescribeVpcsOutput{}, nil)
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			ec2api := awsmock.NewMockEC2API(ctrl)
			tt.setup(ec2api)

			c := &cadaws.SdkClient{Ec2Client: ec2api}
			got, err := c.GetVpcDhcpConfiguration(context.Background(), "infra-1", tt.subnetIDs)
			if (err != nil) != tt.wantErr {
				t.Fatalf("SdkClient.GetVpcDhcpConfiguration() error = %v, wantErr %v", err, tt.wantErr)
			}
			if len(got) != len(tt.want) || (len(got) > 0 && got[0] != tt.want[0]) {
				t.Errorf("SdkClient.GetVpcDhcpConfiguration() = %v, want %v", got, tt.want)
			}
		})
	}
}

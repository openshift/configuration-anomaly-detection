package osde2etests

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

// EC2API interface to make testing easier
type EC2API interface {
	RevokeSecurityGroupEgress(ctx context.Context, params *ec2.RevokeSecurityGroupEgressInput, optFns ...func(*ec2.Options)) (*ec2.RevokeSecurityGroupEgressOutput, error)
	AuthorizeSecurityGroupEgress(ctx context.Context, params *ec2.AuthorizeSecurityGroupEgressInput, optFns ...func(*ec2.Options)) (*ec2.AuthorizeSecurityGroupEgressOutput, error)
}

// EC2ClientWrapper wraps the AWS SDK EC2 client to implement our EC2API interface
type EC2ClientWrapper struct {
	Client *ec2.Client
}

// RevokeSecurityGroupEgress implements EC2API
func (w *EC2ClientWrapper) RevokeSecurityGroupEgress(ctx context.Context, params *ec2.RevokeSecurityGroupEgressInput, optFns ...func(*ec2.Options)) (*ec2.RevokeSecurityGroupEgressOutput, error) {
	return w.Client.RevokeSecurityGroupEgress(ctx, params, optFns...)
}

// AuthorizeSecurityGroupEgress implements EC2API
func (w *EC2ClientWrapper) AuthorizeSecurityGroupEgress(ctx context.Context, params *ec2.AuthorizeSecurityGroupEgressInput, optFns ...func(*ec2.Options)) (*ec2.AuthorizeSecurityGroupEgressOutput, error) {
	return w.Client.AuthorizeSecurityGroupEgress(ctx, params, optFns...)
}

// NewEC2ClientWrapper creates a new EC2ClientWrapper that implements EC2API
func NewEC2ClientWrapper(client *ec2.Client) *EC2ClientWrapper {
	return &EC2ClientWrapper{Client: client}
}

// BlockEgress revokes all outbound traffic from the security group
func BlockEgress(ctx context.Context, ec2Client EC2API, securityGroupID string) error {
	input := &ec2.RevokeSecurityGroupEgressInput{
		GroupId: &securityGroupID,
		IpPermissions: []types.IpPermission{
			{
				IpProtocol: awsString("-1"), // -1 = all protocols
				IpRanges: []types.IpRange{
					{CidrIp: awsString("0.0.0.0/0")},
				},
			},
		},
	}
	_, err := ec2Client.RevokeSecurityGroupEgress(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to revoke egress: %w", err)
	}
	return nil
}

// RestoreEgress allows all outbound traffic from the security group
func RestoreEgress(ctx context.Context, ec2Client EC2API, securityGroupID string) error {
	input := &ec2.AuthorizeSecurityGroupEgressInput{
		GroupId: &securityGroupID,
		IpPermissions: []types.IpPermission{
			{
				IpProtocol: awsString("-1"),
				IpRanges: []types.IpRange{
					{CidrIp: awsString("0.0.0.0/0")},
				},
			},
		},
	}
	_, err := ec2Client.AuthorizeSecurityGroupEgress(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to restore egress: %w", err)
	}
	return nil
}

// awsString helper function to convert a string to a pointer
func awsString(value string) *string {
	return &value
}

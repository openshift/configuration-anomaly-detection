package aws

import (
	"context"
	"fmt"

	ec2v2 "github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

// BlockEgress removes 0.0.0.0/0 rule from the security group
func BlockEgress(ctx context.Context, ec2Client EC2API, securityGroupID string) error {
	input := &ec2v2.RevokeSecurityGroupEgressInput{
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

// RestoreEgress re-adds 0.0.0.0/0 rule to the security group
func RestoreEgress(ctx context.Context, ec2Client EC2API, securityGroupID string) error {
	input := &ec2v2.AuthorizeSecurityGroupEgressInput{
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

// Helper to avoid repetitive aws.String(...)
func awsString(value string) *string {
	return &value
}

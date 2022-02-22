package aws

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/aws/aws-sdk-go/service/sts/stsiface"
	_ "github.com/golang/mock/mockgen/model"
)

// Client is a representation of the AWS Client
type AwsClient struct {
	Region    string
	StsClient stsiface.STSAPI
}

// New is used when we already know the secrets and region, without any need to do any lookup.
func NewClient(accessID, accessSecret, token, region string) (AwsClient, error) {
	awsConfig := &aws.Config{
		Region:                        aws.String(region),
		CredentialsChainVerboseErrors: aws.Bool(true),
	}
	awsConfig.Credentials = credentials.NewStaticCredentials(accessID, accessSecret, token)

	s, err := session.NewSession(awsConfig)
	if err != nil {
		return AwsClient{}, err
	}
	return AwsClient{
		Region:    *aws.String(region),
		StsClient: sts.New(s),
	}, nil
}

// AssumeRole is a function to wrap the AWS STS AssumeRole command
func (a AwsClient) AssumeRole(roleARN, region string) (AwsClient, error) {
	input := &sts.AssumeRoleInput{
		RoleArn: &roleARN,
	}
	out, err := a.StsClient.AssumeRole(input)
	if err != nil {
		return AwsClient{}, err
	}
	if region == "" {
		region = a.Region
	}
	return NewClient(*out.Credentials.AccessKeyId, *out.Credentials.SecretAccessKey, *out.Credentials.SessionToken, region)
}

package awsclient

import (
	"os"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/aws/aws-sdk-go/service/sts/stsiface"
	_ "github.com/golang/mock/mockgen/model"
)

//go:generate mockgen -destination=./../../../utils/mocks/aws_client_mocks.go -package=mocks github.com/openshift/configuration-anomaly-detection/pkg/cloudclient/aws/client AwsClient,BuilderIface

// AwsClient is a representation of the upstream AWS client, as opposed to the
// internal representation used by the rest of backplane. This is included in
// the awsClient struct.
type AwsClient interface {
	// sts
	AssumeRole(*sts.AssumeRoleInput) (*sts.AssumeRoleOutput, error)
}

// Client is a representation of the AWS Client
type Client struct {
	stsClient stsiface.STSAPI
	AwsClient
}

// BuilderIface is a representation of the interface needed to create a builder
type BuilderIface interface {
	New(string, string, string, string) (AwsClient, error)
}

// Builder is a struct that returns a new AWS Client
type Builder struct {
	BuilderIface
}

// New is used when we already know the secrets and region, without any need to do any lookup.
func (b *Builder) New(accessID, accessSecret, token, region string) (AwsClient, error) {
	awsConfig := &aws.Config{
		Region:                        aws.String(region),
		CredentialsChainVerboseErrors: aws.Bool(true),
	}
	if token == "" {
		os.Setenv("AWS_ACCESS_KEY_ID", accessID)
		os.Setenv("AWS_SECRET_ACCESS_KEY", accessSecret)
	} else {
		awsConfig.Credentials = credentials.NewStaticCredentials(accessID, accessSecret, token)
	}

	s, err := session.NewSession(awsConfig)
	if err != nil {
		return &Client{}, err
	}
	return &Client{
		stsClient: sts.New(s),
	}, nil
}

// AssumeRole is a function to wrap the AWS STS AssumeRole command
func (a *Client) AssumeRole(input *sts.AssumeRoleInput) (*sts.AssumeRoleOutput, error) {
	return a.stsClient.AssumeRole(input)
}

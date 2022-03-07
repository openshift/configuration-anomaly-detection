package aws

import (
	"fmt"
	"io/ioutil"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/client"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cloudtrail"
	"github.com/aws/aws-sdk-go/service/cloudtrail/cloudtrailiface"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/ec2/ec2iface"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/aws/aws-sdk-go/service/sts/stsiface"
	_ "github.com/golang/mock/mockgen/model"
)

const (
	accessKeyIDFilename       string = "aws_access_key_id"
	secretAccessKeyIDFilename string = "aws_secret_access_key" /* #nosec */
	maxRetries                int    = 3
)

//go:generate mockgen -destination mock/stsmock.go -package $GOPACKAGE github.com/aws/aws-sdk-go/service/sts/stsiface STSAPI
//go:generate mockgen -destination mock/ec2mock.go -package $GOPACKAGE github.com/aws/aws-sdk-go/service/ec2/ec2iface EC2API
//go:generate mockgen -destination mock/cloudtrailmock.go -package $GOPACKAGE github.com/aws/aws-sdk-go/service/cloudtrail/cloudtrailiface CloudTrailAPI

// AwsClient is a representation of the AWS Client
type AwsClient struct {
	Region           string
	StsClient        stsiface.STSAPI
	Ec2Client        ec2iface.EC2API
	CloudTrailClient cloudtrailiface.CloudTrailAPI
}

// New creates a new client and is used when we already know the secrets and region,
// without any need to do any lookup.
func NewClient(accessID, accessSecret, token, region string) (AwsClient, error) {
	awsConfig := &aws.Config{
		Region:                        aws.String(region),
		Credentials:                   credentials.NewStaticCredentials(accessID, accessSecret, token),
		CredentialsChainVerboseErrors: aws.Bool(true),
		Retryer: client.DefaultRetryer{
			NumMaxRetries:    maxRetries,
			MinThrottleDelay: 2 * time.Second,
		},
	}

	s, err := session.NewSession(awsConfig)
	if err != nil {
		return AwsClient{}, err
	}

	ec2Sess, err := session.NewSession(awsConfig)
	if err != nil {
		return AwsClient{}, err
	}

	cloudTrailSess, err := session.NewSession(awsConfig)
	if err != nil {
		return AwsClient{}, err
	}

	return AwsClient{
		Region:           *aws.String(region),
		StsClient:        sts.New(s),
		Ec2Client:        ec2.New(ec2Sess),
		CloudTrailClient: cloudtrail.New(cloudTrailSess),
	}, nil
}

// NewClientFrmFileCredentials creates a new client by reading credentials from a file
func NewClientFrmFileCredentials(dir string, region string) (AwsClient, error) {
	dir = strings.TrimSuffix(dir, "/")
	dir = filepath.Clean(dir)

	accessKeyBytesPath := filepath.Clean(path.Join(dir, accessKeyIDFilename))
	accessKeyBytes, err := ioutil.ReadFile(accessKeyBytesPath)
	if err != nil {
		return AwsClient{}, fmt.Errorf("cannot read accessKeyID '%s' from path  %s", accessKeyIDFilename, dir)
	}
	secretKeyBytesPath := filepath.Clean(path.Join(dir, secretAccessKeyIDFilename))
	secretKeyBytes, err := ioutil.ReadFile(secretKeyBytesPath)
	if err != nil {
		return AwsClient{}, fmt.Errorf("cannot read secretKeyID '%s' from path  %s", secretAccessKeyIDFilename, dir)
	}
	accessKeyID := strings.TrimRight(string(accessKeyBytes), "\n")
	secretKeyID := strings.TrimRight(string(secretKeyBytes), "\n")
	return NewClient(accessKeyID, secretKeyID, "", region)
}

// AssumeRole returns you a new client in the account specified in the roleARN
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
	return NewClient(*out.Credentials.AccessKeyId,
		*out.Credentials.SecretAccessKey,
		*out.Credentials.SessionToken,
		region)
}

// ListRunningInstances lists all running or starting instances that belong to a cluster
func (a *AwsClient) ListRunningInstances(infraId string) ([]*ec2.Instance, error) {
	filters := []*ec2.Filter{
		{
			Name:   aws.String("tag:kubernetes.io/cluster/" + infraId),
			Values: []*string{aws.String("owned")},
		},
		{
			Name:   aws.String("instance-state-name"),
			Values: []*string{aws.String("running"), aws.String("pending")},
		},
	}
	return a.listInstancesWithFilter(filters)
}

// ListStoppedInstances lists all stopped instances that belong to a cluster
func (a *AwsClient) ListStoppedInstances(infraId string) ([]*ec2.Instance, error) {
	filters := []*ec2.Filter{
		{
			Name:   aws.String("tag:kubernetes.io/cluster/" + infraId),
			Values: []*string{aws.String("owned")},
		},
		{
			Name:   aws.String("instance-state-name"),
			Values: []*string{aws.String("stopped")},
		},
	}
	return a.listInstancesWithFilter(filters)
}

// ListInstances lists all stopped instances that belong to a cluster
func (a *AwsClient) ListInstances(infraId string) ([]*ec2.Instance, error) {
	filters := []*ec2.Filter{
		{
			Name:   aws.String("tag:kubernetes.io/cluster/" + infraId),
			Values: []*string{aws.String("owned")},
		},
	}
	return a.listInstancesWithFilter(filters)
}

// listInstancesWithFilter will return a list of ec2 instance by applying a filter
func (a *AwsClient) listInstancesWithFilter(filters []*ec2.Filter) ([]*ec2.Instance, error) {
	in := &ec2.DescribeInstancesInput{
		Filters: filters,
	}

	instances := []*ec2.Instance{}
	for {
		out, err := a.Ec2Client.DescribeInstances(in)
		if err != nil {
			return []*ec2.Instance{}, err
		}
		nextToken := out.NextToken
		for _, res := range out.Reservations {
			instances = append(instances, res.Instances...)
		}
		if nextToken == nil {
			break
		}
	}
	return instances, nil
}

// ListStopInstancesEvents lists StopInstances events from CloudTrail
func (a AwsClient) ListStopInstancesEvents() ([]*cloudtrail.Event, error) {
	in := &cloudtrail.LookupEventsInput{
		LookupAttributes: []*cloudtrail.LookupAttribute{
			{
				AttributeKey:   aws.String("EventName"),
				AttributeValue: aws.String("StopInstances"),
			},
		},
	}
	events := []*cloudtrail.Event{}
	for {
		out, err := a.CloudTrailClient.LookupEvents(in)
		if err != nil {
			return []*cloudtrail.Event{}, err
		}
		nextToken := out.NextToken
		events = append(events, out.Events...)
		if nextToken == nil {
			break
		}
	}
	return events, nil
}

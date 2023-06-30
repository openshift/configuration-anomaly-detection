// Package aws contains functions related to aws sdk
package aws

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
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
	_ "github.com/golang/mock/mockgen/model" //revive:disable:blank-imports used for the mockgen generation
	"github.com/openshift/configuration-anomaly-detection/pkg/services/logging"
	"k8s.io/apimachinery/pkg/util/wait"
)

const (
	accessKeyIDFilename       string = "aws_access_key_id"
	secretAccessKeyIDFilename string = "aws_secret_access_key" /* #nosec G101 -- this is just the fileName, not a key*/
	maxRetries                int    = 3
	backoffUpperLimit                = 5 * time.Minute
)

var (
	stopInstanceDateRegex = regexp.MustCompile(`\((\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}.*)\)`)
)

//go:generate mockgen --build_flags=--mod=readonly -destination mock/stsmock.go -package awsmock github.com/aws/aws-sdk-go/service/sts/stsiface STSAPI
//go:generate mockgen --build_flags=--mod=readonly -destination mock/ec2mock.go -package awsmock github.com/aws/aws-sdk-go/service/ec2/ec2iface EC2API
//go:generate mockgen --build_flags=--mod=readonly -destination mock/cloudtrailmock.go -package awsmock github.com/aws/aws-sdk-go/service/cloudtrail/cloudtrailiface CloudTrailAPI
//go:generate mockgen --build_flags=--mod=readonly -source $GOFILE -destination ./mock/aws.go -package awsmock

// Client is the interface exposing Aws related functions
type Client interface {
	ListRunningInstances(infraID string) ([]*ec2.Instance, error)
	ListNonRunningInstances(infraID string) ([]*ec2.Instance, error)
	PollInstanceStopEventsFor(instances []*ec2.Instance, retryTimes int) ([]*cloudtrail.Event, error)
	GetAWSCredentials() credentials.Value
	GetSecurityGroupID(infraID string) (string, error)
	GetSubnetID(infraID string) ([]string, error)
	IsSubnetPrivate(subnet string) bool
	AssumeRole(roleARN, region string) (*SdkClient, error)
}

// SdkClient is a representation of the AWS Client
type SdkClient struct {
	Region           string
	StsClient        stsiface.STSAPI
	Ec2Client        ec2iface.EC2API
	CloudTrailClient cloudtrailiface.CloudTrailAPI
	Credentials      credentials.Value
}

// NewClient creates a new client and is used when we already know the secrets and region,
// without any need to do any lookup.
func NewClient(accessID, accessSecret, token, region string) (*SdkClient, error) {
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
		return nil, err
	}

	ec2Sess, err := session.NewSession(awsConfig)
	if err != nil {
		return nil, err
	}

	cloudTrailSess, err := session.NewSession(awsConfig)
	if err != nil {
		return nil, err
	}

	credentials, err := awsConfig.Credentials.Get()
	if err != nil {
		return nil, err
	}

	return &SdkClient{
		Region:           *aws.String(region),
		StsClient:        sts.New(s),
		Ec2Client:        ec2.New(ec2Sess),
		CloudTrailClient: cloudtrail.New(cloudTrailSess),
		Credentials:      credentials,
	}, nil
}

// GetAWSCredentials gets the AWS credentials
func (c *SdkClient) GetAWSCredentials() credentials.Value {
	return c.Credentials
}

// NewClientFromFileCredentials creates a new client by reading credentials from a file
func NewClientFromFileCredentials(dir string, region string) (*SdkClient, error) {
	dir = strings.TrimSuffix(dir, "/")
	dir = filepath.Clean(dir)

	accessKeyBytesPath := filepath.Clean(path.Join(dir, accessKeyIDFilename))
	accessKeyBytes, err := os.ReadFile(accessKeyBytesPath)
	if err != nil {
		return nil, fmt.Errorf("cannot read accessKeyID '%s' from path  %s", accessKeyIDFilename, dir)
	}
	secretKeyBytesPath := filepath.Clean(path.Join(dir, secretAccessKeyIDFilename))
	secretKeyBytes, err := os.ReadFile(secretKeyBytesPath)
	if err != nil {
		return nil, fmt.Errorf("cannot read secretKeyID '%s' from path  %s", secretAccessKeyIDFilename, dir)
	}
	accessKeyID := strings.TrimRight(string(accessKeyBytes), "\n")
	secretKeyID := strings.TrimRight(string(secretKeyBytes), "\n")
	return NewClient(accessKeyID, secretKeyID, "", region)
}

// AssumeRole returns you a new client in the account specified in the roleARN
func (c *SdkClient) AssumeRole(roleARN, region string) (*SdkClient, error) {
	input := &sts.AssumeRoleInput{
		RoleArn:         &roleARN,
		RoleSessionName: aws.String("CAD"),
	}
	out, err := c.StsClient.AssumeRole(input)
	if err != nil {
		return nil, err
	}
	if region == "" {
		region = c.Region
	}
	return NewClient(*out.Credentials.AccessKeyId,
		*out.Credentials.SecretAccessKey,
		*out.Credentials.SessionToken,
		region)
}

// ListRunningInstances lists all running or starting instances that belong to a cluster
func (c *SdkClient) ListRunningInstances(infraID string) ([]*ec2.Instance, error) {
	filters := []*ec2.Filter{
		{
			Name:   aws.String("tag:kubernetes.io/cluster/" + infraID),
			Values: []*string{aws.String("owned")},
		},
		{
			Name:   aws.String("instance-state-name"),
			Values: []*string{aws.String("running"), aws.String("pending")},
		},
	}
	return c.listInstancesWithFilter(filters)
}

// ListNonRunningInstances lists all non running instances that belong to a cluster
func (c *SdkClient) ListNonRunningInstances(infraID string) ([]*ec2.Instance, error) {
	filters := []*ec2.Filter{
		{
			Name:   aws.String("tag:kubernetes.io/cluster/" + infraID),
			Values: []*string{aws.String("owned")},
		},
		{
			Name: aws.String("instance-state-name"),
			Values: []*string{
				aws.String("stopped"),
				aws.String("stopping"),
				aws.String("terminated"),
				aws.String("terminating"),
			},
		},
	}
	return c.listInstancesWithFilter(filters)
}

// ListInstances lists all stopped instances that belong to a cluster
func (c *SdkClient) ListInstances(infraID string) ([]*ec2.Instance, error) {
	filters := []*ec2.Filter{
		{
			Name:   aws.String("tag:kubernetes.io/cluster/" + infraID),
			Values: []*string{aws.String("owned")},
		},
	}
	return c.listInstancesWithFilter(filters)
}

// listInstancesWithFilter will return a list of ec2 instance by applying a filter
func (c *SdkClient) listInstancesWithFilter(filters []*ec2.Filter) ([]*ec2.Instance, error) {
	in := &ec2.DescribeInstancesInput{
		Filters: filters,
	}

	var instances []*ec2.Instance
	for {
		out, err := c.Ec2Client.DescribeInstances(in)
		if err != nil {
			return []*ec2.Instance{}, err
		}
		for _, res := range out.Reservations {
			instances = append(instances, res.Instances...)
		}
		if out.NextToken == nil {
			break
		}
		in.NextToken = out.NextToken
	}
	return instances, nil
}

// PollInstanceStopEventsFor will poll the ListAllInstanceStopEvents, and retry on various cases
// the returned events are unique per instance and are the most up to date that exist
func (c *SdkClient) PollInstanceStopEventsFor(instances []*ec2.Instance, retryTimes int) ([]*cloudtrail.Event, error) {
	if len(instances) == 0 {
		return nil, nil
	}

	backoffOptions := wait.Backoff{
		Duration: 2 * time.Second,
		Factor:   2,
		Steps:    retryTimes,
		// How much variance will there be
		Jitter: 0.01,
		Cap:    backoffUpperLimit,
	}

	var events []*cloudtrail.Event

	idToStopTime, err := populateStopTime(instances)
	if err != nil {
		return nil, fmt.Errorf("could not populate the idToCloudtrailEvent map: %w", err)
	}

	logging.Info("Following instances are not running:")
	for k, v := range idToStopTime {
		logging.Infof("%s, stopped running at %s", k, v.String())
	}
	logging.Info("Investigating stopped reason via cloudtrail events...")
	idToCloudtrailEvent := make(map[string]*cloudtrail.Event)

	var executionError error
	err = wait.ExponentialBackoff(backoffOptions, func() (bool, error) {
		executionError = nil

		stoppedInstanceEvents, err := c.ListAllInstanceStopEvents()
		if err != nil {
			executionError = fmt.Errorf("an error occurred in ListAllInstanceStopEvents: %w", err)
			return false, nil
		}

		terminatedInstanceEvents, err := c.ListAllTerminatedInstances()
		if err != nil {
			executionError = fmt.Errorf("an error occurred in ListAllTerminatedInstances: %w", err)
			return false, nil
		}

		// only add events to our investigation, if these events contain
		// at least one of our cluster instances.
		var clusterInstanceEvents []*cloudtrail.Event
		for _, event := range stoppedInstanceEvents {
			if eventContainsInstances(instances, event) {
				clusterInstanceEvents = append(clusterInstanceEvents, event)
				continue
			}
			// Event is not for one of our cluster instances.
			logging.Debugf("Ignoring event with id '%s', as it is unrelated to the cluster.", *event.EventId)
		}

		for _, event := range terminatedInstanceEvents {
			if eventContainsInstances(instances, event) {
				clusterInstanceEvents = append(clusterInstanceEvents, event)
				continue
			}
			// Event is not for one of our cluster instances.
			logging.Debugf("Ignoring event with id '%s', as it is unrelated to the cluster.", *event.EventId)
		}

		// Loop over all stopped and terminate events for our cluster instancs
		for _, event := range clusterInstanceEvents {
			// we have to loop over each resource in each event
			for _, resource := range event.Resources {
				instanceID := *resource.ResourceName
				_, ok := idToStopTime[instanceID]
				if ok {
					storedEvent, ok := idToCloudtrailEvent[instanceID]
					if !ok {
						idToCloudtrailEvent[instanceID] = event
					} else if storedEvent.EventTime.Before(*event.EventTime) {
						// here the event exists already, and we compared it with the eventTime of the current event.
						// We only jump into this else if clause, if the storedEvent happened BEFORE the current event.
						// This means we are overwriting the idToCloudTrailEvent with the "newest" event.
						idToCloudtrailEvent[instanceID] = event
					}
				}
			}
		}
		logging.Infof("%+v", idToCloudtrailEvent)
		for _, instance := range instances {
			instanceID := *instance.InstanceId
			event, ok := idToCloudtrailEvent[instanceID]
			if !ok {
				executionError = fmt.Errorf("the stopped instance %s does not have a StopInstanceEvent", instanceID)
				return false, nil
			}
			logging.Debug("event in idToCloudtrailEvent[instanceID]", instanceID)

			// not checking if the item is in the array as it's a 1-1 mapping
			extractedTime := idToStopTime[instanceID]

			if event.EventTime.Before(extractedTime) {
				executionError = fmt.Errorf("most up to date time is before the instance stopped time")
				return false, nil
			}
		}

		for _, event := range idToCloudtrailEvent {
			if !containsEvent(event, events) {
				events = append(events, event)
			}
		}

		return true, nil
	})
	logging.Infof("%+v", idToCloudtrailEvent)

	if err != nil || executionError != nil {
		if executionError == nil {
			return nil, fmt.Errorf("command failed after a pollTimeout of %v: %w", backoffUpperLimit, err)
		}
		return nil, fmt.Errorf("command failed after a pollTimeout of %v: %v: %w", backoffUpperLimit, err, executionError)
	}

	return events, nil
}

// containsEvent is a little helper function that checks if the list contains an event
func containsEvent(e *cloudtrail.Event, events []*cloudtrail.Event) bool {
	for _, event := range events {
		if event == e {
			return true
		}
	}
	return false
}

// eventContainsInstances returns true, when an event lists at least one
// of the given instances. This function is being used for kicking out events,
// that are unrelated to our cluster.
func eventContainsInstances(instances []*ec2.Instance, event *cloudtrail.Event) bool {
	for _, resource := range event.Resources {
		for _, instance := range instances {
			if *instance.InstanceId == *resource.ResourceName {
				return true
			}
		}
	}
	return false
}

func populateStopTime(instances []*ec2.Instance) (map[string]time.Time, error) {
	idToStopTime := make(map[string]time.Time)
	for _, instance := range instances {
		instanceID := *instance.InstanceId
		if instance.StateTransitionReason == nil || *instance.StateTransitionReason == "" {
			return nil, fmt.Errorf("StateTransitionReason is missing for instance %s, is required", instanceID)
		}
		rawReason := *instance.StateTransitionReason
		extractedTime, err := getTime(rawReason)
		if err != nil {
			return nil, fmt.Errorf("could not extract date for instance %s: %w", *instance.InstanceId, err)
		}
		// not checking if the item is in the array as it's a 1-1 mapping
		idToStopTime[instanceID] = extractedTime
	}
	return idToStopTime, nil

}

func getTime(rawReason string) (time.Time, error) {
	subMatches := stopInstanceDateRegex.FindStringSubmatch(rawReason)
	if subMatches == nil || len(subMatches) < 2 {
		return time.Time{}, fmt.Errorf("did not find matches: raw data %s", rawReason)
	}
	if len(subMatches) != 2 {
		return time.Time{}, fmt.Errorf("found too many matches: raw data %s", rawReason)
	}

	// the time format is this specific time as based on the time code (choosing a different time for the format might break the code)
	extractedTime, err := time.Parse("2006-01-02 15:04:05 MST", subMatches[1])
	if err != nil {
		return time.Time{}, fmt.Errorf("could not parse the time %s: %w", subMatches[1], err)
	}

	return extractedTime, nil
}

// ListAllInstanceStopEvents lists StopInstances events from CloudTrail
func (c *SdkClient) ListAllInstanceStopEvents() ([]*cloudtrail.Event, error) {
	att := &cloudtrail.LookupAttribute{
		AttributeKey:   aws.String("EventName"),
		AttributeValue: aws.String("StopInstances"),
	}
	return c.listAllInstancesAttribute(att)
}

// ListAllTerminatedInstances lists TerminatedInstances events from CloudTrail
func (c *SdkClient) ListAllTerminatedInstances() ([]*cloudtrail.Event, error) {
	att := &cloudtrail.LookupAttribute{
		AttributeKey:   aws.String("EventName"),
		AttributeValue: aws.String("TerminateInstances"),
	}
	return c.listAllInstancesAttribute(att)
}

func (c *SdkClient) listAllInstancesAttribute(att *cloudtrail.LookupAttribute) ([]*cloudtrail.Event, error) {
	// We only look up events that are not older than 2 hours
	since := time.Now().UTC().Add(time.Duration(-2) * time.Hour)
	// We only look up 1000 events maximum
	var maxResults int64 = 1000
	in := &cloudtrail.LookupEventsInput{
		LookupAttributes: []*cloudtrail.LookupAttribute{att},
		MaxResults:       &maxResults,
		StartTime:        &since,
	}
	out, err := c.CloudTrailClient.LookupEvents(in)
	if err != nil {
		return nil, err
	}
	return out.Events, nil
}

// GetSecurityGroupID will return the security group id needed for the network verifier
func (c *SdkClient) GetSecurityGroupID(infraID string) (string, error) {
	in := &ec2.DescribeSecurityGroupsInput{
		Filters: []*ec2.Filter{
			{
				Name:   aws.String("tag:Name"),
				Values: []*string{aws.String(fmt.Sprintf("%s-worker-sg", infraID))},
			},
		},
	}
	out, err := c.Ec2Client.DescribeSecurityGroups(in)
	if err != nil {
		return "", fmt.Errorf("failed to list security group: %w", err)
	}
	if out.SecurityGroups == nil {
		return "", fmt.Errorf("security groups are empty")
	}
	if len(*out.SecurityGroups[0].GroupId) == 0 {
		return "", fmt.Errorf("failed to list security group %s-worker-sg", infraID)
	}
	return *out.SecurityGroups[0].GroupId, nil
}

// GetSubnetID will return the private subnets needed for the network verifier
func (c *SdkClient) GetSubnetID(infraID string) ([]string, error) {
	in := &ec2.DescribeSubnetsInput{
		Filters: []*ec2.Filter{
			{
				Name:   aws.String(fmt.Sprintf("tag:kubernetes.io/cluster/%s", infraID)),
				Values: []*string{aws.String("owned")},
			},
			{
				Name:   aws.String("tag-key"),
				Values: []*string{aws.String("kubernetes.io/role/internal-elb")},
			},
		},
	}
	out, err := c.Ec2Client.DescribeSubnets(in)
	if err != nil {
		return nil, fmt.Errorf("failed to find private subnet for %s: %w", infraID, err)
	}
	if len(out.Subnets) == 0 {
		return nil, fmt.Errorf("found 0 subnets with kubernetes.io/cluster/%s=owned and kubernetes.io/role/internal-elb", infraID)
	}
	return []string{*out.Subnets[0].SubnetId}, nil
}

// IsSubnetPrivate checks if the provided subnet is private
func (c *SdkClient) IsSubnetPrivate(subnet string) bool {
	in := &ec2.DescribeSubnetsInput{
		SubnetIds: []*string{aws.String(subnet)},
	}

	out, _ := c.Ec2Client.DescribeSubnets(in)

	return !*out.Subnets[0].MapPublicIpOnLaunch
}

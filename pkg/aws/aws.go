package aws

import (
	"fmt"
	"io/ioutil"
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
	"k8s.io/apimachinery/pkg/util/wait"
)

const (
	accessKeyIDFilename       string = "aws_access_key_id"
	secretAccessKeyIDFilename string = "aws_secret_access_key" /* #nosec G101 -- this is just the fileName, not a key*/
	maxRetries                int    = 3
	backoffUpperLimit                = 5 * time.Minute
)

var (
	stopInstanceDateRegex = regexp.MustCompile(`\(([0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}.*)\)`)
)

//go:generate mockgen --build_flags=--mod=readonly -destination mock/stsmock.go -package $GOPACKAGE github.com/aws/aws-sdk-go/service/sts/stsiface STSAPI
//go:generate mockgen --build_flags=--mod=readonly -destination mock/ec2mock.go -package $GOPACKAGE github.com/aws/aws-sdk-go/service/ec2/ec2iface EC2API
//go:generate mockgen --build_flags=--mod=readonly -destination mock/cloudtrailmock.go -package $GOPACKAGE github.com/aws/aws-sdk-go/service/cloudtrail/cloudtrailiface CloudTrailAPI

// Client is a representation of the AWS Client
type Client struct {
	Region           string
	StsClient        stsiface.STSAPI
	Ec2Client        ec2iface.EC2API
	CloudTrailClient cloudtrailiface.CloudTrailAPI
}

// NewClient creates a new client and is used when we already know the secrets and region,
// without any need to do any lookup.
func NewClient(accessID, accessSecret, token, region string) (Client, error) {
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
		return Client{}, err
	}

	ec2Sess, err := session.NewSession(awsConfig)
	if err != nil {
		return Client{}, err
	}

	cloudTrailSess, err := session.NewSession(awsConfig)
	if err != nil {
		return Client{}, err
	}

	return Client{
		Region:           *aws.String(region),
		StsClient:        sts.New(s),
		Ec2Client:        ec2.New(ec2Sess),
		CloudTrailClient: cloudtrail.New(cloudTrailSess),
	}, nil
}

// NewClientFromFileCredentials creates a new client by reading credentials from a file
func NewClientFromFileCredentials(dir string, region string) (Client, error) {
	dir = strings.TrimSuffix(dir, "/")
	dir = filepath.Clean(dir)

	accessKeyBytesPath := filepath.Clean(path.Join(dir, accessKeyIDFilename))
	accessKeyBytes, err := ioutil.ReadFile(accessKeyBytesPath)
	if err != nil {
		return Client{}, fmt.Errorf("cannot read accessKeyID '%s' from path  %s", accessKeyIDFilename, dir)
	}
	secretKeyBytesPath := filepath.Clean(path.Join(dir, secretAccessKeyIDFilename))
	secretKeyBytes, err := ioutil.ReadFile(secretKeyBytesPath)
	if err != nil {
		return Client{}, fmt.Errorf("cannot read secretKeyID '%s' from path  %s", secretAccessKeyIDFilename, dir)
	}
	accessKeyID := strings.TrimRight(string(accessKeyBytes), "\n")
	secretKeyID := strings.TrimRight(string(secretKeyBytes), "\n")
	return NewClient(accessKeyID, secretKeyID, "", region)
}

// AssumeRole returns you a new client in the account specified in the roleARN
func (c Client) AssumeRole(roleARN, region string) (Client, error) {
	input := &sts.AssumeRoleInput{
		RoleArn:         &roleARN,
		RoleSessionName: aws.String("CAD"),
	}
	out, err := c.StsClient.AssumeRole(input)
	if err != nil {
		return Client{}, err
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
func (c Client) ListRunningInstances(infraID string) ([]*ec2.Instance, error) {
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
func (c Client) ListNonRunningInstances(infraID string) ([]*ec2.Instance, error) {
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
func (c Client) ListInstances(infraID string) ([]*ec2.Instance, error) {
	filters := []*ec2.Filter{
		{
			Name:   aws.String("tag:kubernetes.io/cluster/" + infraID),
			Values: []*string{aws.String("owned")},
		},
	}
	return c.listInstancesWithFilter(filters)
}

// listInstancesWithFilter will return a list of ec2 instance by applying a filter
func (c Client) listInstancesWithFilter(filters []*ec2.Filter) ([]*ec2.Instance, error) {
	in := &ec2.DescribeInstancesInput{
		Filters: filters,
	}

	instances := []*ec2.Instance{}
	for {
		out, err := c.Ec2Client.DescribeInstances(in)
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

// PollInstanceStopEventsFor will poll the ListAllInstanceStopEvents, and retry on various cases
// the returned events are unique per instance and are the most up to date that exist
func (c Client) PollInstanceStopEventsFor(instances []*ec2.Instance, retryTimes int) ([]*cloudtrail.Event, error) {
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

	fmt.Println("Following instances are not running:")
	for k, v := range idToStopTime {
		fmt.Printf("%s, stopped running at %s\n", k, v.String())
	}
	fmt.Println("Investigating in reason...")
	idToCloudtrailEvent := make(map[string]*cloudtrail.Event)

	var executionError error
	err = wait.ExponentialBackoff(backoffOptions, func() (bool, error) {
		executionError = nil

		localStopEvents, err := c.ListAllInstanceStopEvents()
		if err != nil {
			executionError = fmt.Errorf("an error occurred in ListAllInstanceStopEvents: %w", err)
			return false, nil
		}
		fmt.Println("successfully ListAllInstanceStopEvents")

		localTerminatedEvents, err := c.ListAllTerminatedInstances()
		if err != nil {
			executionError = fmt.Errorf("an error occurred in ListAAllTerminatedInstances: %w", err)
			return false, nil
		}
		fmt.Println("successfully ListAllTerminatedInstances")

		var localEvents []*cloudtrail.Event
		localEvents = append(localEvents, localStopEvents...)
		localEvents = append(localEvents, localTerminatedEvents...)

		for _, event := range localEvents {
			instanceID := *event.Resources[0].ResourceName
			_, ok := idToStopTime[instanceID]
			if ok {
				storedEvent, ok := idToCloudtrailEvent[instanceID]
				if !ok {
					idToCloudtrailEvent[instanceID] = event
				} else if storedEvent.EventTime.Before(*event.EventTime) {
					idToCloudtrailEvent[instanceID] = event
				}
			}
		}
		fmt.Printf("%+v\n", idToCloudtrailEvent)
		for _, instance := range instances {
			instanceID := *instance.InstanceId
			event, ok := idToCloudtrailEvent[instanceID]
			if !ok {
				executionError = fmt.Errorf("the stopped instance %s does not have a StopInstanceEvent", instanceID)
				return false, nil
			}
			fmt.Println("event in idToCloudtrailEvent[instanceID]", instanceID)

			// not checking if the item is in the array as it's a 1-1 mapping
			extractedTime := idToStopTime[instanceID]

			if event.EventTime.Before(extractedTime) {
				executionError = fmt.Errorf("most up to date time is before the instance stopped time")
				return false, nil
			}
		}

		for _, event := range idToCloudtrailEvent {
			events = append(events, event)
		}

		return true, nil
	})
	fmt.Printf("%+v\n", idToCloudtrailEvent)

	if err != nil || executionError != nil {
		if executionError == nil {
			return nil, fmt.Errorf("command failed after a pollTimeout of %v: %w", backoffUpperLimit, err)
		}
		return nil, fmt.Errorf("command failed after a pollTimeout of %v: %v: %w", backoffUpperLimit, err, executionError)
	}

	return events, nil
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
func (c Client) ListAllInstanceStopEvents() ([]*cloudtrail.Event, error) {
	att := &cloudtrail.LookupAttribute{
		AttributeKey:   aws.String("EventName"),
		AttributeValue: aws.String("StopInstances"),
	}
	return c.listAllInstancesAttribute(att)
}

// ListAllTerminatedInstances lists TerminatedInstances events from CloudTrail
func (c Client) ListAllTerminatedInstances() ([]*cloudtrail.Event, error) {
	att := &cloudtrail.LookupAttribute{
		AttributeKey:   aws.String("EventName"),
		AttributeValue: aws.String("TerminateInstances"),
	}
	return c.listAllInstancesAttribute(att)
}

func (c Client) listAllInstancesAttribute(att *cloudtrail.LookupAttribute) ([]*cloudtrail.Event, error) {
	in := &cloudtrail.LookupEventsInput{
		LookupAttributes: []*cloudtrail.LookupAttribute{att},
	}
	var events []*cloudtrail.Event
	for {
		out, err := c.CloudTrailClient.LookupEvents(in)
		if err != nil {
			return nil, err
		}
		nextToken := out.NextToken
		events = append(events, out.Events...)
		if nextToken == nil {
			break
		}
	}
	return events, nil
}

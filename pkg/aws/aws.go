// Package aws contains functions related to aws sdk
package aws

import (
	"context"
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"time"

	// V2 SDK
	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	configv2 "github.com/aws/aws-sdk-go-v2/config"
	credentialsv2 "github.com/aws/aws-sdk-go-v2/credentials"
	cloudtrailv2 "github.com/aws/aws-sdk-go-v2/service/cloudtrail"

	cloudtrailv2types "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	ec2v2 "github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2v2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	stsv2 "github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
	"k8s.io/apimachinery/pkg/util/wait"
)

const (
	maxRetries        int = 3
	backoffUpperLimit     = 5 * time.Minute
)

var stopInstanceDateRegex = regexp.MustCompile(`\((\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}.*)\)`)

//go:generate mockgen -source=aws.go -package=awsmock -destination=mock/aws.go

type EC2API interface {
	DescribeInstances(ctx context.Context, in *ec2v2.DescribeInstancesInput, optFns ...func(*ec2v2.Options)) (*ec2v2.DescribeInstancesOutput, error)
	DescribeSecurityGroups(ctx context.Context, in *ec2v2.DescribeSecurityGroupsInput, optFns ...func(*ec2v2.Options)) (*ec2v2.DescribeSecurityGroupsOutput, error)
	DescribeSubnets(ctx context.Context, in *ec2v2.DescribeSubnetsInput, optFns ...func(*ec2v2.Options)) (*ec2v2.DescribeSubnetsOutput, error)
	DescribeRouteTables(ctx context.Context, in *ec2v2.DescribeRouteTablesInput, optFns ...func(*ec2v2.Options)) (*ec2v2.DescribeRouteTablesOutput, error)
}

type CloudTrailAPI interface {
	LookupEvents(ctx context.Context, in *cloudtrailv2.LookupEventsInput, optFns ...func(*cloudtrailv2.Options)) (*cloudtrailv2.LookupEventsOutput, error)
}

type StsAPI interface {
	AssumeRole(ctx context.Context, in *stsv2.AssumeRoleInput, optFns ...func(*stsv2.Options)) (*stsv2.AssumeRoleOutput, error)
}

type Client interface {
	ListRunningInstances(infraID string) ([]ec2v2types.Instance, error)
	ListNonRunningInstances(infraID string) ([]ec2v2types.Instance, error)
	PollInstanceStopEventsFor(instances []ec2v2types.Instance, retryTimes int) ([]cloudtrailv2types.Event, error)
	GetAWSCredentials() awsv2.Credentials
	GetSecurityGroupID(infraID string) (string, error)
	GetSubnetID(infraID string) ([]string, error)
	IsSubnetPrivate(subnet string) (bool, error)
	GetRouteTableForSubnet(subnetID string) (ec2v2types.RouteTable, error)
}

type SdkClient struct {
	Credentials      awsv2.Credentials
	Region           string
	CloudtrailClient CloudTrailAPI
	Ec2Client        EC2API
	StsClient        StsAPI
}

func NewClient(accessID, accessSecret, token, region string) (*SdkClient, error) {
	staticCredentials := awsv2.NewCredentialsCache(credentialsv2.NewStaticCredentialsProvider(accessID, accessSecret, token))
	config, err := configv2.LoadDefaultConfig(context.TODO(),
		configv2.WithRegion(region),
		configv2.WithCredentialsProvider(staticCredentials),
		configv2.WithRetryer(func() awsv2.Retryer {
			return retry.AddWithMaxBackoffDelay(retry.AddWithMaxAttempts(retry.NewStandard(), maxRetries), time.Second*5)
		}),
	)
	if err != nil {
		return nil, err
	}
	creds, err := config.Credentials.Retrieve(context.TODO())
	if err != nil {
		return nil, err
	}
	return &SdkClient{
		Credentials:      creds,
		Region:           region,
		CloudtrailClient: cloudtrailv2.NewFromConfig(config),
		Ec2Client:        ec2v2.NewFromConfig(config),
		StsClient:        stsv2.NewFromConfig(config),
	}, nil
}

// GetAWSCredentials gets the AWS credentials
func (c *SdkClient) GetAWSCredentials() awsv2.Credentials {
	return c.Credentials
}

// AssumeRole returns you a new client in the account specified in the roleARN
func (c *SdkClient) AssumeRole(roleARN, region string) (*SdkClient, error) {
	input := &stsv2.AssumeRoleInput{
		RoleArn:         &roleARN,
		RoleSessionName: awsv2.String("CAD"),
	}
	out, err := c.StsClient.AssumeRole(context.TODO(), input)
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
func (c *SdkClient) ListRunningInstances(infraID string) ([]ec2v2types.Instance, error) {
	filters := []ec2v2types.Filter{
		{
			Name:   awsv2.String("tag:kubernetes.io/cluster/" + infraID),
			Values: []string{"owned"},
		},
		{
			Name:   awsv2.String("instance-state-name"),
			Values: []string{"running", "pending"},
		},
	}
	return c.listInstancesWithFilter(filters)
}

func (c *SdkClient) listInstancesWithFilter(filters []ec2v2types.Filter) ([]ec2v2types.Instance, error) {
	in := &ec2v2.DescribeInstancesInput{
		Filters: filters,
	}

	var instances []ec2v2types.Instance
	for {
		out, err := c.Ec2Client.DescribeInstances(context.TODO(), in)
		if err != nil {
			return []ec2v2types.Instance{}, err
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

// ListNonRunningInstances lists all non-running instances that belong to a cluster
func (c *SdkClient) ListNonRunningInstances(infraID string) ([]ec2v2types.Instance, error) {
	filters := []ec2v2types.Filter{
		{
			Name:   awsv2.String("tag:kubernetes.io/cluster/" + infraID),
			Values: []string{("owned")},
		},
		{
			Name: awsv2.String("instance-state-name"),
			Values: []string{
				"stopped",
				"stopping",
				"terminated",
				"terminating",
			},
		},
	}
	return c.listInstancesWithFilter(filters)
}

func (c *SdkClient) PollInstanceStopEventsFor(instances []ec2v2types.Instance, retryTimes int) ([]cloudtrailv2types.Event, error) {
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

	var events []cloudtrailv2types.Event

	idToStopTime, err := populateStopTime(instances)
	if err != nil {
		return nil, fmt.Errorf("could not populate the idToCloudtrailEvent map: %w", err)
	}

	logging.Info("Following instances are not running:")
	for k, v := range idToStopTime {
		logging.Infof("%s, stopped running at %s", k, v.String())
	}
	logging.Info("Investigating stopped reason via cloudtrail events...")
	idToCloudtrailEvent := make(map[string]cloudtrailv2types.Event)

	var executionError error
	stoppedInstanceEvents := make([]cloudtrailv2types.Event, 0)
	terminatedInstanceEvents := make([]cloudtrailv2types.Event, 0)
	err = wait.ExponentialBackoff(backoffOptions, func() (bool, error) {
		executionError = nil

		// Retry only in case we haven't retrieved these events in the previous iteration.
		if len(stoppedInstanceEvents) == 0 {
			stoppedInstanceEvents, err = c.ListAllInstanceStopEventsV2()
			if err != nil {
				executionError = fmt.Errorf("an error occurred in ListAllInstanceStopEvents: %w", err)
				//nolint:nilerr
				return false, nil
			}
		}

		// Retry only in case we haven't retrieved these events in the previous
		// iteration (this should never be != 0 as the code is sequential and
		// this is the only part that can trigger the partial-retry)
		if len(terminatedInstanceEvents) == 0 {
			terminatedInstanceEvents, err = c.ListAllTerminatedInstancesV2()
			if err != nil {
				executionError = fmt.Errorf("an error occurred in ListAllTerminatedInstances: %w", err)
				//nolint:nilerr
				return false, nil
			}
		}
		return true, nil
	})

	// only add events to our investigation, if these events contain
	// at least one of our cluster instances.
	var clusterInstanceEvents []cloudtrailv2types.Event
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
	logging.Debugf("%+v", idToCloudtrailEvent)
	for _, instance := range instances {
		instanceID := *instance.InstanceId
		event, ok := idToCloudtrailEvent[instanceID]
		if !ok {
			executionError = fmt.Errorf("the stopped instance %s does not have a StopInstanceEvent", instanceID)
			return nil, executionError
		}
		logging.Debug("event in idToCloudtrailEvent[instanceID]", instanceID)

		// not checking if the item is in the array as it's a 1-1 mapping
		extractedTime := idToStopTime[instanceID]

		if event.EventTime.Before(extractedTime) {
			executionError = fmt.Errorf("most up to date time is before the instance stopped time")
			return nil, executionError
		}
	}

	for _, event := range idToCloudtrailEvent {
		if !containsEvent(event, events) {
			events = append(events, event)
		}
	}

	logging.Debugf("%+v", idToCloudtrailEvent)

	if err != nil || executionError != nil {
		if executionError == nil {
			return nil, fmt.Errorf("command failed after a pollTimeout of %v: %w", backoffUpperLimit, err)
		}
		return nil, fmt.Errorf("command failed after a pollTimeout of %v: %w: %w", backoffUpperLimit, err, executionError)
	}

	return events, nil
}

// ListAllInstanceStopEvents lists StopInstances events from CloudTrail
func (c *SdkClient) ListAllInstanceStopEventsV2() ([]cloudtrailv2types.Event, error) {
	att := cloudtrailv2types.LookupAttribute{
		AttributeKey:   "EventName",
		AttributeValue: awsv2.String("StopInstances"),
	}
	return c.listAllInstancesAttribute(att)
}

// ListAllTerminatedInstances lists TerminatedInstances events from CloudTrail
func (c *SdkClient) ListAllTerminatedInstancesV2() ([]cloudtrailv2types.Event, error) {
	att := cloudtrailv2types.LookupAttribute{
		AttributeKey:   "EventName",
		AttributeValue: awsv2.String("TerminateInstances"),
	}
	return c.listAllInstancesAttribute(att)
}

// GetSecurityGroupID will return the security group id needed for the network verifier
func (c *SdkClient) GetSecurityGroupID(infraID string) (string, error) {
	in := &ec2v2.DescribeSecurityGroupsInput{
		Filters: []ec2v2types.Filter{
			{
				// Prior to 4.16: <infra_id>-master-sg
				// 4.16+: <infra_id>-controlplane
				Name:   awsv2.String("tag:Name"),
				Values: []string{fmt.Sprintf("%s-master-sg", infraID), fmt.Sprintf("%s-controlplane", infraID)},
			},
		},
	}
	out, err := c.Ec2Client.DescribeSecurityGroups(context.TODO(), in)
	if err != nil {
		return "", fmt.Errorf("failed to list security group: %w", err)
	}
	if len(out.SecurityGroups) == 0 {
		return "", fmt.Errorf("security groups are empty")
	}
	if len(*out.SecurityGroups[0].GroupId) == 0 {
		return "", fmt.Errorf("failed to list security groups: %s-master-sg, %s-controlplane", infraID, infraID)
	}
	return *out.SecurityGroups[0].GroupId, nil
}

// GetSubnetID will return the private subnets needed for the network verifier
func (c *SdkClient) GetSubnetID(infraID string) ([]string, error) {
	in := &ec2v2.DescribeSubnetsInput{
		Filters: []ec2v2types.Filter{
			{
				Name:   awsv2.String("tag-key"),
				Values: []string{fmt.Sprintf("kubernetes.io/cluster/%s", infraID)},
			},
			{
				Name:   awsv2.String("tag-key"),
				Values: []string{"kubernetes.io/role/internal-elb"},
			},
		},
	}
	out, err := c.Ec2Client.DescribeSubnets(context.TODO(), in)
	if err != nil {
		return nil, fmt.Errorf("failed to find private subnet for %s: %w", infraID, err)
	}
	if len(out.Subnets) == 0 {
		return nil, fmt.Errorf("found 0 subnets with kubernetes.io/cluster/%s and kubernetes.io/role/internal-elb", infraID)
	}
	return []string{*out.Subnets[0].SubnetId}, nil
}

// IsSubnetPrivate checks if the provided subnet is private
func (c *SdkClient) IsSubnetPrivate(subnet string) (bool, error) {
	in := &ec2v2.DescribeSubnetsInput{
		SubnetIds: []string{subnet},
	}

	out, err := c.Ec2Client.DescribeSubnets(context.TODO(), in)
	if err != nil {
		return false, err
	}

	// Check the associated routetable for having an internet gateway.
	rtbIn := &ec2v2.DescribeRouteTablesInput{
		Filters: []ec2v2types.Filter{
			{
				Name:   awsv2.String("association.subnet-id"),
				Values: []string{subnet},
			},
		},
	}
	var rtb *ec2v2types.RouteTable
	rtbs, err := c.Ec2Client.DescribeRouteTables(context.TODO(), rtbIn)
	if err != nil {
		return false, err
	}
	if len(rtbs.RouteTables) == 0 {
		rtb, err = c.defaultRouteTableForVpc(*out.Subnets[0].VpcId)
		if err != nil {
			return false, err
		}
	} else {
		rtb = &rtbs.RouteTables[0]
	}
	for _, route := range rtb.Routes {
		// GatewayId can contain an internet gateway *or* a virtual private gateway:
		// "The ID of an internet gateway or virtual private gateway attached to your VPC."
		if route.DestinationCidrBlock == awsv2.String("0.0.0.0/0") &&
			(route.GatewayId != nil && strings.HasPrefix(*route.GatewayId, "igw")) {
			// This is a public subnet
			return false, nil
		}
	}

	return !*out.Subnets[0].MapPublicIpOnLaunch, nil
}

// GetRouteTableForSubnet returns the subnets routeTable
func (c *SdkClient) GetRouteTableForSubnet(subnetID string) (ec2v2types.RouteTable, error) {
	out, err := c.Ec2Client.DescribeRouteTables(context.TODO(), &ec2v2.DescribeRouteTablesInput{
		Filters: []ec2v2types.Filter{
			{
				Name:   awsv2.String("association.subnet-id"),
				Values: []string{subnetID},
			},
		},
	})
	if err != nil {
		return ec2v2types.RouteTable{}, fmt.Errorf("failed to describe route tables associated to subnet %s: %w", subnetID, err)
	}

	var routeTable string

	// If there are no associated RouteTables, then the subnet uses the default RoutTable for the VPC
	if len(out.RouteTables) == 0 {
		vpcID, err := c.findVpcIDForSubnet(subnetID)
		if err != nil {
			return ec2v2types.RouteTable{}, err
		}

		// Set the route table to the default for the VPC
		routeTable, err = c.findDefaultRouteTableForVPC(vpcID)
		if err != nil {
			return ec2v2types.RouteTable{}, err
		}
	} else {
		// Set the route table to the one associated with the subnet
		routeTable = *out.RouteTables[0].RouteTableId
	}

	return c.getRouteTable(routeTable)
}

func (c *SdkClient) defaultRouteTableForVpc(vpcId string) (*ec2v2types.RouteTable, error) {
	describeRouteTablesOutput, err := c.Ec2Client.DescribeRouteTables(context.TODO(), &ec2v2.DescribeRouteTablesInput{
		Filters: []ec2v2types.Filter{{Name: awsv2.String("vpc-id"), Values: []string{vpcId}}},
	})
	if err != nil {
		return nil, err
	}

	for _, rt := range describeRouteTablesOutput.RouteTables {
		for _, assoc := range rt.Associations {
			if *assoc.Main {
				return &rt, nil
			}
		}
	}
	return nil, fmt.Errorf("no default route table found for vpc: %s", vpcId)
}

func (c *SdkClient) listAllInstancesAttribute(att cloudtrailv2types.LookupAttribute) ([]cloudtrailv2types.Event, error) {
	// We only look up events that are not older than 2 hours
	since := time.Now().UTC().Add(time.Duration(-2) * time.Hour)
	// We will only capture this many events via pagination - looping till we
	// exhaust 90 days of events might take *very* long in big accounts
	// otherwise.
	maxNumberEvents := 1000
	events := make([]cloudtrailv2types.Event, 0)
	in := &cloudtrailv2.LookupEventsInput{
		LookupAttributes: []cloudtrailv2types.LookupAttribute{att},
		StartTime:        &since,
	}
	paginator := cloudtrailv2.NewLookupEventsPaginator(c.CloudtrailClient, in)
	// FIXME: Decide if we should just always retrieve *all* events which could
	// be wasteful
	for paginator.HasMorePages() && len(events) < maxNumberEvents {
		out, err := paginator.NextPage(context.TODO())
		if err != nil {
			return nil, err
		}
		events = append(events, out.Events...)
	}
	return events, nil
}

// findVpcIDForSubnet returns the VPC ID for the subnet
func (c *SdkClient) findVpcIDForSubnet(subnetID string) (string, error) {
	describeSubnetOutput, err := c.Ec2Client.DescribeSubnets(context.TODO(), &ec2v2.DescribeSubnetsInput{
		SubnetIds: []string{subnetID},
	})
	if err != nil {
		return "", err
	}
	if len(describeSubnetOutput.Subnets) == 0 {
		return "", fmt.Errorf("no subnets returned for subnet id %v", subnetID)
	}

	return *describeSubnetOutput.Subnets[0].VpcId, nil
}

// findDefaultRouteTableForVPC returns the AWS Route Table ID of the VPC's default Route Table
func (c *SdkClient) findDefaultRouteTableForVPC(vpcID string) (string, error) {
	describeRouteTablesOutput, err := c.Ec2Client.DescribeRouteTables(context.TODO(), &ec2v2.DescribeRouteTablesInput{
		Filters: []ec2v2types.Filter{
			{
				Name:   awsv2.String("vpc-id"),
				Values: []string{vpcID},
			},
		},
	})
	if err != nil {
		return "", fmt.Errorf("failed to describe route tables associated with vpc %s: %w", vpcID, err)
	}

	for _, rt := range describeRouteTablesOutput.RouteTables {
		for _, assoc := range rt.Associations {
			if *assoc.Main {
				return *rt.RouteTableId, nil
			}
		}
	}

	return "", fmt.Errorf("no default route table found for vpc: %s", vpcID)
}

// GetRouteTable takes a routeTable ID and returns a RouteTablesOutput
func (c *SdkClient) getRouteTable(routeTableID string) (ec2v2types.RouteTable, error) {
	describeRouteTablesOutput, err := c.Ec2Client.DescribeRouteTables(context.TODO(), &ec2v2.DescribeRouteTablesInput{
		RouteTableIds: []string{routeTableID},
	})
	if err != nil {
		return ec2v2types.RouteTable{}, err
	}

	if len(describeRouteTablesOutput.RouteTables) == 0 {
		return ec2v2types.RouteTable{}, fmt.Errorf("no route tables found for route table id %v", routeTableID)
	}
	return describeRouteTablesOutput.RouteTables[0], nil
}

func populateStopTime(instances []ec2v2types.Instance) (map[string]time.Time, error) {
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

// containsEvent is a little helper function that checks if the list contains an event
func containsEvent(e cloudtrailv2types.Event, events []cloudtrailv2types.Event) bool {
	for _, event := range events {
		if reflect.DeepEqual(event, e) {
			return true
		}
	}
	return false
}

// eventContainsInstances returns true, when an event lists at least one
// of the given instances. This function is being used for kicking out events,
// that are unrelated to our cluster.
func eventContainsInstances(instances []ec2v2types.Instance, event cloudtrailv2types.Event) bool {
	for _, resource := range event.Resources {
		for _, instance := range instances {
			if *instance.InstanceId == *resource.ResourceName {
				return true
			}
		}
	}
	return false
}

func getTime(rawReason string) (time.Time, error) {
	subMatches := stopInstanceDateRegex.FindStringSubmatch(rawReason)
	if len(subMatches) < 2 {
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

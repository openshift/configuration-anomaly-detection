package chgm

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/openshift/configuration-anomaly-detection/pkg/aws"
	"github.com/openshift/configuration-anomaly-detection/pkg/ocm"

	"github.com/aws/aws-sdk-go/service/cloudtrail"
	"github.com/aws/aws-sdk-go/service/ec2"

	v1 "github.com/openshift-online/ocm-sdk-go/clustersmgmt/v1"
	hivev1 "github.com/openshift/hive/apis/hive/v1"
)

// these type aliases are here to make the types unique and unambiguus when using inside the struct

// AwsClient is a wrapper around the aws client, and is used to import the received functions into the Provider
type AwsClient = aws.Client

// OcmClient is a wrapper around the aws client, and is used to import the received functions into the Provider
type OcmClient = ocm.Client

// Provider should have all of the functions that ChgmService is implementing
type Provider struct {
	// having awsClient and ocmClient this way
	// allows for all of the method receivers defined on them to be passed into the parent struct,
	// thus making it more composable than just having each func redefined here
	//
	// a different solution is to have the structs have unique names to begin with, which makes the code
	// aws.AwsClient feel a bit redundant
	AwsClient
	OcmClient
}

// This will generate mocks for the interfaces in this file
//go:generate mockgen --build_flags=--mod=readonly -source $GOFILE -destination ./mock/interfaces.go -package mock

// Service will wrap all the required commands the client needs to run it's operations
type Service interface {
	// AWS
	ListRunningInstances(infraID string) ([]*ec2.Instance, error)
	ListStoppedInstances(infraID string) ([]*ec2.Instance, error)
	PollInstanceStopEventsFor(instances []*ec2.Instance, retryTimes int) ([]*cloudtrail.Event, error)
	// OCM
	GetClusterDeployment(clusterID string) (*hivev1.ClusterDeployment, error)
	GetClusterInfo(identifier string) (*v1.Cluster, error)
}

// Client is an implementation of the Interface, and adds functionality above it
// to create 'Client' you can use a mock, or fill it with
// this differs from the ChgmProvider as it makes sure you are intentional when using functions.
// if I am missing a func I will copy it from the corresponding package to the interface instead of
// having a function change break my code.
// TODO: decide if the Client should be the ChgmProvider
type Client struct {
	Service
}

// isUserAllowedToStop will verify if a user is allowed to stop instances.
// as this is the thing that might change the most it is at the top.
// additionallyit is private as I don't see anyone using this outside of AreAllInstancesRunning
func isUserAllowedToStop(username string, userDetails CloudTrailEventRaw, infraID string) bool {
	//TODO: what is the best ordering for this? (from the most common to the most rare)

	// operatorIamNames will hold all of the iam names that are allowed to stop instances
	// TODO: (remove when there is more than one item) holds only one item to allow adding IAM stuff later
	// pulled by:
	// 1. logging (via osdctl account cli) into an aws cluster
	// 2. running the command "aws iam list-users --query 'Users[?starts_with(UserName,`<INFRA_ID>`)].UserName'"
	// 3. trimming the infra id from the front and the uuid from the back
	// 4. curate the list down until you have only the required api's
	operatorIamNames := []string{
		"openshift-machine-api-aws",
	}
	for _, operatorIamName := range operatorIamNames {
		// I added an additional '-' in the end to make sure it's the same as close as I can to the aws username (cannot guess the uuid)
		operatorIamName = fmt.Sprintf("%s-%s-", infraID, operatorIamName)
		if strings.HasPrefix(username, operatorIamName) {
			return true
		}
	}

	// I wanted to keep this an if statement, but golangci-lint didn't allow me :(
	if strings.HasPrefix(username, "osdManagedAdmin-") {
		return true
	}

	return assumedRoleOfName("OrganizationAccountAccessRole", userDetails)
}

// UserInfo will hold the extracted user details
type UserInfo struct {
	UserName       string
	IssuerUserName string
}

// InvestigateInstancesOutput is the result of the InvestigateInstances command
type InvestigateInstancesOutput struct {
	NonRunningInstances []*ec2.Instance
	User                UserInfo
	StopTime            time.Time
	UserAuthorized      bool
}

// InvestigateInstances will check all of the instances under the externalID are running.
// in case they are not it will make sure the stopped instances are correctly at this state.
func (c Client) InvestigateInstances(externalID string) (InvestigateInstancesOutput, error) {
	cluster, err := c.GetClusterInfo(externalID)
	if err != nil {
		return InvestigateInstancesOutput{}, fmt.Errorf("could not retrieve cluster info for %s: %w", externalID, err)
	}
	fmt.Println("successfully GetClusterInfo")

	// fmt.Printf("cluster ::: %v\n", cluster)
	id := cluster.ID()

	cd, err := c.GetClusterDeployment(id)
	if err != nil {
		return InvestigateInstancesOutput{}, fmt.Errorf("could not retrieve Cluster Deployment for %s: %w", id, err)
	}
	fmt.Println("successfully GetClusterDeployment")

	// fmt.Printf("cd ::: %v\n", cd)
	infraID := cd.Spec.ClusterMetadata.InfraID

	stoppedInstances, err := c.ListStoppedInstances(infraID)
	if err != nil {
		return InvestigateInstancesOutput{}, fmt.Errorf("could not retrieve stopped instances for %s: %w", infraID, err)
	}
	fmt.Println("successfully ListStoppedInstances")

	// fmt.Printf("stoppedInstances ::: %#v\n", stoppedInstances)

	if len(stoppedInstances) == 0 {
		return InvestigateInstancesOutput{UserAuthorized: true}, nil
	}

	stoppedInstancesEvents, err := c.PollInstanceStopEventsFor(stoppedInstances, 15)
	if err != nil {
		return InvestigateInstancesOutput{}, fmt.Errorf("could not PollStopEventsFor stoppedInstances: %w", err)
	}
	fmt.Println("successfully PollInstanceStopEventsFor")

	// fmt.Printf("stoppedInstancesEvents ::: %#v\n", stoppedInstancesEvents)

	if len(stoppedInstancesEvents) == 0 {
		return InvestigateInstancesOutput{}, fmt.Errorf("the are stopped instances but no stoppedInstancesEvents, this means the instances were stopped too long ago or CloudTrail is not up to date")
	}
	output := InvestigateInstancesOutput{
		NonRunningInstances: stoppedInstances,
		UserAuthorized:      true,
	}
	for _, event := range stoppedInstancesEvents {
		// fmt.Printf("the event is %#v\n", event)
		userDetails, err := extractUserDetails(event.CloudTrailEvent)
		if err != nil {
			resourceData := "with no resources"
			if len(event.Resources) != 0 {
				resourceData = fmt.Sprintf("with resource %v", event.Resources[0].ResourceName)
			}

			return InvestigateInstancesOutput{}, fmt.Errorf("could not extractUserDetails for event %s: %w", resourceData, err)
		}

		output.User = UserInfo{
			UserName:       *event.Username,
			IssuerUserName: userDetails.UserIdentity.SessionContext.SessionIssuer.UserName,
		}
		if !isUserAllowedToStop(*event.Username, userDetails, infraID) {
			output.UserAuthorized = false
		}
	}

	return output, nil
}

// CloudTrailEventRaw will help marshal the cloudtrail.Event.CloudTrailEvent string
// TODO: tidy uo the struct when we know exactly what we need
type CloudTrailEventRaw struct {
	EventVersion string `json:"eventVersion"`
	UserIdentity struct {
		Type           string `json:"type"`
		SessionContext struct {
			SessionIssuer struct {
				Type     string `json:"type"`
				UserName string `json:"userName"`
			} `json:"sessionIssuer"`
		} `json:"sessionContext"`
	} `json:"userIdentity"`
}

// extractUserDetails will take an event and
func extractUserDetails(cloudTrailEvent *string) (CloudTrailEventRaw, error) {
	if cloudTrailEvent == nil || *cloudTrailEvent == "" {
		return CloudTrailEventRaw{}, fmt.Errorf("cannot parse a nil input")
	}
	var res CloudTrailEventRaw
	err := json.Unmarshal([]byte(*cloudTrailEvent), &res)
	if err != nil {
		return CloudTrailEventRaw{}, fmt.Errorf("could not marshal event.CloudTrailEvent: %w", err)
	}
	const supportedEventVersion = "1.08"
	if res.EventVersion != supportedEventVersion {
		return CloudTrailEventRaw{}, fmt.Errorf("event version differs from saved one (got %s, want %s) , not sure it's the same schema", res.EventVersion, supportedEventVersion)
	}
	return res, nil
}

// assumedRoleOfName will verify the SessionIssuer UserName is the same as the provided role
func assumedRoleOfName(role string, userDetails CloudTrailEventRaw) bool {
	userType := userDetails.UserIdentity.Type
	// if the user doing the action is a normal user (not an assumed role), stop processing
	if userType == "IAMUser" {
		return false
	}
	// to make logic less nested, and as the current flow doesn't support other types, stopping on anything not an assumed role
	if userType != "AssumedRole" {
		return false
	}
	// if the type is not role, it's not supported for now
	if userDetails.UserIdentity.SessionContext.SessionIssuer.Type != "Role" {
		return false
	}
	return userDetails.UserIdentity.SessionContext.SessionIssuer.UserName == role
}

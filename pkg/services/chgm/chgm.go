package chgm

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/openshift/configuration-anomaly-detection/pkg/aws"
	"github.com/openshift/configuration-anomaly-detection/pkg/ocm"
	"github.com/openshift/configuration-anomaly-detection/pkg/pagerduty"

	"github.com/aws/aws-sdk-go/service/cloudtrail"
	"github.com/aws/aws-sdk-go/service/ec2"

	v1 "github.com/openshift-online/ocm-sdk-go/clustersmgmt/v1"
	servicelog "github.com/openshift-online/ocm-sdk-go/servicelogs/v1"
	hivev1 "github.com/openshift/hive/apis/hive/v1"
)

// these type aliases are here to make the types unique and unambiguus when using inside the struct

// AwsClient is a wrapper around the aws client, and is used to import the received functions into the Provider
type AwsClient = aws.Client

// OcmClient is a wrapper around the ocm client, and is used to import the received functions into the Provider
type OcmClient = ocm.Client

// PdClient is a wrapper around the pagerduty client, and is used to import the received functions into the Provider
type PdClient = pagerduty.Client

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
	PdClient
}

// This will generate mocks for the interfaces in this file
//go:generate mockgen --build_flags=--mod=readonly -source $GOFILE -destination ./mock/interfaces.go -package mock

// Service will wrap all the required commands the client needs to run it's operations
type Service interface {
	// AWS
	ListRunningInstances(infraID string) ([]*ec2.Instance, error)
	ListNonRunningInstances(infraID string) ([]*ec2.Instance, error)
	PollInstanceStopEventsFor(instances []*ec2.Instance, retryTimes int) ([]*cloudtrail.Event, error)
	// OCM
	GetClusterDeployment(clusterID string) (*hivev1.ClusterDeployment, error)
	GetClusterInfo(identifier string) (*v1.Cluster, error)
	SendCHGMServiceLog(cluster *v1.Cluster) (*servicelog.LogEntry, error)
	// PD
	AddNote(incidentID string, noteContent string) error
	MoveToEscalationPolicy(incidentID string, escalationPolicyID string) error
	GetEscalationPolicy() string
	GetSilentPolicy() string
}

// Client is an implementation of the Interface, and adds functionality above it
// to create 'Client' you can use a mock, or fill it with
// this differs from the ChgmProvider as it makes sure you are intentional when using functions.
// if I am missing a func I will copy it from the corresponding package to the interface instead of
// having a function change break my code.
// TODO: decide if the Client should be the ChgmProvider
type Client struct {
	Service
	cluster *v1.Cluster
	cd      *hivev1.ClusterDeployment
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
	UserAuthorized      bool
}

// String implements the stringer interface for InvestigateInstancesOutput
func (i InvestigateInstancesOutput) String() string {
	msg := ""
	msg += fmt.Sprintf("Is user authorized: '%v' \n", i.UserAuthorized)
	// TODO: check if %v is the best formatting for UserInfo
	msg += fmt.Sprintf("\nUserName : '%v'", i.User.UserName)
	msg += fmt.Sprintf("\nIssuerUserName: '%v'", i.User.IssuerUserName)
	msg += fmt.Sprintf("\nThe amount of non running instances is: '%v'", len(i.NonRunningInstances))
	ids := []string{}
	for _, nonRunningInstance := range i.NonRunningInstances {
		// TODO: add also the StateTransitionReason to the output if needed
		ids = append(ids, *nonRunningInstance.InstanceId)
	}
	if len(i.NonRunningInstances) > 0 {
		msg += fmt.Sprintf("\nInstance IDs: '%v'", ids)
	}
	return msg
}

func (c *Client) populateStuctWith(externalID string) error {
	if c.cluster == nil {
		cluster, err := c.GetClusterInfo(externalID)
		if err != nil {
			return fmt.Errorf("could not retrieve cluster info for %s: %w", externalID, err)
		}
		// fmt.Printf("cluster ::: %v\n", cluster)
		c.cluster = cluster
	}
	id := c.cluster.ID()

	if c.cd == nil {
		cd, err := c.GetClusterDeployment(id)
		if err != nil {
			return fmt.Errorf("could not retrieve Cluster Deployment for %s: %w", id, err)
		}
		c.cd = cd
	}
	// fmt.Printf("cd ::: %v\n", cd)
	return nil
}

// InvestigateInstances will check all of the instances for the cluster are running.
// in case they are not it will make sure the stopped instances are correctly at this state.
func (c *Client) InvestigateInstances(externalID string) (InvestigateInstancesOutput, error) {
	err := c.populateStuctWith(externalID)
	if err != nil {
		return InvestigateInstancesOutput{}, fmt.Errorf("could not populate the struct: %w", err)
	}

	return c.investigateInstances()
}

// SendServiceLog sends a service log to the corresponding cluster
// We have to use this function as wrapper, because otherwise we have no access to the
// cluster. The CHGM package does not export the cluster and cluster deployment yet.
func (c Client) SendServiceLog() error {
	_, err := c.SendCHGMServiceLog(c.cluster)
	if err != nil {
		return fmt.Errorf("could not send service log for %s: %w", c.cluster.Name(), err)
	}
	return nil
}

// investigateInstances is the internal version of investigateInstances operating on the read-only
// version of Client.
func (c Client) investigateInstances() (InvestigateInstancesOutput, error) {

	if c.cd == nil {
		return InvestigateInstancesOutput{}, fmt.Errorf("clusterdeployment is empty, did not populate the instance before")
	}

	infraID := c.cd.Spec.ClusterMetadata.InfraID

	stoppedInstances, err := c.ListNonRunningInstances(infraID)
	if err != nil {
		return InvestigateInstancesOutput{}, fmt.Errorf("could not retrieve non running instances for %s: %w", infraID, err)
	}

	// fmt.Printf("stoppedInstances ::: %#v\n", stoppedInstances)

	if len(stoppedInstances) == 0 {
		return InvestigateInstancesOutput{UserAuthorized: true}, nil
	}

	stoppedInstancesEvents, err := c.PollInstanceStopEventsFor(stoppedInstances, 15)
	if err != nil {
		return InvestigateInstancesOutput{}, fmt.Errorf("could not PollStopEventsFor stoppedInstances: %w", err)
	}

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

// EscalateAlert will ensure that an incident informs a SRE.
// Optionally notes can be added to the incident
func (c Client) EscalateAlert(incidentID, notes string) error {
	return c.updatePagerduty(incidentID, notes, c.GetEscalationPolicy())
}

// SilenceAlert annotates the PagerDuty alert with the given notes and silences it via
// assigning the "Silent Test" escalation policy
func (c Client) SilenceAlert(incidentID, notes string) error {
	return c.updatePagerduty(incidentID, notes, c.GetSilentPolicy())
}

// updatePagerduty attaches notes to an incident and moves it to a escalation policy
func (c Client) updatePagerduty(incidentID, notes, escalationPolicy string) error {
	if notes != "" {
		fmt.Printf("Attaching Note %s\n", notes)
		err := c.AddNote(incidentID, notes)
		if err != nil {
			return fmt.Errorf("failed to attach notes to incident: %w", err)
		}
	}
	fmt.Printf("Moving Alert to Escalation Policy %s\n", escalationPolicy)
	err := c.MoveToEscalationPolicy(incidentID, escalationPolicy)
	if err != nil {
		return fmt.Errorf("failed to change incident escalation policy: %w", err)
	}
	return nil
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

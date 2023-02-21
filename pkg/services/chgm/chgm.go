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
	hivev1 "github.com/openshift/hive/apis/hive/v1"
)

// these type aliases are here to make the types unique and unambiguous when used inside the struct

// AwsClient is a wrapper around the aws client, and is used to import the received functions into the Provider
type AwsClient = aws.Client

// OcmClient is a wrapper around the ocm client, and is used to import the received functions into the Provider
type OcmClient = ocm.Client

// PdClient is a wrapper around the pagerduty client, and is used to import the received functions into the Provider
type PdClient = pagerduty.Client

// Provider should have all the functions that ChgmService is implementing
type Provider struct {
	// having awsClient and ocmClient this way
	// allows for all the method receivers defined on them to be passed into the parent struct,
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

// Service will wrap all the required commands the client needs to run its operations
type Service interface {
	// AWS
	ListRunningInstances(infraID string) ([]*ec2.Instance, error)
	ListNonRunningInstances(infraID string) ([]*ec2.Instance, error)
	PollInstanceStopEventsFor(instances []*ec2.Instance, retryTimes int) ([]*cloudtrail.Event, error)
	// OCM
	GetClusterDeployment(clusterID string) (*hivev1.ClusterDeployment, error)
	GetClusterInfo(identifier string) (*v1.Cluster, error)
	GetClusterMachinePools(clusterID string) ([]*v1.MachinePool, error)
	PostCHGMLimitedSupportReason(clusterID string) (*v1.LimitedSupportReason, error)
	DeleteCHGMLimitedSupportReason(clusterID string) (bool, error)
	DeleteCCAMLimitedSupportReason(clusterID string) (bool, error)
	LimitedSupportReasonsExist(clusterID string) (bool, error)
	NonCADLimitedSupportExists(clusterID string) (bool, error)
	// PD
	AddNote(incidentID string, noteContent string) error
	ExtractServiceIDFromPayload(payloadFilePath string, reader pagerduty.FileReader) (string, error)
	CreateNewAlert(description string, details interface{}, serviceID string) error
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

// isUserAllowedToStop verifies if a user is allowed to stop/terminate instances
func isUserAllowedToStop(username, issuerUsername string, userDetails CloudTrailEventRaw, infraID string) bool {
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
		// HOTFIX(OSD-15308): the value of `username` is not clearly documented and is obtained from the
		// API call made to fetch cloudtrail events. (see https://docs.aws.amazon.com/sdk-for-go/api/service/cloudtrail/#Event)
		// The `openshift-machine-api-aws` operator uses `assumeRole` to perform the node stops/terminations,
		// therefore it is contained in the `issuerUserName` field.
		// To not break anything with this hotfix, we're adding the check on top of the currently likely
		// broken `strings.Contains(username, operatorIamName)`.
		if strings.Contains(issuerUsername, operatorIamName) || strings.Contains(username, operatorIamName) {
			return true
		}
	}

	if strings.HasPrefix(username, "osdManagedAdmin") {
		return true
	}

	// add RH-SRE-* users to authenticated users to escalate the incident for validation.
	// The RH SRE on call should verify if the RH SRE was allowed to shutdown the node instance
	if strings.HasPrefix(username, "RH-SRE-") {
		return true
	}

	// The ManagedOpenshift Installer Role is allowed to shutdown instances, such as the bootstrap instance
	if issuerUsername == "ManagedOpenShift-Installer-Role" {
		return true
	}

	// "OrganizationAccountAccessRole" could be an SRE based on the cluster type
	// - NON-CCS: "OrganizationAccountAccessRole" can only be SRE
	// - CCS: "OrganizationAccountAccessRole" can only be customer
	// 
	// We currently flag all stopped/terminated instances by an user that assumesRoles "OrganizationAccountAccessRole"
	// as authorized, to avoid putting anything in limited support (we don't know if it's SRE).
	// 
	// We could change the logic to know whether or not it was an SRE in the future,
	// as to not unnecessarily page for all "OrganizationAccountAccessRole" instance stops.
	return assumedRoleOfName("OrganizationAccountAccessRole", userDetails)
}

// UserInfo will hold the extracted user details
type UserInfo struct {
	UserName       string
	IssuerUserName string
}

// RunningNodesCount holds the number of actual running nodes
type RunningNodesCount struct {
    Master int
    Infra  int
    Worker int
}

// ExpectedNodesCount holds the number of expected running nodes
type ExpectedNodesCount struct {
    Master    int
    Infra     int
    MinWorker int
    MaxWorker int
}

// InvestigateInstancesOutput is the result of the InvestigateInstances command
type InvestigateInstancesOutput struct {
	NonRunningInstances  []*ec2.Instance
	RunningInstances     RunningNodesCount
	ExpectedInstances    ExpectedNodesCount
	User                 UserInfo
	UserAuthorized       bool
	ClusterState         string
	ClusterNotEvaluated  bool
	LimitedSupportReason *v1.LimitedSupportReason
	Error                string
}

// String implements the stringer interface for InvestigateInstancesOutput
func (i InvestigateInstancesOutput) String() string {
	msg := ""
	msg += fmt.Sprintf("Is user authorized: '%v' \n", i.UserAuthorized)
	// TODO: check if %v is the best formatting for UserInfo
	if i.User.UserName != "" {
		msg += fmt.Sprintf("\nUserName : '%v' \n", i.User.UserName)
	}
	if i.User.IssuerUserName != "" {
		msg += fmt.Sprintf("\nIssuerUserName: '%v' \n", i.User.IssuerUserName)
	}
	msg += fmt.Sprintf("\nNumber of non running instances: '%v' \n", len(i.NonRunningInstances))
    msg += fmt.Sprintf("\nNumber of running instances:\n\tMaster: '%v'\n\tInfra: '%v'\n\tWorker: '%v'\n",
        i.RunningInstances.Master, i.RunningInstances.Infra, i.RunningInstances.Worker)
    msg += fmt.Sprintf("\nNumber of expected instances:\n\tMaster: '%v'\n\tInfra: '%v'\n\tMin Worker: '%v'\n\tMax Worker: '%v'\n",
        i.ExpectedInstances.Master, i.ExpectedInstances.Infra, i.ExpectedInstances.MinWorker, i.ExpectedInstances.MaxWorker)
	var ids []string
	for _, nonRunningInstance := range i.NonRunningInstances {
		// TODO: add also the StateTransitionReason to the output if needed
		ids = append(ids, *nonRunningInstance.InstanceId)
	}
	if len(i.NonRunningInstances) > 0 {
		msg += fmt.Sprintf("\nInstance IDs: '%v' \n", ids)
	}

	if i.LimitedSupportReason.Summary() != "" || i.LimitedSupportReason.Details() != "" {
		msg += fmt.Sprintln("\nLimited Support reason sent:")
		msg += fmt.Sprintf("- Summary: '%s'\n", i.LimitedSupportReason.Summary())
		msg += fmt.Sprintf("- Details: '%s'\n", i.LimitedSupportReason.Details())
	}

	if i.Error != "" {
		msg += fmt.Sprintf("\nErrors: '%v' \n", i.Error)
	}
	return msg
}

func (c *Client) populateStructWith(externalID string) error {
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

// InvestigateStoppedInstances will check all the instances for the cluster are running.
// in case they are not it will make sure the stopped instances are correctly at this state.
func (c *Client) InvestigateStoppedInstances(externalID string) (InvestigateInstancesOutput, error) {
	err := c.populateStructWith(externalID)
	if err != nil {
		return InvestigateInstancesOutput{}, fmt.Errorf("could not populate the struct when investigating stopped instances: %w", err)
	}

	return c.investigateStoppedInstances()
}

// investigateStoppedInstances is the internal version of InvestigateStoppedInstances operating on the read-only
// version of Client.
func (c Client) investigateStoppedInstances() (InvestigateInstancesOutput, error) {
	if c.cd == nil {
		return InvestigateInstancesOutput{}, fmt.Errorf("clusterdeployment is empty when investigating stopped instances, did not populate the instance before")
	}

	infraID := c.cd.Spec.ClusterMetadata.InfraID

	stoppedInstances, err := c.ListNonRunningInstances(infraID)
	if err != nil {
		return InvestigateInstancesOutput{}, fmt.Errorf("could not retrieve non running instances while investigating stopped instances for %s: %w", infraID, err)
	}

	runningNodesCount, err := c.GetRunningNodesCount(infraID)
	if err != nil {
		return InvestigateInstancesOutput{}, fmt.Errorf("could not retrieve running cluster nodes while investigating stopped instances for %s: %w", infraID, err)
	}

	// evaluate number of all supposed nodes
	expectedNodesCount, err := c.GetExpectedNodesCount()
	if err != nil {
		return InvestigateInstancesOutput{}, fmt.Errorf("could not retrieve expected cluster nodes while investigating stopped instances for %s: %w", infraID, err)
	}

	if len(stoppedInstances) == 0 {
		// UserAuthorized: true so SRE will still be alerted for manual investigation
		return InvestigateInstancesOutput{UserAuthorized: true, RunningInstances:  *runningNodesCount,
			ExpectedInstances: *expectedNodesCount, Error: "no non running instances found, terminated instances may have already expired"}, nil
	}

	stoppedInstancesEvents, err := c.PollInstanceStopEventsFor(stoppedInstances, 15)
	if err != nil {
		return InvestigateInstancesOutput{}, fmt.Errorf("could not PollStopEventsFor stoppedInstances: %w", err)
	}

	if len(stoppedInstancesEvents) == 0 {
		return InvestigateInstancesOutput{}, fmt.Errorf("there are stopped instances but no stoppedInstancesEvents, this means the instances were stopped too long ago or CloudTrail is not up to date")
	}

	output := InvestigateInstancesOutput{
		NonRunningInstances: stoppedInstances,
		UserAuthorized:      true,
		RunningInstances:  *runningNodesCount,
		ExpectedInstances: *expectedNodesCount,
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
		if !isUserAllowedToStop(*event.Username, output.User.IssuerUserName, userDetails, infraID) {
			output.UserAuthorized = false
		}
	}

	return output, nil
}

// InvestigateStartedInstances will check whether the instances for the cluster have been properly resumed.
func (c *Client) InvestigateStartedInstances(externalID string) (InvestigateInstancesOutput, error) {
	err := c.populateStructWith(externalID)
	if err != nil {
		return InvestigateInstancesOutput{}, fmt.Errorf("could not populate the struct when investigating started instances: %w", err)
	}

	return c.investigateStartedInstances()
}

// investigateStartedInstances is the internal version of InvestigateStartedInstances operating on the read-only
// version of Client.
func (c Client) investigateStartedInstances() (InvestigateInstancesOutput, error) {
	if c.cd == nil {
		return InvestigateInstancesOutput{}, fmt.Errorf("clusterdeployment is empty when investigating started instances, did not populate the instance before")
	}

	infraID := c.cd.Spec.ClusterMetadata.InfraID

	// Verify cluster is in a valid state to be investigated (ie - not hibernating, powering down, or being deleted)
	state, ok := c.cluster.GetState()
	if !ok {
		return InvestigateInstancesOutput{}, fmt.Errorf("failed to determine if investigation required: cluster '%s' has no state associated with it", c.cluster.ID())
	}
	if state == v1.ClusterStateUninstalling || state == v1.ClusterStatePoweringDown || state == v1.ClusterStateHibernating {
		output := InvestigateInstancesOutput {
			ClusterState:        string(state),
			ClusterNotEvaluated: true,
		}
		return output, nil
	}

	lsExists, err := c.NonCADLimitedSupportExists(c.cluster.ID())
	if err != nil {
		return InvestigateInstancesOutput{}, fmt.Errorf("failed to determine if investigation required: could not determine if non-CAD limited support reasons exist: %w", err)
	}
	if lsExists {
		output := InvestigateInstancesOutput {
			ClusterState: "unrelated limited support reasons present on cluster",
			ClusterNotEvaluated: true,
		}
		return output, nil
	}

	// Verify cluster has expected number of nodes running
	runningNodesCount, err := c.GetRunningNodesCount(infraID)
	if err != nil {
        return InvestigateInstancesOutput{}, fmt.Errorf("could not retrieve running cluster nodes count while investigating started instances for %s: %w", infraID, err)
	}

	expectedNodesCount, err := c.GetExpectedNodesCount()
	if err != nil {
        return InvestigateInstancesOutput{}, fmt.Errorf("could not retrieve expected cluster nodes count while investigating started instances for %s: %w", infraID, err)
	}

        // Check for mistmach in running nodes and expected nodes
	if runningNodesCount.Master != expectedNodesCount.Master {
		return InvestigateInstancesOutput{UserAuthorized: true, Error: "number of running master node instances does not match the expected master node count: quota may be insufficient or irreplaceable machines have been terminated"}, nil
	}
	if runningNodesCount.Infra != expectedNodesCount.Infra {
		return InvestigateInstancesOutput{UserAuthorized: true, Error: "number of running infra node instances does not match the expected infra node count: quota may be insufficient or irreplaceable machines have been terminated"}, nil
	}

	output := InvestigateInstancesOutput{
		UserAuthorized:      true,
        ExpectedInstances:   *expectedNodesCount,
        RunningInstances:    *runningNodesCount,
	}
	return output, nil
}

// PostCHGMLimitedSupport adds a CHGM limited support reason to the corresponding cluster
func (c Client) PostCHGMLimitedSupport(externalID string) (*v1.LimitedSupportReason, error) {
	err := c.populateStructWith(externalID)
	if err != nil {
		return &v1.LimitedSupportReason{}, fmt.Errorf("could not populate the struct when posting CHGM Limited Support reason: %w", err)
	}
	return c.PostCHGMLimitedSupportReason(c.cluster.ID())
}

// RemoveCHGMLimitedSupport removes chgm-related limited support reasons added to the cluster by CAD, returning
// true if any reasons were removed
func (c Client) RemoveCHGMLimitedSupport(externalID string) (bool, error) {
	err := c.populateStructWith(externalID)
	if err != nil {
		return false, fmt.Errorf("could not populate the struct when removing CHGM Limited Support reason: %w", err)
	}
	return c.DeleteCHGMLimitedSupportReason(c.cluster.ID())
}

// RemoveCCAMLimitedSupport removes ccam-related limited support reasons added to the cluster by CAD, returning
// true if any reasons were removed
func (c Client) RemoveCCAMLimitedSupport(externalID string) (bool, error) {
	err := c.populateStructWith(externalID)
	if err != nil {
		return false, fmt.Errorf("could not populate the struct when removing CCAM Limited Support reason: %w", err)
	}
	return c.DeleteCCAMLimitedSupportReason(c.cluster.ID())
}

// GetRunningNodesCount return the number of running nodes that are currently running in the cluster
func (c Client) GetRunningNodesCount(infraID string) (*RunningNodesCount, error) {
    instances, err := c.ListRunningInstances(infraID) 
	if err != nil {
		return nil, err
	}

    runningNodesCount := &RunningNodesCount{
        Master: 0,
        Infra: 0,
        Worker: 0,
    }

    for _, instance := range instances {
        for _, t := range instance.Tags {
            if *t.Key == "Name" {
                switch {
                case strings.Contains(*t.Value, "master"):
                    runningNodesCount.Master++
                case strings.Contains(*t.Value, "infra"):
                    runningNodesCount.Infra++
                case strings.Contains(*t.Value, "worker"):
                    runningNodesCount.Worker++
                default:
                    continue
                }
            }
        }

    }

    return runningNodesCount, nil
}

// GetExpectedNodesCount returns the mininum number of nodes that are supposed to be in the cluster
// We do not use nodes.GetTotal() here, because total seems to be always 0.
func (c Client) GetExpectedNodesCount() (*ExpectedNodesCount, error) {
	nodes, ok := c.cluster.GetNodes()
	if !ok {
		// We do not error out here, because we do not want to fail the whole run, because of one missing metric
		fmt.Printf("node data is missing, dumping cluster object: %#v", c.cluster)
		return nil, fmt.Errorf("Failed to retrieve cluster node data")
	}
	masterCount, ok := nodes.GetMaster()
	if !ok {
		fmt.Printf("master node data is missing, dumping cluster object: %#v", c.cluster)
		return nil, fmt.Errorf("Failed to retrieve master node data")
	}
	infraCount, ok := nodes.GetInfra()
	if !ok {
		fmt.Printf("infra node data is missing, dumping cluster object: %#v", c.cluster)
		return nil, fmt.Errorf("Failed to retrieve infra node data")
	}

    minWorkerCount, maxWorkerCount := 0, 0
	computeCount, computeCountOk := nodes.GetCompute()
	if computeCountOk {
	    minWorkerCount += computeCount
	    maxWorkerCount += computeCount
    }
    autoscaleCompute, autoscaleComputeOk := nodes.GetAutoscaleCompute()
    if autoscaleComputeOk {
        minReplicasCount, ok := autoscaleCompute.GetMinReplicas()
        if !ok {
            fmt.Printf("autoscale min replicas data is missing, dumping cluster object: %v#", c.cluster)
            return nil, fmt.Errorf("Failed to retrieve min replicas from autoscale compute data")
        }

        maxReplicasCount, ok := autoscaleCompute.GetMaxReplicas()
        if !ok {
            fmt.Printf("autoscale max replicas data is missing, dumping cluster object: %v#", c.cluster)
            return nil, fmt.Errorf("Failed to retrieve max replicas from autoscale compute data")
        }

        minWorkerCount += minReplicasCount
        maxWorkerCount += maxReplicasCount
    }
    if !computeCountOk && !autoscaleComputeOk {
        fmt.Printf("compute and autoscale compute data are missing, dumping cluster object: %v#", c.cluster)
        return nil, fmt.Errorf("Failed to retrieve cluster compute and autoscale compute data")
    }

    poolMinWorkersCount, poolMaxWorkersCount := 0, 0
    machinePools, err := c.GetClusterMachinePools(c.cluster.ID())
    if err != nil {
		fmt.Printf("machine pools data is missing, dumping cluster object: %#v", c.cluster)
		return nil, fmt.Errorf("Failed to retrieve machine pools data")
    }
    for _, pool := range machinePools {
        replicasCount, replicasCountOk := pool.GetReplicas()
        if replicasCountOk {
            poolMinWorkersCount += replicasCount
            poolMaxWorkersCount += replicasCount
        }

        autoscaling, autoscalingOk := pool.GetAutoscaling()
        if autoscalingOk {
            minReplicasCount, ok := autoscaling.GetMinReplicas()
            if !ok {
                fmt.Printf("min replicas data is missing from autoscaling pool, dumping pool object: %v#", pool)
                return nil, fmt.Errorf("Failed to retrieve min replicas data from autoscaling pool")
            }

            maxReplicasCount, ok := autoscaling.GetMaxReplicas()
            if !ok {
                fmt.Printf("min replicas data is missing from autoscaling pool, dumping pool object: %v#", pool)
                return nil, fmt.Errorf("Failed to retrieve max replicas data from autoscaling pool")
            }

            poolMinWorkersCount += minReplicasCount
            poolMaxWorkersCount += maxReplicasCount
        }

        if !replicasCountOk && !autoscalingOk {
            fmt.Printf("pool replicas and autoscaling data are missing from autoscaling pool, dumping pool object: %v#", pool)
            return nil, fmt.Errorf("Failed to retrieve replicas and autoscaling data from autoscaling pool")
        }
    }

    nodeCount := &ExpectedNodesCount {
        Master: masterCount,
        Infra: infraCount,
        MinWorker: minWorkerCount + poolMinWorkersCount,
        MaxWorker: maxWorkerCount + poolMaxWorkersCount,
    }
	return nodeCount, nil
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
			return fmt.Errorf("failed to attach notes to CHGM incident: %w", err)
		}
	}
	fmt.Printf("Moving Alert to Escalation Policy %s\n", escalationPolicy)
	err := c.MoveToEscalationPolicy(incidentID, escalationPolicy)
	if err != nil {
		return fmt.Errorf("failed to change incident escalation policy: %w", err)
	}
	return nil
}

// CreateIncidentForRestoredCluster creates an alert for a cluster that no longer has a CHGM alert firing, but is
// still somehow failing investigation
func (c *Client) CreateIncidentForRestoredCluster(resultErr, externalID, serviceID string) error {
	// Ensure the client is properly populated w/ the cluster object prior to creating the alert
	err := c.populateStructWith(externalID)
	if err != nil {
		return fmt.Errorf("could not populate the struct when creating an incident for restored cluster: %w", err)
	}

	// The alert description acts as a title for the resulting incident
	description := fmt.Sprintf("cluster %s has failed CAD's CHGM resolution investigation", c.cluster.ID())

	// Defining the alert's details as a struct creates a table of entries that is easily parsed
	details := struct {
		ClusterID  string `json:"Cluster ID"`
		Reason     string `json:"Reason"`
		Resolution string `json:"Resolution"`
		SOP        string `json:"SOP"`
	}{
		ClusterID:  c.cluster.ID(),
		Reason:     resultErr,
		Resolution: "Review the investigation reason and take action as appropriate. Once the cluster has been reviewed, this alert needs to be manually resolved.",
		SOP:        "https://github.com/openshift/ops-sop/blob/master/v4/alerts/CAD_ClusterFailedPostCHGMInvestigation.md",
	}

	err = c.CreateNewAlert(description, details, serviceID)
	if err != nil {
		return fmt.Errorf("failed to create incident for restored cluster '%s': %w", c.cluster.ID(), err)
	}
	return nil
}

// CreateIncidentForInvestigationFailure creates an alert for a cluster that could not be properly investigated
func (c *Client) CreateIncidentForInvestigationFailure(investigationErr error, externalID, serviceID string) error {
	// Ensure the client is properly populated w/ the cluster object prior to creating the alert
	err := c.populateStructWith(externalID)
	if err != nil {
		return fmt.Errorf("could not populate the struct when creating an incident for failed investigation: %w", err)
	}

	// The alert description acts as a title for the resulting incident
	description := fmt.Sprintf("CAD's CHGM resolution investigation for cluster %s has encountered an error", c.cluster.ID())

	// Defining the alert's details as a struct creates a table of entries that is easily parsed
	details := struct {
		ClusterID  string `json:"Cluster ID"`
		Error      string `json:"Error"`
		Resolution string `json:"Resolution"`
		SOP        string `json:"SOP"`
	}{
		ClusterID:  c.cluster.ID(),
		Error:      investigationErr.Error(),
		Resolution: "Manually review the cluster to determine if it should have it's 'Cluster Has Gone Missing' and/or 'Cloud Credentials Are Missing' Limited Support reasons removed. Once the cluster has been reviewed and appropriate actions have been taken, manually resolve this alert.",
		SOP:        "https://github.com/openshift/ops-sop/blob/master/v4/alerts/CAD_ErrorInPostCHGMInvestigation.md",
	}

	err = c.CreateNewAlert(description, details, serviceID)
	if err != nil {
		return fmt.Errorf("failed to create incident for failed investigation on cluster '%s': %w", c.cluster.ID(), err)
	}
	return nil
}

// CreateIncidentForLimitedSupportRemovalFailure creates an alert for a cluster who's Limited Support reasons could not
// be removed by CAD
func (c Client) CreateIncidentForLimitedSupportRemovalFailure(lsErr error, externalID, serviceID string) error {
	err := c.populateStructWith(externalID)
	if err != nil {
		return fmt.Errorf("could not populate the struct when creating an incident for failing to add a Limited Support reason: %w", err)
	}

	// The alert description acts as a title for the resulting incident
	description := fmt.Sprintf("CAD is unable to remove a Limited Support reason from cluster %s", c.cluster.ID())

	// Defining the alert's details as a struct creates a table of entries that is easily parsed
	details := struct {
		ClusterID  string `json:"Cluster ID"`
		Error      string `json:"Error"`
		Resolution string `json:"Resolution"`
		SOP        string `json:"SOP"`
	}{
		ClusterID:  c.cluster.ID(),
		Error:      lsErr.Error(),
		Resolution: "CAD has been unable to remove a Limited Support reason from this cluster. The cluster needs to be manually reviewed and have any appropriate Limited Support reasons removed. After corrective actions have been taken, this alert must be manually resolved.",
		SOP:        "https://github.com/openshift/ops-sop/blob/master/v4/alerts/CAD_ErrorRemovingLSReason.md",
	}

	err = c.CreateNewAlert(description, details, serviceID)
	if err != nil {
		return fmt.Errorf("failed to create incident for failed Limited Support post to cluster '%s': %w", c.cluster.ID(), err)
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

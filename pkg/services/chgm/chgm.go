package chgm

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/openshift/configuration-anomaly-detection/pkg/aws"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigation"
	"github.com/openshift/configuration-anomaly-detection/pkg/ocm"
	"github.com/openshift/configuration-anomaly-detection/pkg/pagerduty"
	"github.com/openshift/configuration-anomaly-detection/pkg/utils"

	"github.com/aws/aws-sdk-go/service/cloudtrail"
	"github.com/aws/aws-sdk-go/service/ec2"

	v1 "github.com/openshift-online/ocm-sdk-go/clustersmgmt/v1"
	hivev1 "github.com/openshift/hive/apis/hive/v1"
)

const restoredClusterRetryDelaySeconds = 1200

// NOTE: USE CAUTION WHEN CHANGING THESE TEMPLATES!!
// Changing the templates' summaries will likely prevent CAD from removing clusters with these Limited Support reasons in the future, since it identifies which reasons to delete via their summaries.
// If the summaries *must* be modified, it's imperative that existing clusters w/ these LS reasons have the new summary applied to them (currently, the only way to do this is to delete the current
// reason & apply the new one). Failure to do so will result in orphan clusters that are not managed by CAD.
var chgmLimitedSupport = ocm.LimitedSupportReason{
	Summary: "Cluster not checking in",
	Details: "Your cluster is no longer checking in with Red Hat OpenShift Cluster Manager. Possible causes include stopped instances or a networking misconfiguration. If you have stopped the cluster instances, please start them again - stopping instances is not supported. If you intended to terminate this cluster then please delete the cluster in the Red Hat console",
}

// CAUTION!!

// these type aliases are here to make the types unique and unambiguous when used inside the struct

// AwsClient is a wrapper around the aws client, and is used to import the received functions into the Provider
type AwsClient = aws.Client

// OcmClient is a wrapper around the ocm client, and is used to import the received functions into the Provider
type OcmClient = ocm.Client

// PdClient is a wrapper around the pagerduty client, and is used to import the received functions into the Provider
type PdClient = pagerduty.Client

// Provider should have all the functions that ChgmService is implementing
type Provider struct {
	*AwsClient
	*OcmClient
	*PdClient
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
	GetClusterMachinePools(clusterID string) ([]*v1.MachinePool, error)
	PostLimitedSupportReason(limitedSupportReason ocm.LimitedSupportReason, clusterID string) error
	LimitedSupportReasonsExist(clusterID string) (bool, error)
	UnrelatedLimitedSupportExists(ls ocm.LimitedSupportReason, clusterID string) (bool, error)
	DeleteLimitedSupportReasons(ls ocm.LimitedSupportReason, clusterID string) error
	// PD
	SilenceAlert(notes string) error
	AddNote(notes string) error
	CreateNewAlert(newAlert pagerduty.NewAlert, serviceID string) error
	GetServiceID() string
	UpdateAndEscalateAlert(notes string) error
}

// Client for the chgm investigation
type Client struct {
	Service
	Cluster           *v1.Cluster
	ClusterDeployment *hivev1.ClusterDeployment
	*investigation.Client
}

// Triggered will analyse chgm incidents that are newly created
func (c *Client) Triggered() error {
	res, err := c.investigateStoppedInstances()
	if err != nil {
		return c.UpdateAndEscalateAlert(fmt.Sprintf("InvestigateInstances failed: %s\n", err.Error()))
	}

	fmt.Printf("the investigation returned %#v\n", res)

	lsExists, err := c.LimitedSupportReasonsExist(c.Cluster.ID())
	if err != nil {
		return c.UpdateAndEscalateAlert(fmt.Errorf("failed to determine if limited support reason already exists: %w", err).Error())
	}

	// if lsExists, silence alert and add investigation to notes
	if lsExists {
		fmt.Println("Unrelated limited support reason present on cluster, silencing")
		return c.SilenceAlert(res.String() + "Unrelated limited support reason present on cluster, silenced.")
	}

	if res.UserAuthorized {
		fmt.Println("The node shutdown was not the customer. Should alert SRE")
		return c.UpdateAndEscalateAlert(res.String())
	}
	res.LimitedSupportReason = chgmLimitedSupport
	// The node shutdown was the customer
	// Put into limited support, silence and update incident notes
	fmt.Printf("Sending limited support reason: %s\n", chgmLimitedSupport.Summary)
	return utils.Retry(utils.DefaultRetries, time.Second*2, func() error {
		return c.PostLimitedSupport(res.String())
	})
}

// Resolved will take appropriate action against a cluster whose CHGM incident has resolved.
func (c *Client) Resolved() error {
	res, err := c.investigateRestoredCluster()

	// The investigation encountered an error & never completed - alert Primary and report the error
	if err != nil {
		return err
	}

	// Investigation completed, but the state in OCM indicated the cluster didn't need investigation
	if res.ClusterNotEvaluated {
		fmt.Printf("Cluster has state '%s' in OCM, and so investigation is not need\n", res.ClusterState)
		err = utils.Retry(utils.DefaultRetries, time.Second*2, func() error {
			return c.AddNote(res.String())
		})
		if err != nil {
			fmt.Printf("Failed to add notes to incident: %s\n", res.String())
			return nil
		}
	}

	// Investigation completed, but an error was encountered.
	// Retry the investigation, escalating to Primary if the cluster still isn't healthy on recheck
	if res.Error != "" {
		fmt.Printf("Cluster failed alert resolution check. Result: %#v\n", res)
		fmt.Printf("Waiting %d seconds before rechecking cluster\n", restoredClusterRetryDelaySeconds)

		time.Sleep(time.Duration(restoredClusterRetryDelaySeconds) * time.Second)

		res, err = c.investigateRestoredCluster()
		if err != nil {
			return fmt.Errorf("failure while re-investigating cluster: %w", err)
		}
		if res.ClusterNotEvaluated {
			fmt.Printf("Investigation not required, cluster has the following condition: %s", res.ClusterState)
			return nil
		}
		if res.Error != "" {
			fmt.Printf("investigation completed, but cluster has not been restored properly\n")
			err = utils.Retry(utils.DefaultRetries, time.Second*2, func() error {
				return c.AddNote(res.String())
			})
			if err != nil {
				fmt.Printf("failed to add notes to incident: %s\n", res.String())
			}

			return utils.Retry(utils.DefaultRetries, time.Second*2, func() error {
				return c.CreateNewAlert(c.buildAlertForFailedPostCHGM(res.Error), c.GetServiceID())
			})
		}
	}
	fmt.Println("Investigation complete, remove 'Cluster has gone missing' limited support reason if any...")
	err = utils.Retry(utils.DefaultRetries, time.Second*2, func() error {
		return c.DeleteLimitedSupportReasons(chgmLimitedSupport, c.Cluster.ID())
	})
	if err != nil {
		fmt.Println("failed to remove limited support")
		err = utils.Retry(utils.DefaultRetries, time.Second*2, func() error {
			return c.CreateNewAlert(investigation.BuildAlertForLimitedSupportRemovalFailure(err, c.Cluster.ID()), c.GetServiceID())
		})
		if err != nil {
			return fmt.Errorf("failed to create alert: %w", err)
		}
		fmt.Println("Alert has been sent")
		return nil
	}
	return nil
}

// investigateRestoredCluster investigates the status of all instances belonging to the cluster. If the investigation encounters an error,
// Primary is notified via PagerDuty incident
func (c *Client) investigateRestoredCluster() (res InvestigateInstancesOutput, err error) {
	res, err = c.investigateStartedInstances()
	// The investigation encountered an error & never completed - alert Primary and report the error, retrying as many times as necessary to escalate the issue
	if err != nil {
		fmt.Printf("Failure detected while investigating cluster '%s', attempting to notify Primary. Error: %v\n", c.Cluster.ExternalID(), err)
		originalErr := err
		err = c.AddNote(fmt.Sprintf("Resolved investigation did not complete: %v\n", err.Error()))
		if err != nil {
			fmt.Println("could not update incident notes")
		}
		return InvestigateInstancesOutput{}, utils.Retry(utils.DefaultRetries, time.Second*2, func() error {
			return c.CreateNewAlert(c.buildAlertForInvestigationFailure(originalErr), c.GetServiceID())
		})
	}

	return res, nil
}

// isUserAllowedToStop verifies if a user is allowed to stop/terminate instances

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
	LimitedSupportReason ocm.LimitedSupportReason
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

	if i.LimitedSupportReason != (ocm.LimitedSupportReason{}) {
		msg += fmt.Sprintln("\nLimited Support reason sent:")
		msg += fmt.Sprintf("- Summary: '%s'\n", i.LimitedSupportReason.Summary)
		msg += fmt.Sprintf("- Details: '%s'\n", i.LimitedSupportReason.Details)
	}

	if i.Error != "" {
		msg += fmt.Sprintf("\nErrors: '%v' \n", i.Error)
	}
	return msg
}

func (c *Client) investigateStoppedInstances() (InvestigateInstancesOutput, error) {
	if c.ClusterDeployment == nil {
		return InvestigateInstancesOutput{}, fmt.Errorf("clusterdeployment is empty when investigating stopped instances, did not populate the instance before")
	}

	infraID := c.ClusterDeployment.Spec.ClusterMetadata.InfraID

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
		return InvestigateInstancesOutput{UserAuthorized: true, RunningInstances: *runningNodesCount,
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
		RunningInstances:    *runningNodesCount,
		ExpectedInstances:   *expectedNodesCount,
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

			// Return early with `output` containing the first unauthorized user.
			// This prevents overwriting the `Output.User` fields in the next loop.
			return output, nil
		}
	}

	// Return the last `stoppedInstanceEvent` `UserInfo`, ideally we would want to return
	// all users that stopped events, not just the last one. But in the case it's authorized,
	// it's not too much of an issue to just keep one of the authorized users.
	return output, nil
}

// investigateStartedInstances is the internal version of InvestigateStartedInstances operating on the read-only
// version of Client.
func (c *Client) investigateStartedInstances() (InvestigateInstancesOutput, error) {
	if c.ClusterDeployment == nil {
		return InvestigateInstancesOutput{}, fmt.Errorf("clusterdeployment is empty when investigating started instances, did not populate the instance before")
	}

	infraID := c.ClusterDeployment.Spec.ClusterMetadata.InfraID

	// Verify cluster is in a valid state to be investigated (ie - not hibernating, powering down, or being deleted)
	state, ok := c.Cluster.GetState()
	if !ok {
		return InvestigateInstancesOutput{}, fmt.Errorf("failed to determine if investigation required: cluster '%s' has no state associated with it", c.Cluster.ID())
	}
	if state == v1.ClusterStateUninstalling || state == v1.ClusterStatePoweringDown || state == v1.ClusterStateHibernating {
		output := InvestigateInstancesOutput{
			ClusterState:        string(state),
			ClusterNotEvaluated: true,
		}
		return output, nil
	}

	lsExists, err := c.UnrelatedLimitedSupportExists(chgmLimitedSupport, c.Cluster.ID())
	if err != nil {
		return InvestigateInstancesOutput{}, fmt.Errorf("failed to determine if investigation required: could not determine if non-CAD limited support reasons exist: %w", err)
	}
	if lsExists {
		output := InvestigateInstancesOutput{
			ClusterState:        "unrelated limited support reasons present on cluster",
			ClusterNotEvaluated: true,
		}
		return output, nil
	}

	// Verify cluster has expected number of nodes running
	runningNodesCount, err := c.GetRunningNodesCount(infraID)
	if err != nil {
		return InvestigateInstancesOutput{}, fmt.Errorf("could not retrieve non running instances while investigating started instances for %s: %w", infraID, err)
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
		UserAuthorized:    true,
		ExpectedInstances: *expectedNodesCount,
		RunningInstances:  *runningNodesCount,
	}
	return output, nil
}

// GetRunningNodesCount return the number of running nodes that are currently running in the cluster
func (c Client) GetRunningNodesCount(infraID string) (*RunningNodesCount, error) {
	instances, err := c.ListRunningInstances(infraID)
	if err != nil {
		return nil, err
	}

	runningNodesCount := &RunningNodesCount{
		Master: 0,
		Infra:  0,
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
	nodes, ok := c.Cluster.GetNodes()
	if !ok {
		// We do not error out here, because we do not want to fail the whole run, because of one missing metric
		fmt.Printf("node data is missing, dumping cluster object: %#v", c.Cluster)
		return nil, fmt.Errorf("failed to retrieve cluster node data")
	}
	masterCount, ok := nodes.GetMaster()
	if !ok {
		fmt.Printf("master node data is missing, dumping cluster object: %#v", c.Cluster)
		return nil, fmt.Errorf("failed to retrieve master node data")
	}
	infraCount, ok := nodes.GetInfra()
	if !ok {
		fmt.Printf("infra node data is missing, dumping cluster object: %#v", c.Cluster)
		return nil, fmt.Errorf("failed to retrieve infra node data")
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
			fmt.Printf("autoscale min replicas data is missing, dumping cluster object: %v#", c.Cluster)
			return nil, fmt.Errorf("failed to retrieve min replicas from autoscale compute data")
		}

		maxReplicasCount, ok := autoscaleCompute.GetMaxReplicas()
		if !ok {
			fmt.Printf("autoscale max replicas data is missing, dumping cluster object: %v#", c.Cluster)
			return nil, fmt.Errorf("failed to retrieve max replicas from autoscale compute data")
		}

		minWorkerCount += minReplicasCount
		maxWorkerCount += maxReplicasCount
	}
	if !computeCountOk && !autoscaleComputeOk {
		fmt.Printf("compute and autoscale compute data are missing, dumping cluster object: %v#", c.Cluster)
		return nil, fmt.Errorf("failed to retrieve cluster compute and autoscale compute data")
	}

	poolMinWorkersCount, poolMaxWorkersCount := 0, 0
	machinePools, err := c.GetClusterMachinePools(c.Cluster.ID())
	if err != nil {
		fmt.Printf("machine pools data is missing, dumping cluster object: %#v", c.Cluster)
		return nil, fmt.Errorf("failed to retrieve machine pools data")
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
				return nil, fmt.Errorf("failed to retrieve min replicas data from autoscaling pool")
			}

			maxReplicasCount, ok := autoscaling.GetMaxReplicas()
			if !ok {
				fmt.Printf("min replicas data is missing from autoscaling pool, dumping pool object: %v#", pool)
				return nil, fmt.Errorf("failed to retrieve max replicas data from autoscaling pool")
			}

			poolMinWorkersCount += minReplicasCount
			poolMaxWorkersCount += maxReplicasCount
		}

		if !replicasCountOk && !autoscalingOk {
			fmt.Printf("pool replicas and autoscaling data are missing from autoscaling pool, dumping pool object: %v#", pool)
			return nil, fmt.Errorf("failed to retrieve replicas and autoscaling data from autoscaling pool")
		}
	}

	nodeCount := &ExpectedNodesCount{
		Master:    masterCount,
		Infra:     infraCount,
		MinWorker: minWorkerCount + poolMinWorkersCount,
		MaxWorker: maxWorkerCount + poolMaxWorkersCount,
	}
	return nodeCount, nil
}

// buildAlertForFailedPostCHGM returns an alert for a cluster that resolved its chgm alert but somehow is still failing CAD checks
// This is potentially very noisy and led to some confusion for primary already
func (c *Client) buildAlertForFailedPostCHGM(investigationErr string) pagerduty.NewAlert {
	return pagerduty.NewAlert{
		Description: fmt.Sprintf("cluster %s has failed CAD's post-CHGM investigation", c.Cluster.ID()),
		Details: pagerduty.NewAlertDetails{
			ClusterID:  c.Cluster.ID(),
			Error:      investigationErr,
			Resolution: "Review the investigation reason and take action as appropriate. Once the cluster has been reviewed, this alert needs to be manually resolved.",
			SOP:        "https://github.com/openshift/ops-sop/blob/master/v4/alerts/CAD_ClusterFailedPostCHGMInvestigation.md",
		}}
}

// buildAlertForInvestigationFailure returns an alert for a cluster that could not be properly investigated
func (c *Client) buildAlertForInvestigationFailure(investigationErr error) pagerduty.NewAlert {
	return pagerduty.NewAlert{
		Description: fmt.Sprintf("CAD's post-CHGM investigation for cluster %s has encountered an error", c.Cluster.ID()),
		Details: pagerduty.NewAlertDetails{
			ClusterID:  c.Cluster.ID(),
			Error:      investigationErr.Error(),
			Resolution: "Manually review the cluster to determine if it should have it's 'Cluster Has Gone Missing' and/or 'Cloud Credentials Are Missing' Limited Support reasons removed. Once the cluster has been reviewed and appropriate actions have been taken, manually resolve this alert.",
			SOP:        "https://github.com/openshift/ops-sop/blob/master/v4/alerts/CAD_ErrorInPostCHGMInvestigation.md",
		}}
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

// PostLimitedSupport will put the cluster into limited support
// As the deadmanssnitch operator is not silenced on limited support
// the alert is updated with notes and silenced
func (c *Client) PostLimitedSupport(notes string) error {
	err := c.PostLimitedSupportReason(chgmLimitedSupport, c.Cluster.ID())
	if err != nil {
		return fmt.Errorf("failed posting limited support reason: %w", err)
	}
	// we need to aditionally silence here, as dms service keeps firing
	// even when we put in limited support
	return c.SilenceAlert(string(notes))
}

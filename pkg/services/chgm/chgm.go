// Package chgm contains functionality for the chgm investigation
package chgm

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/openshift/configuration-anomaly-detection/pkg/aws"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigation"
	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
	"github.com/openshift/configuration-anomaly-detection/pkg/ocm"
	"github.com/openshift/configuration-anomaly-detection/pkg/pagerduty"
	"github.com/openshift/configuration-anomaly-detection/pkg/services/networkverifier"
	"github.com/openshift/configuration-anomaly-detection/pkg/utils"
	hivev1 "github.com/openshift/hive/apis/hive/v1"

	"github.com/aws/aws-sdk-go/service/ec2"

	v1 "github.com/openshift-online/ocm-sdk-go/clustersmgmt/v1"
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

// CAUTION

// InvestigateTriggered runs the investigation for a triggered chgm pagerduty event
func InvestigateTriggered(r *investigation.Resources) error {
	res, err := investigateStoppedInstances(r.Cluster, r.ClusterDeployment, r.AwsClient, r.OcmClient)
	if err != nil {
		return r.PdClient.EscalateAlertWithNote(fmt.Sprintf("InvestigateInstances failed: %s\n", err.Error()))
	}

	logging.Debugf("the investigation returned %#v", res.string())

	lsExists, err := r.OcmClient.IsInLimitedSupport(r.Cluster.ID())
	if err != nil {
		return r.PdClient.EscalateAlertWithNote(fmt.Errorf("failed to determine if limited support reason already exists: %w", err).Error())
	}

	// if lsExists, silence alert and add investigation to notes
	if lsExists {
		logging.Info("Unrelated limited support reason present on cluster, silencing")
		return r.PdClient.SilenceAlertWithNote(res.string() + "Unrelated limited support reason present on cluster, silenced.")
	}

	if res.UserAuthorized {
		logging.Info("The customer has not stopped/terminated any nodes.")
		// Run network verifier
		verifierResult, failureReason, err := networkverifier.Run(r.Cluster, r.ClusterDeployment, r.AwsClient)
		if err != nil {
			// Forward to on call, set err as note to pagerduty incident
			logging.Error("Error running network verifier, escalating to SRE.")
			err = r.PdClient.AddNote(fmt.Sprintf("NetworkVerifier failed to run:\n\t %s", err))
			if err != nil {
				logging.Error("could not add failure reason incident notes")
			}
			return r.PdClient.EscalateAlertWithNote(res.string())
		}

		if verifierResult == networkverifier.Failure {
			err = r.PdClient.AddNote(fmt.Sprintf("Network verifier found issues:\n %s \n\n Verify and send service log if necessary: \n osdctl servicelog post %s -t https://raw.githubusercontent.com/openshift/managed-notifications/master/osd/required_network_egresses_are_blocked.json -p URLS=%s", failureReason, r.Cluster.ID(), failureReason))
			if err != nil {
				logging.Error("could not add issues to incident notes")
			}
			// Change this to put the cluster into limited support after some time
			return r.PdClient.EscalateAlertWithNote(res.string())
		}

		logging.Info("Network verifier passed. Escalating to SRE")
		err = r.PdClient.AddNote(fmt.Sprintln("Network verifier passed."))
		if err != nil {
			logging.Error("could not add passed message to incident notes")
		}
		return r.PdClient.EscalateAlertWithNote(res.string())
	}
	res.LimitedSupportReason = chgmLimitedSupport

	// The node shutdown was the customer
	// Put into limited support, silence and update incident notes
	return utils.WithRetries(func() error {
		return postLimitedSupport(r.Cluster.ID(), res.string(), r.OcmClient, r.PdClient)
	})
}

// InvestigateResolved runs the investigation for a resolved chgm pagerduty event
func InvestigateResolved(r *investigation.Resources) error {

	// Check if CAD put the cluster in CHGM LS. If it didn't, we don't need a resolve investigation, as
	// either way it would be a NOOP for CAD (no LS to remove).
	// This is the case most of the time, so it saves us a lot of long pipeline runs.
	chgmLsExists, err := r.OcmClient.LimitedSupportReasonExists(chgmLimitedSupport, r.Cluster.ID())
	if err != nil {
		// The check is just to allow returning early, as we don't need an investigation if CAD didn't put the cluster in LS.
		// If this fails, it's not a big issue. We can skip the check and proceed with the resolve investigation.
		logging.Warn("Unable to determine whether or not the cluster was put in limited support by CAD. Proceeding with investigation anyway...")
	}
	if !chgmLsExists {
		logging.Info("Skipping resolve investigation, as no actions were taking on this cluster by CAD.")
		return nil
	}

	res, err := investigateRestoredCluster(r)

	// The investigation encountered an error & never completed - alert Primary and report the error
	if err != nil {
		return err
	}

	// Investigation completed, but the state in OCM indicated the cluster didn't need investigation
	if res.ClusterNotEvaluated {
		investigationNotNeededNote := fmt.Sprintf("Cluster has state '%s' in OCM, and so investigation is not needed:\n", res.ClusterState)
		logging.Infof("Adding note: %s", investigationNotNeededNote)

		err = utils.WithRetries(func() error {
			return r.PdClient.AddNote(investigationNotNeededNote)
		})
		if err != nil {
			logging.Errorf("Failed to add note '%s' to incident: %s", investigationNotNeededNote, err)
			return nil
		}
		return nil
	}

	// Investigation completed, but an error was encountered.
	// Retry the investigation, escalating to Primary if the cluster still isn't healthy on recheck
	if res.Error != "" {
		logging.Warnf("Cluster failed alert resolution check. Result: %#v", res)
		logging.Infof("Waiting %d seconds before rechecking cluster", restoredClusterRetryDelaySeconds)

		time.Sleep(time.Duration(restoredClusterRetryDelaySeconds) * time.Second)

		res, err = investigateRestoredCluster(r)
		if err != nil {
			return fmt.Errorf("failure while re-investigating cluster: %w", err)
		}
		if res.ClusterNotEvaluated {
			logging.Infof("Investigation not required, cluster has the following condition: %s", res.ClusterState)
			return nil
		}
		if res.Error != "" {
			logging.Warnf("investigation completed, but cluster has not been restored properly")
			err = utils.WithRetries(func() error {
				return r.PdClient.AddNote(res.string())
			})
			if err != nil {
				logging.Errorf("failed to add notes to incident: %s", res.string())
			}

			return utils.WithRetries(func() error {
				return r.PdClient.CreateNewAlert(buildAlertForFailedPostCHGM(r.Cluster.ID(), res.Error), r.PdClient.GetServiceID())
			})
		}
	}
	logging.Info("Investigation complete, remove 'Cluster has gone missing' limited support reason if any...")
	err = utils.WithRetries(func() error {
		return r.OcmClient.DeleteLimitedSupportReasons(chgmLimitedSupport, r.Cluster.ID())
	})
	if err != nil {
		logging.Error("failed to remove limited support")
		err = utils.WithRetries(func() error {
			return r.PdClient.CreateNewAlert(investigation.BuildAlertForLimitedSupportRemovalFailure(err, r.Cluster.ID()), r.PdClient.GetServiceID())
		})
		if err != nil {
			return fmt.Errorf("failed to create alert: %w", err)
		}
		logging.Info("Alert has been sent")
		return nil
	}
	return nil
}

// investigateRestoredCluster investigates the status of all instances belonging to the cluster. If the investigation encounters an error,
// Primary is notified via PagerDuty incident
func investigateRestoredCluster(r *investigation.Resources) (res investigateInstancesOutput, err error) {
	res, err = investigateStartedInstances(r)
	// The investigation encountered an error & never completed - alert Primary and report the error, retrying as many times as necessary to escalate the issue
	if err != nil {
		logging.Warnf("Failure detected while investigating cluster '%s', attempting to notify Primary. Error: %v", r.Cluster.ExternalID(), err)
		originalErr := err
		err = r.PdClient.AddNote(fmt.Sprintf("Resolved investigation did not complete: %v\n", err.Error()))
		if err != nil {
			logging.Error("could not update incident notes")
		}
		err = utils.WithRetries(func() error {
			return r.PdClient.CreateNewAlert(buildAlertForInvestigationFailure(r.Cluster.ID(), originalErr), r.PdClient.GetServiceID())
		})
		if err != nil {
			logging.Errorf("failed to alert primary: %w", err)
		}
		return investigateInstancesOutput{}, fmt.Errorf("InvestigateStartedInstances failed for %s: %w", r.Cluster.ExternalID(), originalErr)
	}

	return res, nil
}

// isUserAllowedToStop verifies if a user is allowed to stop/terminate instances
// For this, we use a whitelist of partial strings that can be SRE
// based on findings in https://issues.redhat.com/browse/OSD-16042
func isUserAllowedToStop(username, issuerUsername string, ccsEnabled bool) bool {

	// Users are represented by Username in cloudtrail events
	allowedUsersPartialStrings := []string{
		// 'openshift-machine-api-aws' is a role for STS, and a user for ROSA non-STS and non-CCS
		"openshift-machine-api-aws", // Infra nodes/Autoscaling

		"osdCcsAdmin",     // ROSA-STS - doesn't start/stop instances but is our user
		"osdManagedAdmin", // ROSA non-STS, OSD non-CCS - install/uninstall node run/terminate

		// Might not exist - better safe than sorry
		"RH-SRE-",
	}

	for _, partialUserString := range allowedUsersPartialStrings {
		if strings.Contains(username, partialUserString) {
			return true
		}
	}

	// Roles are represented by issuerUsername in cloudtrail events
	allowedRolesPartialStrings := []string{
		// 'openshift-machine-api-aws' is a role for STS, and a user for ROSA non-STS and non-CCS
		"openshift-machine-api-aws", // Infra nodes/Autoscaling

		"-Installer-Role",           // ROSA-STS - install/uninstall node run/terminate
		"-Support-Role",             // ROSA-STS - SRE work
		"ManagedOpenShift-Support-", // ROSA- non-STS - SRE work
	}

	// Check cluster flavor, as 'OrganizationAccountAccessRole' is SRE for non-CCS and the user for ROSA
	if !ccsEnabled {
		allowedRolesPartialStrings = append(allowedRolesPartialStrings, "OrganizationAccountAccessRole")
	}

	for _, partialRoleString := range allowedRolesPartialStrings {
		if strings.Contains(issuerUsername, partialRoleString) {
			return true
		}
	}

	return false
}

// userInfo will hold the extracted user details
type userInfo struct {
	UserName       string
	IssuerUserName string
}

// runningNodesCount holds the number of actual running nodes
type runningNodesCount struct {
	Master int
	Infra  int
	Worker int
}

// expectedNodesCount holds the number of expected running nodes
type expectedNodesCount struct {
	Master    int
	Infra     int
	MinWorker int
	MaxWorker int
}

// investigateInstancesOutput is the result of the InvestigateInstances command
type investigateInstancesOutput struct {
	NonRunningInstances  []*ec2.Instance
	RunningInstances     runningNodesCount
	ExpectedInstances    expectedNodesCount
	User                 userInfo
	UserAuthorized       bool
	ClusterState         string
	ClusterNotEvaluated  bool
	LimitedSupportReason ocm.LimitedSupportReason
	Error                string
}

// string implements the stringer interface for InvestigateInstancesOutput
func (i investigateInstancesOutput) string() string {
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

func investigateStoppedInstances(cluster *v1.Cluster, clusterDeployment *hivev1.ClusterDeployment, awsCli aws.Client, ocmCli ocm.Client) (investigateInstancesOutput, error) {
	if clusterDeployment == nil {
		return investigateInstancesOutput{}, fmt.Errorf("clusterdeployment is empty when investigating stopped instances, did not populate the instance before")
	}

	infraID := clusterDeployment.Spec.ClusterMetadata.InfraID

	stoppedInstances, err := awsCli.ListNonRunningInstances(infraID)
	if err != nil {
		return investigateInstancesOutput{}, fmt.Errorf("could not retrieve non running instances while investigating stopped instances for %s: %w", infraID, err)
	}

	runningNodesCount, err := getRunningNodesCount(infraID, awsCli)
	if err != nil {
		return investigateInstancesOutput{}, fmt.Errorf("could not retrieve running cluster nodes while investigating stopped instances for %s: %w", infraID, err)
	}

	// evaluate number of all supposed nodes
	expectedNodesCount, err := getExpectedNodesCount(cluster, ocmCli)
	if err != nil {
		return investigateInstancesOutput{}, fmt.Errorf("could not retrieve expected cluster nodes while investigating stopped instances for %s: %w", infraID, err)
	}

	if len(stoppedInstances) == 0 {
		// UserAuthorized: true so SRE will still be alerted for manual investigation
		return investigateInstancesOutput{UserAuthorized: true, RunningInstances: *runningNodesCount,
			ExpectedInstances: *expectedNodesCount, Error: "no non running instances found, terminated instances may have already expired"}, nil
	}

	stoppedInstancesEvents, err := awsCli.PollInstanceStopEventsFor(stoppedInstances, 15)
	if err != nil {
		return investigateInstancesOutput{}, fmt.Errorf("could not PollStopEventsFor stoppedInstances: %w", err)
	}

	if len(stoppedInstancesEvents) == 0 {
		return investigateInstancesOutput{}, fmt.Errorf("there are stopped instances but no stoppedInstancesEvents, this means the instances were stopped too long ago or CloudTrail is not up to date")
	}

	output := investigateInstancesOutput{
		NonRunningInstances: stoppedInstances,
		UserAuthorized:      true,
		RunningInstances:    *runningNodesCount,
		ExpectedInstances:   *expectedNodesCount,
	}
	for _, event := range stoppedInstancesEvents {
		userDetails, err := extractUserDetails(event.CloudTrailEvent)
		if err != nil {
			resourceData := "with no resources"
			if len(event.Resources) != 0 {
				resourceData = fmt.Sprintf("with resource %v", event.Resources[0].ResourceName)
			}

			return investigateInstancesOutput{}, fmt.Errorf("could not extractUserDetails for event %s: %w", resourceData, err)
		}

		output.User = userInfo{
			UserName:       *event.Username,
			IssuerUserName: userDetails.UserIdentity.SessionContext.SessionIssuer.UserName,
		}

		if !isUserAllowedToStop(*event.Username, output.User.IssuerUserName, cluster.CCS().Enabled()) {
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
func investigateStartedInstances(r *investigation.Resources) (investigateInstancesOutput, error) {
	if r.ClusterDeployment == nil {
		return investigateInstancesOutput{}, fmt.Errorf("clusterdeployment is empty when investigating started instances, did not populate the instance before")
	}

	infraID := r.ClusterDeployment.Spec.ClusterMetadata.InfraID

	// Verify cluster is in a valid state to be investigated (ie - not hibernating, powering down, or being deleted)
	state, ok := r.Cluster.GetState()
	if !ok {
		return investigateInstancesOutput{}, fmt.Errorf("failed to determine if investigation required: cluster '%s' has no state associated with it", r.Cluster.ID())
	}
	if state == v1.ClusterStateUninstalling || state == v1.ClusterStatePoweringDown || state == v1.ClusterStateHibernating {
		output := investigateInstancesOutput{
			ClusterState:        string(state),
			ClusterNotEvaluated: true,
		}
		return output, nil
	}

	lsExists, err := r.OcmClient.UnrelatedLimitedSupportExists(chgmLimitedSupport, r.Cluster.ID())
	if err != nil {
		return investigateInstancesOutput{}, fmt.Errorf("failed to determine if investigation required: could not determine if non-CAD limited support reasons exist: %w", err)
	}
	if lsExists {
		output := investigateInstancesOutput{
			ClusterState:        "unrelated limited support reasons present on cluster",
			ClusterNotEvaluated: true,
		}
		return output, nil
	}

	// Verify cluster has expected number of nodes running
	runningNodesCount, err := getRunningNodesCount(infraID, r.AwsClient)
	if err != nil {
		return investigateInstancesOutput{}, fmt.Errorf("could not retrieve non running instances while investigating started instances for %s: %w", infraID, err)
	}

	expectedNodesCount, err := getExpectedNodesCount(r.Cluster, r.OcmClient)
	if err != nil {
		return investigateInstancesOutput{}, fmt.Errorf("could not retrieve expected cluster nodes count while investigating started instances for %s: %w", infraID, err)
	}

	// Check for mistmach in running nodes and expected nodes
	if runningNodesCount.Master != expectedNodesCount.Master {
		return investigateInstancesOutput{UserAuthorized: true, Error: "number of running master node instances does not match the expected master node count: quota may be insufficient or irreplaceable machines have been terminated"}, nil
	}
	if runningNodesCount.Infra != expectedNodesCount.Infra {
		return investigateInstancesOutput{UserAuthorized: true, Error: "number of running infra node instances does not match the expected infra node count: quota may be insufficient or irreplaceable machines have been terminated"}, nil
	}

	output := investigateInstancesOutput{
		UserAuthorized:    true,
		ExpectedInstances: *expectedNodesCount,
		RunningInstances:  *runningNodesCount,
	}
	return output, nil
}

// GetRunningNodesCount return the number of running nodes that are currently running in the cluster
func getRunningNodesCount(infraID string, awsCli aws.Client) (*runningNodesCount, error) {
	instances, err := awsCli.ListRunningInstances(infraID)
	if err != nil {
		return nil, err
	}

	runningNodesCount := &runningNodesCount{
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
func getExpectedNodesCount(cluster *v1.Cluster, ocmCli ocm.Client) (*expectedNodesCount, error) {
	nodes, ok := cluster.GetNodes()
	if !ok {
		// We do not error out here, because we do not want to fail the whole run, because of one missing metric
		logging.Errorf("node data is missing, dumping cluster object: %#v", cluster)
		return nil, fmt.Errorf("failed to retrieve cluster node data")
	}
	masterCount, ok := nodes.GetMaster()
	if !ok {
		logging.Errorf("master node data is missing, dumping cluster object: %#v", cluster)
		return nil, fmt.Errorf("failed to retrieve master node data")
	}
	infraCount, ok := nodes.GetInfra()
	if !ok {
		logging.Errorf("infra node data is missing, dumping cluster object: %#v", cluster)
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
			logging.Errorf("autoscale min replicas data is missing, dumping cluster object: %v#", cluster)
			return nil, fmt.Errorf("failed to retrieve min replicas from autoscale compute data")
		}

		maxReplicasCount, ok := autoscaleCompute.GetMaxReplicas()
		if !ok {
			logging.Errorf("autoscale max replicas data is missing, dumping cluster object: %v#", cluster)
			return nil, fmt.Errorf("failed to retrieve max replicas from autoscale compute data")
		}

		minWorkerCount += minReplicasCount
		maxWorkerCount += maxReplicasCount
	}
	if !computeCountOk && !autoscaleComputeOk {
		logging.Errorf("compute and autoscale compute data are missing, dumping cluster object: %v#", cluster)
		return nil, fmt.Errorf("failed to retrieve cluster compute and autoscale compute data")
	}

	poolMinWorkersCount, poolMaxWorkersCount := 0, 0
	machinePools, err := ocmCli.GetClusterMachinePools(cluster.ID())
	if err != nil {
		logging.Errorf("machine pools data is missing, dumping cluster object: %#v", cluster)
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
				logging.Errorf("min replicas data is missing from autoscaling pool, dumping pool object: %v#", pool)
				return nil, fmt.Errorf("failed to retrieve min replicas data from autoscaling pool")
			}

			maxReplicasCount, ok := autoscaling.GetMaxReplicas()
			if !ok {
				logging.Errorf("min replicas data is missing from autoscaling pool, dumping pool object: %v#", pool)
				return nil, fmt.Errorf("failed to retrieve max replicas data from autoscaling pool")
			}

			poolMinWorkersCount += minReplicasCount
			poolMaxWorkersCount += maxReplicasCount
		}

		if !replicasCountOk && !autoscalingOk {
			logging.Errorf("pool replicas and autoscaling data are missing from autoscaling pool, dumping pool object: %v#", pool)
			return nil, fmt.Errorf("failed to retrieve replicas and autoscaling data from autoscaling pool")
		}
	}

	nodeCount := &expectedNodesCount{
		Master:    masterCount,
		Infra:     infraCount,
		MinWorker: minWorkerCount + poolMinWorkersCount,
		MaxWorker: maxWorkerCount + poolMaxWorkersCount,
	}
	return nodeCount, nil
}

// buildAlertForFailedPostCHGM returns an alert for a cluster that resolved its chgm alert but somehow is still failing CAD checks
// This is potentially very noisy and led to some confusion for primary already
func buildAlertForFailedPostCHGM(clusterID string, investigationErr string) pagerduty.NewAlert {
	return pagerduty.NewAlert{
		Description: fmt.Sprintf("cluster %s has failed CAD's post-CHGM investigation", clusterID),
		Details: pagerduty.NewAlertDetails{
			ClusterID:  clusterID,
			Error:      investigationErr,
			Resolution: "Review the investigation reason and take action as appropriate. Once the cluster has been reviewed, this alert needs to be manually resolved.",
			SOP:        "https://github.com/openshift/ops-sop/blob/master/v4/alerts/CAD_ClusterFailedPostCHGMInvestigation.md",
		}}
}

// buildAlertForInvestigationFailure returns an alert for a cluster that could not be properly investigated
func buildAlertForInvestigationFailure(clusterID string, investigationErr error) pagerduty.NewAlert {
	return pagerduty.NewAlert{
		Description: fmt.Sprintf("CAD's post-CHGM investigation for cluster %s has encountered an error", clusterID),
		Details: pagerduty.NewAlertDetails{
			ClusterID:  clusterID,
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

// PostLimitedSupport will put the cluster into limited support
// As the deadmanssnitch operator is not silenced on limited support
// the alert is updated with notes and silenced
func postLimitedSupport(clusterID string, notes string, ocmCli ocm.Client, pdCli pagerduty.Client) error {
	err := ocmCli.PostLimitedSupportReason(chgmLimitedSupport, clusterID)
	if err != nil {
		return fmt.Errorf("failed posting limited support reason: %w", err)
	}
	// we need to aditionally silence here, as dms service keeps firing
	// even when we put in limited support
	return pdCli.SilenceAlertWithNote(string(notes))
}

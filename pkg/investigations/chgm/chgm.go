// Package chgm contains functionality for the chgm investigation
package chgm

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/openshift/configuration-anomaly-detection/pkg/aws"
	investigation "github.com/openshift/configuration-anomaly-detection/pkg/investigations"
	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
	"github.com/openshift/configuration-anomaly-detection/pkg/metrics"
	"github.com/openshift/configuration-anomaly-detection/pkg/networkverifier"
	"github.com/openshift/configuration-anomaly-detection/pkg/ocm"
	"github.com/openshift/configuration-anomaly-detection/pkg/pagerduty"
	"github.com/openshift/configuration-anomaly-detection/pkg/utils"
	hivev1 "github.com/openshift/hive/apis/hive/v1"

	"github.com/aws/aws-sdk-go/service/ec2"
	cmv1 "github.com/openshift-online/ocm-sdk-go/clustersmgmt/v1"
)

// NOTE: USE CAUTION WHEN CHANGING THESE TEMPLATES!!
// Changing the templates' summaries will likely prevent CAD from removing clusters with these Limited Support reasons in the future, since it identifies which reasons to delete via their summaries.
// If the summaries *must* be modified, it's imperative that existing clusters w/ these LS reasons have the new summary applied to them (currently, the only way to do this is to delete the current
// reason & apply the new one). Failure to do so will result in orphan clusters that are not managed by CAD.
var chgmLimitedSupport = ocm.LimitedSupportReason{
	Summary: "Cluster not checking in",
	Details: "Your cluster is no longer checking in with Red Hat OpenShift Cluster Manager. Possible causes include stopped instances or a networking misconfiguration. If you have stopped the cluster instances, please start them again - stopping instances is not supported. If you intended to terminate this cluster then please delete the cluster in the Red Hat console",
}

// ClusterDeploymentSupportExceptionLabel is the label indicating the cluster is under limited support
// and the PagerDuty service should be enabled even if the cluster is in limited support
// TODO:() Centrailize or Remove this varaiable once https://issues.redhat.com/browse/XCMSTRAT-427 is completed
var ClusterDeploymentSupportExceptionLabel = "ext-managed.openshift.io/support-exception"

// CAUTION

// InvestigateTriggered runs the investigation for a triggered chgm pagerduty event
func InvestigateTriggered(r *investigation.Resources) error {
	res, err := investigateStoppedInstances(r.Cluster, r.ClusterDeployment, r.AwsClient, r.OcmClient)
	if err != nil {
		return r.PdClient.EscalateAlertWithNote(fmt.Sprintf("InvestigateInstances failed: %s\n", err.Error()))
	}

	logging.Debugf("the investigation returned %#v", res.string())

	hasSupportException := false
	if supportExValue, err := strconv.ParseBool(r.ClusterDeployment.Labels[ClusterDeploymentSupportExceptionLabel]); err == nil {
		hasSupportException = supportExValue
	}

	lsExists, err := r.OcmClient.IsInLimitedSupport(r.Cluster.ID())
	if err != nil {
		return r.PdClient.EscalateAlertWithNote(fmt.Errorf("failed to determine if limited support reason already exists: %w", err).Error())
	}

	// if lsExists, silence alert and add investigation to notes and its not in support exceuption
	if lsExists && !hasSupportException {
		logging.Info("Unrelated limited support reason present on cluster, silencing")
		return r.PdClient.SilenceAlertWithNote(res.string() + "Unrelated limited support reason present on cluster, silenced.")
	}

	longHibernation, hibernationErr := investigateHibernation(r.Cluster, r.OcmClient)
	if hibernationErr != nil {
		logging.Warn(fmt.Errorf("Could not check hibernation status of cluster: %w", err))
	}
	if longHibernation {
		err = r.PdClient.AddNote(fmt.Sprintf("⚠️ Cluster was hibernated more than %.0f days - investigate CSRs and kubelet certificates: see https://github.com/openshift/ops-sop/blob/master/v4/alerts/cluster_has_gone_missing.md#24-hibernation", hibernationTooLong.Hours()/24))
		if err != nil {
			logging.Error("could not add hibernation comment to incident notes")
		}
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
			metrics.Inc(metrics.ServicelogPrepared, r.AlertType.String(), r.PdClient.GetEventType())
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
		metrics.Inc(metrics.LimitedSupportSet, r.AlertType.String(), r.PdClient.GetEventType(), chgmLimitedSupport.Summary)
		return postLimitedSupport(r.Cluster.ID(), res.string(), r.OcmClient, r.PdClient)
	})
}

// investigateHibernation checks if the cluster was recently woken up from
// hibernation. If clusters are hibernated for more than 30 days, the internal
// certificates of the kubelets can expire and CSRs need to be approved
// manually:
// - https://github.com/openshift/hive/blob/master/docs/hibernating-clusters.md
func investigateHibernation(cluster *cmv1.Cluster, client ocm.Client) (bool, error) {
	hibernations, err := getHibernationStatusForCluster(client, cluster)
	if err != nil {
		return false, err
	}
	if len(hibernations) == 0 {
		return false, nil
	}
	return hibernatedTooLong(hibernations, time.Now()), nil
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
	// var ids []string
	ids := make([]string, len(i.NonRunningInstances))
	for i, nonRunningInstance := range i.NonRunningInstances {
		// TODO: add also the StateTransitionReason to the output if needed
		ids[i] = *nonRunningInstance.InstanceId
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

func investigateStoppedInstances(cluster *cmv1.Cluster, clusterDeployment *hivev1.ClusterDeployment, awsCli aws.Client, ocmCli ocm.Client) (investigateInstancesOutput, error) {
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
		return investigateInstancesOutput{
			UserAuthorized: true, RunningInstances: *runningNodesCount,
			ExpectedInstances: *expectedNodesCount, Error: "no non running instances found, terminated instances may have already expired",
		}, nil
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
func getExpectedNodesCount(cluster *cmv1.Cluster, ocmCli ocm.Client) (*expectedNodesCount, error) {
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
		MinWorker: poolMinWorkersCount,
		MaxWorker: poolMaxWorkersCount,
	}
	return nodeCount, nil
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

	// To be sure that your applications can parse the event structure, we recommend that you perform an equal-to
	// comparison on the major version number. To be sure that fields that are expected by your application exist, we
	// also recommend performing a greater-than-or-equal-to comparison on the minor version.
	// https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html
	const supportedEventVersionMajor = 1
	const minSupportedEventVersionMinor = 8

	var responseMajor, responseMinor int
	if _, err := fmt.Sscanf(res.EventVersion, "%d.%d", &responseMajor, &responseMinor); err != nil {
		return CloudTrailEventRaw{}, fmt.Errorf("failed to parse CloudTrail event version: %w", err)
	}

	if responseMajor != supportedEventVersionMajor || responseMinor < minSupportedEventVersionMinor {
		return CloudTrailEventRaw{}, fmt.Errorf("unexpected event version (got %s, expected compatibility with %d.%d)", res.EventVersion, supportedEventVersionMajor, minSupportedEventVersionMinor)
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
	return pdCli.SilenceAlertWithNote(notes)
}

// HandleResolved removes limited support when a CHGM resolves
func HandleResolved(r *investigation.Resources) error {
	logging.Info("Remove 'Cluster has gone missing' limited support reason if any...")

	removedReasons := false
	err := utils.WithRetries(func() error {
		var err error
		removedReasons, err = r.OcmClient.DeleteLimitedSupportReasons(chgmLimitedSupport, r.Cluster.ID())
		return err
	})
	if err != nil {
		return fmt.Errorf("failed to remove limited support")
	}

	if removedReasons {
		metrics.Inc(metrics.LimitedSupportLifted, r.AlertType.String(), r.PdClient.GetEventType(), chgmLimitedSupport.Summary)
	}

	return nil
}

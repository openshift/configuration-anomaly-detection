// Package chgm contains functionality for the chgm investigation
package chgm

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	ec2v2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	cmv1 "github.com/openshift-online/ocm-sdk-go/clustersmgmt/v1"
	"github.com/openshift/configuration-anomaly-detection/pkg/aws"
	"github.com/openshift/configuration-anomaly-detection/pkg/executor"
	investigation "github.com/openshift/configuration-anomaly-detection/pkg/investigations/investigation"
	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
	"github.com/openshift/configuration-anomaly-detection/pkg/networkverifier"
	"github.com/openshift/configuration-anomaly-detection/pkg/notewriter"
	"github.com/openshift/configuration-anomaly-detection/pkg/ocm"
	"github.com/openshift/configuration-anomaly-detection/pkg/reports"
	"github.com/openshift/configuration-anomaly-detection/pkg/types"
	hivev1 "github.com/openshift/hive/apis/hive/v1"
)

var (
	stoppedInfraLS = ocm.LimitedSupportReason{
		Summary: "Cluster is in Limited Support due to unsupported cloud provider configuration",
		Details: "Your cluster is no longer checking in with Red Hat OpenShift Cluster Manager due to stopped or terminated instances. If the instances were stopped, please restart them, as stopping instances is not supported. If you intended to terminate the cluster, please delete it in the Red Hat console",
	}

	egressLS = ocm.LimitedSupportReason{
		Summary: "Cluster is in Limited Support due to unsupported cloud provider configuration",
		Details: "Action required: Network configuration changes detected that block required internet egress, impacting cluster operation and support. Please revert these changes. For firewall requirements for PrivateLink clusters and troubleshooting help, see: https://access.redhat.com/articles/7128431",
	}
)

type Investigation struct{}

// isInfrastructureError determines if an error is a transient infrastructure
// failure that should cause the investigation to be retried (return error),
// vs an investigation finding that should be reported (return actions).
func isInfrastructureError(err error) bool {
	if err == nil {
		return false
	}

	errStr := err.Error()

	// Transient API failures that should trigger retry
	infraPatterns := []string{
		"could not retrieve non running instances",
		"could not retrieve running cluster nodes",
		"could not retrieve expected cluster nodes",
		"could not PollStopEventsFor",
		"failed to retrieve",
		"timeout",
		"rate limit",
		"connection refused",
		"service unavailable",
	}

	for _, pattern := range infraPatterns {
		if strings.Contains(errStr, pattern) {
			return true
		}
	}

	// Investigation findings that should be reported (NOT retried)
	findingPatterns := []string{
		"stopped instances but no stoppedInstancesEvents", // CloudTrail data too old
		"clusterdeployment is empty",                      // Data missing but not retriable
		"no non running instances found",                  // Investigation finding
		"could not extractUserDetails",                    // Invalid CloudTrail event data
		"failed to parse CloudTrail event version",        // Invalid CloudTrail event data
		"cannot parse a nil input",                        // Invalid CloudTrail event data
	}

	for _, pattern := range findingPatterns {
		if strings.Contains(errStr, pattern) {
			return false
		}
	}

	// Default: assume infrastructure error to be safe (retry)
	return true
}

// Run runs the investigation for a triggered chgm pagerduty event
func (i *Investigation) Run(rb investigation.ResourceBuilder) (investigation.InvestigationResult, error) {
	ctx := context.Background()
	result := investigation.InvestigationResult{}
	r, err := rb.WithClusterDeployment().Build()
	if err != nil {
		return result, err
	}
	r.Notes = notewriter.New("CHGM", logging.RawLogger)

	// 1. Check if the user stopped instances
	res, err := investigateStoppedInstances(r.Cluster, r.ClusterDeployment, r.AwsClient, r.OcmClient)
	if err != nil {
		// Check if this is a transient infrastructure error (AWS/OCM API failures)
		// These should trigger a retry of the entire investigation
		if isInfrastructureError(err) {
			return result, fmt.Errorf("investigation infrastructure failure: %w", err)
		}

		// Otherwise, it's an investigation finding (e.g., CloudTrail data too old)
		// Report this as a finding that needs manual investigation
		r.Notes.AppendWarning("Could not complete instance investigation: %s", err.Error())
		result.Actions = []types.Action{
			executor.NoteFrom(r.Notes),
			executor.Escalate("Investigation incomplete - manual review required"),
		}
		return result, nil
	}
	logging.Debugf("the investigation returned: [infras running: %d] - [masters running: %d]", res.RunningInstances.Infra, res.RunningInstances.Master)

	if !res.UserAuthorized {
		logging.Infof("Instances were stopped by unauthorized user: %s / arn: %s", res.User.UserName, res.User.IssuerUserName)
		r.Notes.AppendAutomation("Customer stopped instances. Sent LS and silencing alert.")

		result.Actions = []types.Action{
			executor.NewLimitedSupportAction(stoppedInfraLS.Summary, stoppedInfraLS.Details).Build(),
			executor.NoteFrom(r.Notes),
			executor.Silence("Customer stopped instances - cluster in limited support"),
		}
		return result, nil
	}
	r.Notes.AppendSuccess("Customer did not stop nodes.")
	logging.Info("The customer has not stopped/terminated any nodes.")

	// 2. Check if the cluster was hibernated and has recently resumed.
	hibernationPeriods, err := getHibernationStatusForCluster(r.OcmClient, r.Cluster)
	if err != nil {
		logging.Warnf("could not check hibernation status of cluster: %w", err)
	}

	if hasRecentlyResumed(hibernationPeriods, time.Now()) {
		logging.Info("The cluster has recently resumed from hibernation.")
		r.Notes.AppendWarning("Cluster has resumed from hibernation within the last %.0f hours - investigate CSRs and kubelet certificates: see https://github.com/openshift/ops-sop/blob/master/v4/alerts/cluster_has_gone_missing.md#24-hibernation", recentWakeupTime.Hours())
	} else {
		logging.Info("The cluster was not hibernated for too long.")
	}

	// 3. Check if the customer blocked egresses
	verifierResult, failureReason, err := networkverifier.Run(r.Cluster, r.ClusterDeployment, r.AwsClient)
	if err != nil {
		logging.Error("Network verifier ran into an error: %s", err.Error())
		r.Notes.AppendWarning("NetworkVerifier failed to run:\n %s", err.Error())
	}

	product := ocm.GetClusterProduct(r.Cluster)

	switch verifierResult {
	case networkverifier.Failure:
		logging.Infof("Network verifier reported failure: %s", failureReason)

		if strings.Contains(failureReason, "nosnch.in") {
			r.Notes.AppendAutomation("Egress `nosnch.in` blocked, sent limited support.")

			result.Actions = []types.Action{
				executor.NewLimitedSupportAction(egressLS.Summary, egressLS.Details).
					WithContext("EgressBlocked").
					Build(),
				executor.NoteFrom(r.Notes),
				executor.Silence("Deadman's snitch blocked - cluster in limited support"),
			}
			return result, nil
		}

		docLink := ocm.DocumentationLink(product, ocm.DocumentationTopicPrivatelinkFirewall)
		egressSL := createEgressSL(failureReason, docLink)

		r.Notes.AppendWarning("NetworkVerifier found unreachable targets and sent the SL, but deadmanssnitch is not blocked! \n⚠️ Please investigate this cluster.\nUnreachable: \n%s", failureReason)

		result.Actions = []types.Action{
			executor.NewServiceLogAction(egressSL.Severity, egressSL.Summary).
				WithDescription(egressSL.Description).
				WithServiceName(egressSL.ServiceName).
				Build(),
			executor.NoteFrom(r.Notes),
			executor.Escalate("Egress blocked but not deadman's snitch - manual investigation required"),
		}
		return result, nil
	case networkverifier.Success:
		r.Notes.AppendSuccess("Network verifier passed")
		logging.Info("Network verifier passed.")
	}

	// Write investigations to a cluster report
	report, err := reports.New(ctx, r.BpClient, &reports.Input{
		ClusterID: r.Cluster.ExternalID(),
		Summary:   "CAD Investigation: Cluster Has Gone Missing",
		Data:      fmt.Sprintf("# Investigation Notes:\n %s \n", r.Notes.String()),
	})
	if err != nil {
		r.Notes.AppendWarning("failed to create cluster report: %v", err)
	}
	if report != nil {
		r.Notes.AppendAutomation("%s", report.GenerateStringForNoteWriter())
	}

	// Found no issues that CAD can handle by itself - forward notes to SRE.
	result.Actions = []types.Action{
		executor.NoteFrom(r.Notes),
		executor.Escalate("No automated remediation available - manual investigation required"),
	}
	return result, nil
}

func (i *Investigation) Name() string {
	return "Cluster Has Gone Missing (CHGM)"
}

func (i *Investigation) AlertTitle() string {
	return "has gone missing"
}

func (i *Investigation) Description() string {
	return "Detects reason for clusters that have gone missing"
}

func (i *Investigation) IsExperimental() bool {
	return false
}

// hasRecentlyResumed checks if the cluster was woken up from
// hibernation within the last 2h. In that case, the internal
// certificates of the kubelets could have expired and CSRs need to be approved
// manually:
// - https://github.com/openshift/hive/blob/master/docs/hibernating-clusters.md
func hasRecentlyResumed(hibernationPeriods []*hibernationPeriod, now time.Time) bool {
	if len(hibernationPeriods) == 0 {
		return false
	}
	latestHibernation := hibernationPeriods[len(hibernationPeriods)-1]
	return now.Sub(latestHibernation.DehibernationTime) <= recentWakeupTime
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
	NonRunningInstances  []ec2v2types.Instance
	RunningInstances     runningNodesCount
	ExpectedInstances    expectedNodesCount
	User                 userInfo
	UserAuthorized       bool
	ClusterState         string
	ClusterNotEvaluated  bool
	LimitedSupportReason ocm.LimitedSupportReason
	Error                string
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

// GetRunningNodesCount return the number of nodes that are currently running in the cluster
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

// GetExpectedNodesCount returns the minimum number of nodes that are supposed to be in the cluster
// We do not use nodes.GetTotal() here, because total seems to be always 0.
func getExpectedNodesCount(cluster *cmv1.Cluster, ocmCli ocm.Client) (*expectedNodesCount, error) {
	nodes, ok := cluster.GetNodes()
	if !ok {
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

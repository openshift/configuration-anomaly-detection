// Package clusteroperatordownhcp investigates the ClusterOperatorDown alert for
// HCP clusters, where a data plane ClusterOperator is degraded because the
// worker node's backing EC2 instance was stopped.
package clusteroperatordownhcp

import (
	"context"
	"fmt"
	"strings"

	ec2v2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	servicelogsv1 "github.com/openshift-online/ocm-sdk-go/servicelogs/v1"
	"github.com/openshift/configuration-anomaly-detection/pkg/aws"
	"github.com/openshift/configuration-anomaly-detection/pkg/executor"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/investigation"
	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
	"github.com/openshift/configuration-anomaly-detection/pkg/ocm"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type Investigation struct{}

func (c *Investigation) Name() string {
	return "clusteroperatordownhcp"
}

// awsMachineStopped is the value of an AWSMachine's status.instanceState when
// its backing EC2 instance has been stopped.
const awsMachineStopped = "stopped"

func (c *Investigation) Run(rb investigation.ResourceBuilder) (investigation.InvestigationResult, error) {
	result := investigation.InvestigationResult{}
	ctx := context.Background()

	// ClusterOperatorDown also fires on classic clusters, so the AWS client is not
	// built here: it authenticates into the customer's AWS account and is only
	// needed once we know this is HCP and a node is actually stopped.
	r, err := rb.WithCluster().WithManagementK8sClient().WithNotes().Build()
	if err != nil {
		return result, err
	}

	// This alert is only actionable on HCP. On classic clusters the AWSMachine /
	// management-cluster model below does not exist, so hand it to a human rather
	// than letting it fall through to the generic AI fallback.
	if !r.IsHCP {
		r.Notes.AppendWarning("ClusterOperatorDown on a non-HCP cluster - this investigation only handles HCP")
		result.Actions = append(
			executor.NoteAndReportFrom(r.Notes, r.Cluster.ID(), c.Name()),
			executor.Escalate("ClusterOperatorDown on non-HCP cluster - manual investigation required"),
		)
		return result, nil
	}

	awsMachineName, instanceID, err := firstStoppedAWSMachine(ctx, r.ManagementK8sClient, r.HCPNamespace)
	if err != nil {
		return result, investigation.WrapInfrastructure(
			fmt.Errorf("failed to list AWSMachines in %s: %w", r.HCPNamespace, err),
			"could not read AWSMachines on the management cluster")
	}

	// No stopped data plane instance means the ClusterOperator is degraded for
	// some other reason CAD can't remediate here.
	if awsMachineName == "" {
		r.Notes.AppendWarning("No stopped AWSMachine found in %s - the degraded operator is not caused by a stopped worker instance", r.HCPNamespace)
		result.Actions = append(
			executor.NoteAndReportFrom(r.Notes, r.Cluster.ID(), c.Name()),
			executor.Escalate("No stopped worker instance found - manual investigation required"),
		)
		return result, nil
	}

	// Only now is the customer AWS account needed, to attribute the stop via
	// CloudTrail. Building it here keeps the non-HCP and healthy-data-plane paths
	// from paying for a client they never use.
	//
	// The client is best-effort for the same reason the CloudTrail lookup below
	// is: the stopped instance is already proven from the management cluster, so
	// an unreachable customer account must not cost us the service log.
	attribution := "CloudTrail attribution unavailable: could not create AWS client."
	awsResources, err := rb.WithAwsClient().Build()
	if err != nil {
		logging.Warnf("could not create AWS client for CloudTrail attribution: %v", err)
	} else {
		attribution = stopAttribution(ctx, awsResources.AwsClient, instanceID)
	}

	// Nothing in the HCP data plane lifecycle leaves an instance stopped: CAPA
	// terminates on scale-down and node replacement — it calls TerminateInstance
	// even on an already-stopped instance — and reports "stopped" as an
	// Error-severity condition rather than an expected lifecycle state. Neither
	// autoscaling nor instance replacement can therefore produce this state, so a
	// stopped instance is an out-of-band action by the customer. That is what
	// makes the service log below safe to send without SRE review.
	r.Notes.AppendWarning("AWSMachine %q is stopped (instance %s). %s", awsMachineName, instanceID, attribution)

	serviceLog := newWorkerNodesStoppedSL()
	result.Actions = append(
		executor.NoteAndReportFrom(r.Notes, r.Cluster.ID(), c.Name()),
		executor.NewServiceLogAction(serviceLog.Severity, serviceLog.Summary).
			WithDescription(serviceLog.Description).
			WithServiceName(serviceLog.ServiceName).
			Build(),
		executor.Silence("Customer stopped worker instance on HCP - service log sent"),
	)
	return result, nil
}

// firstStoppedAWSMachine returns the name and backing EC2 instance ID of the
// first AWSMachine in the namespace whose instance is stopped. The returned name
// is empty, with a nil error, both when no machine is stopped and when every
// stopped machine lacks a resolvable instance ID — without that ID the EC2
// instance cannot be attributed, so such a machine is passed over.
//
// All AWSMachines in an HCP namespace are data plane nodes, so no role filtering
// is applied — the first stopped one is enough to act on.
func firstStoppedAWSMachine(ctx context.Context, managementClient client.Client, namespace string) (string, string, error) {
	awsMachines := &unstructured.UnstructuredList{}
	// v1beta2 is the only served version of the CAPA AWSMachine CRD; v1beta1
	// exists in the schema but is served: false.
	awsMachines.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   "infrastructure.cluster.x-k8s.io",
		Version: "v1beta2",
		Kind:    "AWSMachineList",
	})

	if err := managementClient.List(ctx, awsMachines, client.InNamespace(namespace)); err != nil {
		return "", "", err
	}

	for _, awsMachine := range awsMachines.Items {
		instanceState, _, _ := unstructured.NestedString(awsMachine.Object, "status", "instanceState")
		if instanceState != awsMachineStopped {
			continue
		}
		stoppedInstanceID := instanceIDForMachine(&awsMachine)
		if stoppedInstanceID == "" {
			continue
		}
		return awsMachine.GetName(), stoppedInstanceID, nil
	}
	return "", "", nil
}

// instanceIDForMachine reads the EC2 instance ID from an AWSMachine, preferring
// the explicit spec.instanceID field and falling back to parsing spec.providerID.
// It returns an empty string when neither yields a valid id.
//
// spec.instanceID is the direct, canonical field on CAPA AWSMachines; providerID
// is kept as a fallback because it is populated slightly later in the machine
// lifecycle and is the more universally-present field across CAPI providers.
func instanceIDForMachine(awsMachine *unstructured.Unstructured) string {
	if instanceID, _, _ := unstructured.NestedString(awsMachine.Object, "spec", "instanceID"); strings.HasPrefix(instanceID, "i-") {
		return instanceID
	}
	providerID, _, _ := unstructured.NestedString(awsMachine.Object, "spec", "providerID")
	return instanceIDFromProviderID(providerID)
}

// instanceIDFromProviderID extracts the EC2 instance ID from an AWSMachine
// providerID of the form "aws:///<availability-zone>/<instance-id>". It returns
// an empty string when the providerID is missing or malformed.
func instanceIDFromProviderID(providerID string) string {
	if providerID == "" {
		return ""
	}
	segments := strings.Split(providerID, "/")
	lastSegment := segments[len(segments)-1]
	if !strings.HasPrefix(lastSegment, "i-") {
		return ""
	}
	return lastSegment
}

// stopAttribution returns a human-readable "stopped by <access key> at <time>"
// string from CloudTrail for the PD note. Attribution is best-effort: CloudTrail
// only retains ~2h of lookup events, so an older stop yields a fallback message
// rather than an error — we still act on the stopped state regardless.
func stopAttribution(ctx context.Context, awsClient aws.Client, instanceID string) string {
	instance, err := awsClient.GetInstanceByID(ctx, instanceID)
	if err != nil {
		return fmt.Sprintf("CloudTrail attribution unavailable: %v.", err)
	}

	stopEvents, err := awsClient.PollInstanceStopEventsFor([]ec2v2types.Instance{instance}, 5)
	// A failed lookup is reported as such rather than as an absent event: a
	// persistent CloudTrail problem (denied permissions, throttling) would
	// otherwise read to an SRE as "CloudTrail was checked and had nothing".
	if err != nil {
		return fmt.Sprintf("CloudTrail attribution unavailable: %v.", err)
	}
	if len(stopEvents) == 0 {
		return "CloudTrail stop event not found (instance may have been stopped more than 2h ago)."
	}

	stopEvent := stopEvents[0]
	// The CloudTrail Username is PII. The access key ID identifies the same
	// principal and lets an SRE trace it back through CloudTrail when needed,
	// so it is recorded instead of the username.
	stoppedBy := "an unknown principal"
	if stopEvent.AccessKeyId != nil {
		stoppedBy = fmt.Sprintf("access key %s", *stopEvent.AccessKeyId)
	}
	stoppedAt := "unknown time"
	if stopEvent.EventTime != nil {
		stoppedAt = stopEvent.EventTime.UTC().String()
	}
	return fmt.Sprintf("Stopped by %s at %s (per CloudTrail).", stoppedBy, stoppedAt)
}

// newWorkerNodesStoppedSL mirrors the managed-notifications template
// hcp/WorkerNodes_Stopped_error.json, whose severity is the legacy "Major" —
// SeverityImportant is the same level under the current HCC names.
func newWorkerNodesStoppedSL() *ocm.ServiceLog {
	return &ocm.ServiceLog{
		Severity:     servicelogsv1.SeverityImportant,
		ServiceName:  "SREManualAction",
		Summary:      "Worker node(s) stopped, action required",
		Description:  "Your cluster's worker nodes are stopped due to manual action in AWS which is not supported. Please remediate the issue by starting the instances again. If you would like to change the number of worker instances, please refer to the documentation https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/cluster_administration/managing-compute-nodes-using-machine-pools#rosa-scaling-worker-nodes_rosa-managing-worker-nodes.",
		InternalOnly: false,
	}
}

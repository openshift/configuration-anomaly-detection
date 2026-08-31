// Package clusteroperatordownhcp investigates the ClusterOperatorDown alert for
// HCP clusters, where a data plane ClusterOperator is degraded because the
// worker node's backing EC2 instance was stopped.
package clusteroperatordownhcp

import (
	"context"
	"fmt"
	"strings"

	ec2v2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/openshift/configuration-anomaly-detection/pkg/aws"
	"github.com/openshift/configuration-anomaly-detection/pkg/executor"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/investigation"
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

	// WithAwsClient authenticates to the HCP's own (customer) AWS account, which
	// is where the data plane EC2 instances live — not the management cluster's.
	r, err := rb.WithCluster().WithManagementK8sClient().WithAwsClient().WithNotes().Build()
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

	machine, instanceID, err := firstStoppedAWSMachine(ctx, r.ManagementK8sClient, r.HCPNamespace)
	if err != nil {
		return result, investigation.WrapInfrastructure(
			fmt.Errorf("failed to list AWSMachines in %s: %w", r.HCPNamespace, err),
			"could not read AWSMachines on the management cluster")
	}

	// No stopped data plane instance means the ClusterOperator is degraded for
	// some other reason CAD can't remediate here.
	if machine == "" {
		r.Notes.AppendWarning("No stopped AWSMachine found in %s - the degraded operator is not caused by a stopped worker instance", r.HCPNamespace)
		result.Actions = append(
			executor.NoteAndReportFrom(r.Notes, r.Cluster.ID(), c.Name()),
			executor.Escalate("No stopped worker instance found - manual investigation required"),
		)
		return result, nil
	}

	// On HCP, SRE never stops data plane instances, so a stopped instance is a
	// customer action by definition. CloudTrail attribution is recorded in the
	// PD note for SRE visibility, but does not change the action taken.
	attribution := stopAttribution(ctx, r.AwsClient, instanceID)
	r.Notes.AppendWarning("AWSMachine %q is stopped (instance %s). %s", machine, instanceID, attribution)

	sl := newWorkerNodesStoppedSL()
	result.Actions = append(
		executor.NoteAndReportFrom(r.Notes, r.Cluster.ID(), c.Name()),
		executor.NewServiceLogAction(sl.Severity, sl.Summary).
			WithDescription(sl.Description).
			WithServiceName(sl.ServiceName).
			Build(),
		executor.Silence("Customer stopped worker instance on HCP - service log sent"),
	)
	return result, nil
}

// firstStoppedAWSMachine returns the name and backing EC2 instance ID of the
// first AWSMachine in the namespace whose instance is stopped. It returns an
// empty name (with nil error) when none are stopped.
//
// All AWSMachines in an HCP namespace are data plane nodes, so no role filtering
// is applied — the first stopped one is enough to act on.
func firstStoppedAWSMachine(ctx context.Context, mgmt client.Client, namespace string) (name string, instanceID string, err error) {
	list := &unstructured.UnstructuredList{}
	// v1beta2 is the only served version of the CAPA AWSMachine CRD; v1beta1
	// exists in the schema but is served: false.
	list.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   "infrastructure.cluster.x-k8s.io",
		Version: "v1beta2",
		Kind:    "AWSMachineList",
	})

	if err := mgmt.List(ctx, list, client.InNamespace(namespace)); err != nil {
		return "", "", err
	}

	for i := range list.Items {
		m := &list.Items[i]
		state, _, _ := unstructured.NestedString(m.Object, "status", "instanceState")
		if state != awsMachineStopped {
			continue
		}
		id := instanceIDForMachine(m)
		if id == "" {
			continue
		}
		return m.GetName(), id, nil
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
func instanceIDForMachine(m *unstructured.Unstructured) string {
	if id, _, _ := unstructured.NestedString(m.Object, "spec", "instanceID"); strings.HasPrefix(id, "i-") {
		return id
	}
	providerID, _, _ := unstructured.NestedString(m.Object, "spec", "providerID")
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

// stopAttribution returns a human-readable "stopped by <user> at <time>" string
// from CloudTrail for the PD note. Attribution is best-effort: CloudTrail only
// retains ~2h of lookup events, so an older stop yields a fallback message
// rather than an error — we still act on the stopped state regardless.
func stopAttribution(ctx context.Context, awsCli aws.Client, instanceID string) string {
	inst, err := awsCli.GetInstanceByID(ctx, instanceID)
	if err != nil {
		return fmt.Sprintf("CloudTrail attribution unavailable: %v", err)
	}

	events, err := awsCli.PollInstanceStopEventsFor([]ec2v2types.Instance{inst}, 5)
	if err != nil || len(events) == 0 {
		return "CloudTrail stop event not found (instance may have been stopped more than 2h ago)."
	}

	stopEvent := events[0]
	stoppedBy := "unknown"
	if stopEvent.Username != nil {
		stoppedBy = *stopEvent.Username
	}
	stoppedAt := "unknown time"
	if stopEvent.EventTime != nil {
		stoppedAt = stopEvent.EventTime.UTC().String()
	}
	return fmt.Sprintf("Stopped by %s at %s (per CloudTrail).", stoppedBy, stoppedAt)
}

// newWorkerNodesStoppedSL mirrors the managed-notifications template
// hcp/WorkerNodes_Stopped_error.json. Severity uses the HCC name "Important"
// (equivalent to the legacy "Major" the template is authored with).
func newWorkerNodesStoppedSL() *ocm.ServiceLog {
	return &ocm.ServiceLog{
		Severity:     "Important",
		ServiceName:  "SREManualAction",
		Summary:      "Worker node(s) stopped, action required",
		Description:  "Your cluster's worker nodes are stopped due to manual action in AWS which is not supported. Please remediate the issue by starting the instances again. If you would like to change the number of worker instances, please refer to the documentation https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/cluster_administration/managing-compute-nodes-using-machine-pools#rosa-scaling-worker-nodes_rosa-managing-worker-nodes.",
		InternalOnly: false,
	}
}

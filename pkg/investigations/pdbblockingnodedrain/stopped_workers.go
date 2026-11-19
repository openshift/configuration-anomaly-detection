package pdbblockingnodedrain

import (
	"context"
	"fmt"
	"strings"

	cloudtrailtypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/investigation"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	awsMachineNodePoolLabel = "hypershift.openshift.io/nodepool-name"
	hostedNodePoolLabel     = "hypershift.openshift.io/nodePool"
)

// checkStoppedWorkers runs before drain/PDB checks. It only treats a stopped
// instance as the primary finding when the AWSMachine can be tied to a nodepool
// in this incident and a StopInstances event predates any known drain stall.
// An unconfirmed stop is reported for SRE review without suppressing PDB checks.
func (i *Investigation) checkStoppedWorkers(ctx context.Context, rb investigation.ResourceBuilder, r *investigation.Resources) (confirmed, suspected bool) {
	if !r.IsHCP || r.PdClient == nil {
		return false, false
	}

	poolIDs, err := r.PdClient.RetrieveNodePoolIDs()
	if err != nil {
		r.Notes.AppendWarning("Stopped Workers: could not identify alerted nodepool(s): %v; continuing drain and PDB checks", err)
		return false, false
	}

	management, err := rb.WithManagementK8sClient().Build()
	if err != nil {
		r.Notes.AppendWarning("Stopped Workers: could not access management cluster: %v; continuing drain and PDB checks", err)
		return false, false
	}

	awsMachines := &unstructured.UnstructuredList{}
	awsMachines.SetGroupVersionKind(schema.GroupVersionKind{
		Group: "infrastructure.cluster.x-k8s.io", Version: "v1beta2", Kind: "AWSMachineList",
	})
	if err := management.ManagementK8sClient.List(ctx, awsMachines, client.InNamespace(management.HCPNamespace)); err != nil {
		r.Notes.AppendWarning("Stopped Workers: could not list AWSMachines: %v; continuing drain and PDB checks", err)
		return false, false
	}

	nodes := &corev1.NodeList{}
	if err := r.K8sClient.List(ctx, nodes); err != nil {
		r.Notes.AppendWarning("Stopped Workers: could not list hosted cluster Nodes: %v; stop timing cannot be verified, continuing drain and PDB checks", err)
		return false, true
	}

	for _, machine := range awsMachines.Items {
		state, _, err := unstructured.NestedString(machine.Object, "status", "instanceState")
		if err != nil {
			suspected = true
			r.Notes.AppendWarning("Stopped Workers: AWSMachine %s has an unreadable instance state: %v; manual review required", machine.GetName(), err)
			continue
		}
		if state != string(ec2types.InstanceStateNameStopped) {
			continue
		}
		instanceID, err := awsMachineInstanceID(&machine)
		if err != nil {
			suspected = true
			r.Notes.AppendWarning("Stopped Workers: AWSMachine %s has an unreadable instance ID: %v; manual review required", machine.GetName(), err)
			continue
		}
		poolID, node := matchingAlertPool(&machine, instanceID, nodes.Items, poolIDs, r.Cluster.DomainPrefix(), management.HCNamespace)
		if poolID == "" {
			// A stop in another pool must not override this pool's PDB finding.
			continue
		}
		if instanceID == "" {
			suspected = true
			r.Notes.AppendWarning("Stopped Workers: AWSMachine %s in alerted nodepool %s is stopped but has no instance ID; manual review required", machine.GetName(), poolID)
			continue
		}

		awsResources, err := rb.WithAwsClient().Build()
		if err != nil {
			suspected = true
			r.Notes.AppendWarning("Stopped Workers: AWSMachine %s (instance %s, nodepool %s) is stopped, but AWS access failed: %v; manual review required", machine.GetName(), instanceID, poolID, err)
			continue
		}
		instance, err := awsResources.AwsClient.GetInstanceByID(ctx, instanceID)
		if err != nil || instance.State == nil {
			suspected = true
			r.Notes.AppendWarning("Stopped Workers: AWSMachine %s reports stopped, but EC2 state for %s could not be confirmed (%v); manual review required", machine.GetName(), instanceID, err)
			continue
		}
		if instance.State.Name != ec2types.InstanceStateNameStopped {
			r.Notes.AppendWarning("Stopped Workers: AWSMachine %s reports stopped, but EC2 instance %s is currently %s; continuing drain and PDB checks", machine.GetName(), instanceID, instance.State.Name)
			continue
		}
		events, err := awsResources.AwsClient.PollInstanceStopEventsFor([]ec2types.Instance{instance}, 5)
		if err != nil {
			suspected = true
			r.Notes.AppendWarning("Stopped Workers: EC2 instance %s in nodepool %s is stopped, but CloudTrail lookup failed: %v; manual review required", instanceID, poolID, err)
			continue
		}
		var stopEvent *cloudtrailtypes.Event
		for _, e := range events {
			if e.EventName != nil && *e.EventName == "StopInstances" {
				eventCopy := e
				stopEvent = &eventCopy
				break
			}
		}
		if stopEvent == nil || stopEvent.EventTime == nil {
			suspected = true
			r.Notes.AppendWarning("Stopped Workers: EC2 instance %s in nodepool %s is stopped, but a CloudTrail StopInstances event was not found; manual review required", instanceID, poolID)
			continue
		}
		if node != nil {
			if taint, found := findUnschedulableTaint(*node); found && taint.TimeAdded != nil && stopEvent.EventTime.After(taint.TimeAdded.Time) {
				r.Notes.AppendWarning("Stopped Workers: instance %s was stopped at %s after node %s began draining at %s; the stop does not explain the initial drain stall", instanceID, stopEvent.EventTime.UTC(), node.Name, taint.TimeAdded.UTC())
				continue
			}
		}

		stoppedBy := "an unknown principal"
		if stopEvent.AccessKeyId != nil {
			stoppedBy = fmt.Sprintf("access key %s", *stopEvent.AccessKeyId)
		}
		stoppedAt := "unknown time"
		if stopEvent.EventTime != nil {
			stoppedAt = stopEvent.EventTime.UTC().String()
		}
		r.Notes.AppendWarning("Stopped Workers: EC2 instance %s for AWSMachine %s in alerted nodepool %s is stopped. Stopped by %s at %s (per CloudTrail).", instanceID, machine.GetName(), poolID, stoppedBy, stoppedAt)
		return true, true
	}
	return false, suspected
}

func awsMachineInstanceID(machine *unstructured.Unstructured) (string, error) {
	id, _, err := unstructured.NestedString(machine.Object, "spec", "instanceID")
	if err != nil {
		return "", fmt.Errorf("spec.instanceID: %w", err)
	}
	if strings.HasPrefix(id, "i-") {
		return id, nil
	}
	providerID, _, err := unstructured.NestedString(machine.Object, "spec", "providerID")
	if err != nil {
		return "", fmt.Errorf("spec.providerID: %w", err)
	}
	return instanceIDFromProviderID(providerID), nil
}

func instanceIDFromProviderID(providerID string) string {
	if !strings.HasPrefix(providerID, "aws:///") {
		return ""
	}
	id := providerID[strings.LastIndex(providerID, "/")+1:]
	if !strings.HasPrefix(id, "i-") {
		return ""
	}
	return id
}

func matchingAlertPool(machine *unstructured.Unstructured, instanceID string, nodes []corev1.Node, alertPools []string, domainPrefix, hcNamespace string) (string, *corev1.Node) {
	for _, node := range nodes {
		if instanceID == "" || instanceIDFromProviderID(node.Spec.ProviderID) != instanceID {
			continue
		}
		for _, pool := range alertPools {
			if nodePoolValueMatches(node.Labels[hostedNodePoolLabel], pool, domainPrefix, hcNamespace) {
				return pool, &node
			}
		}
		// A matched hosted Node is stronger evidence than an AWSMachine label.
		// If it belongs to another pool, do not fall back to a stale label.
		return "", &node
	}
	for _, pool := range alertPools {
		if nodePoolValueMatches(machine.GetLabels()[awsMachineNodePoolLabel], pool, domainPrefix, hcNamespace) {
			return pool, nil
		}
	}
	return "", nil
}

func nodePoolValueMatches(value, poolID, domainPrefix, hcNamespace string) bool {
	if value == "" || poolID == "" {
		return false
	}
	if value == poolID {
		return true
	}
	qualifiedName := domainPrefix + "-" + poolID
	if domainPrefix != "" && value == qualifiedName {
		return true
	}
	return hcNamespace != "" && (value == hcNamespace+"/"+poolID || (domainPrefix != "" && value == hcNamespace+"/"+qualifiedName))
}

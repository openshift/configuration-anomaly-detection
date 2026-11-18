# pdbblockingnodedrain Investigation

Investigates PodDisruptionBudgets (PDBs) blocking node drain during HCP cluster upgrades,
triggered by the `HCPNodepoolUpgradeDelay` alert.

The investigation first checks whether a worker in an alerted nodepool was stopped.
If that is confirmed, it reports the stopped worker and escalates for SRE review
of the CloudTrail actor and customer notification. Otherwise it identifies PDBs blocking eviction,
classifies them as customer-managed or platform-managed, and assesses whether
scaling can resolve the issue without requiring a PDB change.

## Investigation Flow

| # | Check | Description | Type |
|---|-------|-------------|------|
| 1 | **Stopped workers** | Reads nodepool IDs from the PagerDuty firing alert, matches stopped management-cluster AWSMachines to those pools, confirms current EC2 state, and looks up the instance's `StopInstances` event in CloudTrail | Stops PDB checks and escalates for actor/notification review on confirmation |
| 2 | **Draining nodes** | Lists all nodes with the `node.kubernetes.io/unschedulable` taint and flags those stalled longer than 10 minutes | Informational |
| 3 | **Blocking PDBs** | Enumerates PDBs with `disruptionsAllowed=0` whose selected pods are on stalled nodes; resolves owner workloads (Deployment, StatefulSet, etc.) and classifies each PDB as customer-managed or platform-managed based on namespace | Informational |
| 4 | **Scaling assessment** | For each blocking PDB, compares `minAvailable`/`maxUnavailable` against healthy replica count to determine if scaling up the workload would unblock the drain | Informational |

The stopped-worker path takes precedence only when the stopped AWSMachine belongs
to a nodepool with a currently triggered PagerDuty alert, EC2 still reports it
stopped, and a successful CloudTrail stop event is found. Nodepool labels must
match the complete pool name, optionally qualified by this cluster's domain
prefix and hosted-cluster namespace. A later successful `StartInstances` event
invalidates an earlier stop. If a node already began draining before the stop
event, the stop is reported as later evidence and the PDB path continues.
The Kubernetes and AWS requests in the stopped-worker check share a 45-second
deadline. Incomplete Node, AWS, or CloudTrail evidence is reported for manual
review and does not suppress PDB
checks. A `StopInstances` event alone does not prove a customer initiated the
stop, so CAD does not automatically send a customer service log. The SRE
follow-up points to the existing `hcp/WorkerNodes_Stopped_error.json` template
when customer attribution and notification status are confirmed.

If no stalled nodes or confirmed stopped workers are found, the investigation
escalates for manual review since the alert may indicate an issue outside the
scope of this investigation. Otherwise, it escalates with all collected findings.

## Design Decisions

### Eviction event correlation not implemented

The Jira ticket (ROSAENG-14105) originally called for correlating eviction failure events
(e.g. "Cannot evict pod", "disruption budget") with stalled nodes. Testing showed these
events are produced by the drain controller on the management cluster, not on the service
cluster. Accessing MC events would require RHOBS integration (blocked by ROSAENG-15920) and
MC-to-RHOBS log forwarding on staging (not yet available). The blocking PDB check (step 2)
already provides definitive detection without events: if a PDB has `disruptionsAllowed=0` and
its pods are on a draining node, it is the blocker.

## Architecture

The investigation first builds hosted-cluster Kubernetes and note resources with
`rb.WithCluster().WithK8sClient().WithNotes().Build()`. It then reads AWSMachines
from the management cluster and only builds the customer AWS SDK client when a
stopped machine matches an alerted nodepool. Drain and PDB checks use the hosted
cluster Kubernetes API. CloudTrail is queried by EC2 instance ID for up to 90
days, since the stop may precede the upgrade delay by several days.

### Platform vs customer classification

A PDB is classified as platform-managed if its namespace starts with `openshift-` or `kube-`,
or is exactly `openshift`. All other namespaces are treated as customer-managed.
This determines the remediation guidance (customer should fix vs. platform issue to escalate).

## Testing

Refer to the [testing README](./testing/README.md) for instructions on testing this investigation.

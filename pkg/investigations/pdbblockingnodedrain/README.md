# pdbblockingnodedrain Investigation

Investigates PodDisruptionBudgets (PDBs) blocking node drain during HCP cluster upgrades,
triggered by the `HCPNodepoolUpgradeDelay` alert.

When a node drain stalls during an upgrade, this investigation identifies which PDBs are
blocking eviction, classifies them as customer-managed or platform-managed, and assesses
whether scaling can resolve the issue without requiring a PDB change.

## Investigation Flow

| # | Check | Description | Type |
|---|-------|-------------|------|
| 1 | **Draining nodes** | Lists all nodes with the `node.kubernetes.io/unschedulable` taint and flags those stalled longer than 10 minutes | Informational |
| 2 | **Blocking PDBs** | Enumerates PDBs with `disruptionsAllowed=0` whose selected pods are on stalled nodes; resolves owner workloads (Deployment, StatefulSet, etc.) and classifies each PDB as customer-managed or platform-managed based on namespace | Informational |
| 3 | **Scaling assessment** | For each blocking PDB, compares `minAvailable`/`maxUnavailable` against healthy replica count to determine if scaling up the workload would unblock the drain | Informational |

If no stalled nodes are found, the investigation escalates for manual review since the alert
may indicate an issue outside the scope of this investigation. Otherwise, it escalates with
all collected findings.

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

Single-phase resource build: `rb.WithCluster().WithK8sClient().WithNotes().Build()`

All checks run against the service cluster K8s API using controller-runtime's client.

### Platform vs customer classification

A PDB is classified as platform-managed if its namespace starts with `openshift-` or `kube-`,
or is exactly `openshift`. All other namespaces are treated as customer-managed.
This determines the remediation guidance (customer should fix vs. platform issue to escalate).

## Testing

Refer to the [testing README](./testing/README.md) for instructions on testing this investigation.
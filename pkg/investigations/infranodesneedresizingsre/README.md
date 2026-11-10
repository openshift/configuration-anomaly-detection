# infranodesneedresizingsre Investigation

Handles the `InfraNodesNeedResizingSRE` alert, raised when the dedicated infra nodes of a cluster are
under resource pressure and SRE has to resize the infra machine pool. Tracked in MCS-67 (spike) / MCS-1496.

The investigation gives on-call the context to size the change: it reports how heavily each infra node is
loaded and which platform components (by namespace) are the largest resource requesters on them.

**Stage: informing.** The investigation is read-only. It never resizes anything and never sends a service
log — it records its findings in the PD note and escalates, so the verdicts can be compared with on-call
resolutions before any action is enabled.

## Investigation Flow

| # | Case | Action |
|---|------|--------|
| 0 | Management/service cluster | Escalate as an incident, stop the chain |
| 1 | No infra nodes (`node-role.kubernetes.io/infra`) found | Note and escalate |
| 2 | Infra nodes found | Summarise per-node scheduled requests vs allocatable and the top-requesting namespaces; recommend a resize if any node is ≥85% of allocatable on requests; escalate |

Load is measured from **scheduled resource requests** (nodes + pods via the K8s API), not live metrics,
which CAD does not read in the informing stage. When requests are below the threshold the note says so and
asks on-call to confirm against metrics before resizing.

## Testing

Refer to the [testing README](./testing/README.md) for instructions on testing this investigation.

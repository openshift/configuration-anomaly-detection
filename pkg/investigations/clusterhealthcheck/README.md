# clusterhealthcheck Investigation

Runs comprehensive health checks against a cluster, replicating the functionality of the [managed-scripts health/cluster-health-check](https://github.com/openshift/managed-scripts/tree/main/scripts/health/cluster-health-check).

## Checks

- **Cluster Operators** — reports degraded, unavailable, or progressing operators.
- **API Server Health** — checks `/healthz`, `/livez`, `/readyz` endpoints and per-pod readiness in `openshift-apiserver` and `openshift-kube-apiserver`.
- **ETCD Status** — execs `etcdctl endpoint health --cluster` in an etcd pod to verify cluster health via a linearizable read. Skipped on HCP.
- **MachineConfigPools** — reports degraded or updating MCPs. Skipped on HCP.
- **Pending CSRs** — lists pending certificate signing requests.
- **Node Status** — reports not-ready, unschedulable, or condition-flagged nodes and taints.
- **Capacity** — reports per-node CPU/memory pre-allocation and live utilization via the metrics API.
- **Firing Alerts** — queries Alertmanager (via pod exec) for active firing alerts.
- **Cluster Version** — reports current version, update conditions, and EOL status by querying the OpenShift upgrade graph API.
- **Failing Pods** — reports failed, crash-looping, or high-restart pods.
- **Restrictive PDBs** — reports PodDisruptionBudgets blocking voluntary disruptions (`MaxUnavailable=0`, `MaxUnavailable=0%`, `MinAvailable=100%`, or `MinAvailable >= ExpectedPods`).
- **Events** — reports non-normal cluster events.

## Deviations from the managed-script

This implementation closely follows the original but has a few notable differences:

- **ETCD**: Uses `etcdctl endpoint health --cluster` (linearizable/consensus-verified) instead of curling the `etcd-readyz` sidecar (serializable/local-only). Stronger check, but reports at the cluster level rather than per-pod.
- **Alerts**: Uses pod exec + Alertmanager v2 API instead of route + OAuth + v1 API. Same data, different access path.
- **PDB**: Checks more conditions than the original (also covers `MinAvailable` and gates on `DisruptionsAllowed`).

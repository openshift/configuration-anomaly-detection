# etcdDatabaseQuotaLowSpace Investigation

## Overview
Takes etcd snapshots for analysis when etcd database quota is running low.

### ROSA Classic Clusters
- Executes commands inside etcd pods to create snapshots
- Uses host path volumes for snapshot storage (/var/lib/etcd)
- Creates analysis Job on customer cluster in openshift-etcd namespace

### ROSA HCP Clusters
- Connects to management cluster where etcd runs
- Creates Kubernetes Job in HCP namespace (e.g., `ocm-staging-{cluster-id}-{domain}`)
- Job uses init container to snapshot etcd via network call
- Analysis runs in same Job using shared emptyDir volume

## RBAC Requirements

### Customer Cluster (Classic ROSA)
Namespace: `openshift-etcd`
- Read etcd pods (get, list)
- Execute commands in pods (pods/exec create)
- Read pod logs (pods/log get)
- Create and read Jobs (jobs create, get)

### Management Cluster (HCP)
Namespace: Dynamically resolved `ocm-{environment}-{cluster-id}-{domain}`
- Create, read, list, and delete Jobs (jobs create, get, list, delete)
- Read pods for job status checking (pods get, list)
- Read pod logs (pods/log get) - Note: Will fail on MC, triggering DynaTrace fallback
- Read configmaps and secrets for etcd TLS certificates (configmaps, secrets get)

## Security Considerations
- No etcd data leaves the management cluster
- Snapshots stored in ephemeral emptyDir volumes only
- `customerDataAccess: false` (no customer workload data accessed)
- Management cluster access scoped to single HCP namespace
- RBAC credentials time-limited via backplane remediation system

## Phase 1 Status
Phase 1 (Management Cluster Access) establishes connectivity to management clusters for HCP investigations.
Full automated analysis workflow (Phase 2) is pending implementation.

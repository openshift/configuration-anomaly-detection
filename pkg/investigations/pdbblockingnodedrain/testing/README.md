# Testing the pdbblockingnodedrain Investigation

This document describes how to test the pdbblockingnodedrain investigation end-to-end in a local environment.

## Overview

This investigation is triggered by the `HCPNodepoolUpgradeDelay` alert and:
1. Identifies nodes stuck in a draining state (>10 minutes)
2. Enumerates PDBs with `disruptionsAllowed=0` whose pods are on stalled nodes
3. Classifies blocking PDBs as customer-managed or platform-managed
4. Checks non-draining node health (NotReady, resource pressure)
5. Assesses whether scaling the workload would unblock the drain

## Prerequisites

### Environment Requirements
- **Cluster**: HCP cluster with at least 2 worker nodes
- **Access**: Cluster must be accessible via backplane/OCM
- **Environment Variables**: Set up via `source test/set_stage_env.sh`
- **Local Backplane API**: Start local backplane instance:
  ```bash
  OCM_BACKPLANE_REPO_PATH=<PATH/TO/BACKPLANE>/backplane-api ./test/launch_local_env.sh
  ```

### Build the Binary
```bash
make build
```

## Unit Testing

```bash
make test-cadctl
```

## Manual Testing

### Step 1: Create the Test Workload

Create a deployment with 2 replicas and a PDB that blocks all disruptions:

```bash
oc new-project pdb-test
```

```bash
oc create deployment drain-blocker --image=registry.access.redhat.com/ubi9/ubi-minimal:latest --replicas=2 -- sleep infinity
```

Wait for pods to be running:

```bash
oc get pods -n pdb-test -w
```

### Step 2: Create a Blocking PDB

```bash
cat <<'EOF' | oc create -f -
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: drain-blocker-pdb
  namespace: pdb-test
spec:
  minAvailable: 2
  selector:
    matchLabels:
      app: drain-blocker
EOF
```

Verify the PDB shows `ALLOWED DISRUPTIONS: 0`:

```bash
oc get pdb -n pdb-test
```

### Step 3: Cordon a Node to Simulate Drain Stall

Identify the node running the pods:

```bash
oc get pods -n pdb-test -o wide
```

Cordon the node (replace with the actual node name):

```bash
oc cordon <node-name>
```

Wait at least 10 minutes for the drain stall threshold to be exceeded.

### Step 4: Generate Test Incident

```bash
./test/generate_incident.sh HCPNodepoolUpgradeDelay <cluster-id>
```

### Step 5: Run the Investigation

```bash
source test/set_stage_env.sh
```

```bash
BACKPLANE_URL=https://localhost:8443 \
HTTP_PROXY=http://127.0.0.1:8888 \
HTTPS_PROXY=http://127.0.0.1:8888 \
BACKPLANE_PROXY=http://127.0.0.1:8888 \
./bin/cadctl investigate --payload-path ./payload --log-level debug
```

### Step 6: Verify Results

The PagerDuty note should contain:

1. **Draining Nodes** — reports the stalled node and drain duration
2. **Blocking PDBs** — reports `pdb-test/drain-blocker-pdb` as a customer-managed PDB with `disruptionsAllowed=0`, listing the owner workload and pod names
3. **Node Health** — reports whether non-draining nodes are healthy
4. **Scaling Assessment** — reports that scaling up by 1 replica would unblock the drain
5. **Remediation** — suggests the customer should relax the PDB or scale the workload

Example output:
```
⚠️ Draining Nodes: 1/1 draining node(s) stalled (>10m0s):
  <node-name>: draining for <duration>
⚠️ Blocking PDBs: 1 PDB(s) with disruptionsAllowed=0 affecting pods on stalled nodes:
  pdb-test/drain-blocker-pdb [customer] (minAvailable: 2, healthy: 2/2)
    Owner: Deployment/drain-blocker
    Pods on draining nodes: drain-blocker-xxx, drain-blocker-yyy
✅ Node Health: all non-draining nodes are Ready with no resource pressure
⚠️ Scaling Assessment: 1 PDB(s) can be unblocked by scaling:
  pdb-test/drain-blocker-pdb: scaling up by 1 replica would unblock the drain (healthy: 2, minAvailable: 2)
⚠️ Remediation: 1 customer-managed PDB(s) — customer should relax the PDB or scale the workload to allow disruptions
```

### Step 7: Test Scaling Fix

Scale up the deployment to verify the drain unblocks:

```bash
oc scale deployment/drain-blocker -n pdb-test --replicas=3
```

Re-run the investigation. The PDB should no longer be reported as blocking.

### Step 8: Cleanup

```bash
oc delete namespace pdb-test
```

```bash
oc uncordon <node-name>
```

## Testing Variants

### Well-configured PDB (should not block)

Use `maxUnavailable: 1` instead of `minAvailable: 2`:

```bash
cat <<'EOF' | oc create -f -
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: drain-blocker-pdb
  namespace: pdb-test
spec:
  maxUnavailable: 1
  selector:
    matchLabels:
      app: drain-blocker
EOF
```

This PDB allows 1 disruption, so the investigation should report no blocking PDBs.

### Platform-managed PDB

Deploy a workload in an `openshift-*` namespace to test platform classification. The investigation should report it as `[platform]` with guidance to escalate to engineering.
# Manual Investigation Pipeline

The manual investigation pipeline allows running specific CAD investigations on-demand via Tekton, without requiring a PagerDuty alert webhook.

## Overview

This pipeline uses the `cadctl run` command to execute a specific investigation against a target cluster. It is triggered by directly creating a PipelineRun manifest in the CAD cluster.

## Components

### Pipeline: `cad-manual-investigation-pipeline`

A Tekton Pipeline that orchestrates the execution of a manual investigation.

**Parameters:**
- `cluster-id` (required, string): The cluster ID to investigate
- `investigation` (required, string): The investigation name to run
- `dry-run` (optional, string, default: "false"): Run in dry-run mode without performing external operations

**Tasks:**
- `run-manual-investigation`: Executes the `cad-manual-investigation` task with the provided parameters

### Task: `cad-manual-investigation`

A Tekton Task that runs `cadctl run` with the specified parameters inside a container.

## Architecture Details

### How the Pipeline Works

When you create a PipelineRun:

1. **Kubernetes creates the PipelineRun resource** with your parameters
2. **Tekton controller detects the new PipelineRun** and starts executing it
3. **Pipeline passes parameters to the Task** including cluster-id, investigation, and dry-run flag
4. **Task creates a Pod** using the CAD container image
5. **Pod executes** `cadctl run --cluster-id <id> --investigation <name>` with access to secrets
6. **Investigation runs** and produces output (logs, PagerDuty notes, service logs, etc.)
7. **Pod completes** and Tekton marks the PipelineRun as succeeded or failed

## Usage

### Creating a PipelineRun Programmatically

External tools should create a PipelineRun manifest and apply it to the cluster. Here's the basic structure:

```yaml
apiVersion: tekton.dev/v1beta1
kind: PipelineRun
metadata:
  generateName: cad-manual-
  namespace: configuration-anomaly-detection-production
spec:
  params:
  - name: cluster-id
    value: "<CLUSTER_ID>"
  - name: investigation
    value: "<INVESTIGATION_NAME>"
  - name: dry-run
    value: "false"
  pipelineRef:
    name: cad-manual-investigation-pipeline
  serviceAccountName: cad-sa
  timeout: 30m
```

**Key fields explained:**

- `generateName: cad-manual-`: Kubernetes will append a unique suffix (e.g., `cad-manual-abc123`)
- `namespace`: Must be `configuration-anomaly-detection` (or your CAD namespace)
- `params`: The parameters passed to the pipeline
- `pipelineRef.name`: Must match the pipeline name (`cad-manual-investigation-pipeline`)
- `serviceAccountName`: Must be `cad-sa` to have access to secrets
- `timeout`: Maximum time for the pipeline to run (default: 30m)

### Example: Using oc/kubectl

```bash
oc create -f - <<EOF
apiVersion: tekton.dev/v1beta1
kind: PipelineRun
metadata:
  generateName: cad-manual-
  namespace: configuration-anomaly-detection
spec:
  params:
  - name: cluster-id
    value: "<CLUSTER_ID>"
  - name: investigation
    value: "<INVESTIGATION_NAME>"
  - name: dry-run
    value: "false"
  pipelineRef:
    name: cad-manual-investigation-pipeline
  serviceAccountName: cad-sa
  timeout: 30m
EOF
```

### investigation (required)

The short name of the investigation to run. This must match a registered investigation in the CAD system.

**Type:** string

**Available investigations:**
- `chgm` - Cluster Has Gone Missing
- `cmbb` - Cluster Monitoring Error Budget Burn
- `can-not-retrieve-updates` - Cannot Retrieve Updates SRE
- `ai` - AI Assisted
- `cpd` - Cluster Provisioning Delay
- `etcd-quota-low` - ETCD Database Quota Low Space
- `insightsoperatordown` - Insights Operator Down
- `machine-health-check` - Machine Health Check Unterminated Short Circuit SRE
- `must-gather` - Must Gather
- `upgrade-config` - Upgrade Config Sync Failure Over 4hr

### dry-run (optional)

When set to `"true"`, the investigation will run in dry-run mode.

**Type:** string (must be `"true"` or `"false"` as a string)
**Default:** `"false"`

**Dry-run behavior:**
- Investigation logic executes normally
- No external operations are performed:
  - No PagerDuty notes are posted
  - No service logs are sent
  - No cluster modifications are made
- Results are logged locally only
- Useful for testing investigations or debugging

## Monitoring PipelineRuns

### View Logs of a Specific Run

You will need to connect to the CAD cluster in production.

```bash
# Get the PipelineRun name first
oc get pipelineruns -n configuration-anomaly-detection-production

# View logs
oc logs \
  -n configuration-anomaly-detection-production \
  -l tekton.dev/pipelineRun=<PIPELINERUN_NAME> \
  --all-containers \
  --follow
```

### Automatic Cleanup

A CronJob named `tekton-resource-pruner` runs hourly to clean up old PipelineRuns:
- Keeps the most recent 100 PipelineRuns
- Deletes older PipelineRuns automatically
- Runs at the top of every hour


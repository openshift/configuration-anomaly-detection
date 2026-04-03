# Testing the OCMAgentResponseFailureServiceLogsSRE investigation

This document describes how to test the OCMAgentResponseFailureServiceLogsSRE investigation end-to-end in a local environment.

## Overview

This investigation:
1. verifies if the cluster is classic ROSA (HCP is not supported)
1. runs the network verifier
1. checks if the cluster owner is banned
1. validate the cluster pull secret

> [!NOTE]
>While unit tests use a mocked OCM client to test the user ban validation logic, for integration tests in staging I've tested by returning a hard-coded error.

## Prerequisites

### Environment Requirements
- **Cluster**: ROSA classic cluster (HCP clusters are not supported)
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

## Unit testing

> [!NOTE]
>Only part of the investigation is covered by unit tests: at the time of writing some checks reach out to the AWS API even when using mocked clients.

To run unit tests:

```
$ make test
```


## Manual Testing

### Step 1: Create or Identify a ROSA Classic Cluster

You need an actual ROSA classic cluster. Note the cluster ID for the next steps.

### Step 2: Generate Test Incident Payload

Create a PagerDuty incident payload that triggers the `OCMAgentResponseFailureServiceLogsSRE` alert:

```bash
./test/generate_incident.sh OCMAgentResponseFailureServiceLogsSRE $CLUSTER_ID
```

This creates a `payload` file in the current directory and a PagerDuty incident which can be checked for CAD output.

### Step 3: Set Up Environment

```bash
# Export environment variables from vault
source test/set_stage_env.sh
```

### Step 4: Run the Investigation

```bash
BACKPLANE_URL=https://localhost:8443 \
HTTP_PROXY=http://127.0.0.1:8888 \
HTTPS_PROXY=http://127.0.0.1:8888 \
BACKPLANE_PROXY=http://127.0.0.1:8888 \
./bin/cadctl investigate --payload-path ./payload --log-level debug
```

### Step 5: Verify Results

The investigation should:

1. **Validate network egress** - Check logs for:
   ```
   Running Network Verifier with security group [...]
   ```
   i. if the network verifier reports a failure, the incident should be escalated:

   ```
   {"level":"info","timestamp":"2026-04-14T15:14:13+02:00","caller":"notewriter/notewriter.go:38","msg":"⚠️ Network verifier reported failure: https://observatorium-mst.api.openshift.com:443 (Failed to connect to observatorium-mst.api.openshift.com port 443: Connection timed out)\n","cluster_id":"","pipeline_name":""}
   {"level":"info","timestamp":"2026-04-14T15:14:16+02:00","caller":"executor/actions.go:211","msg":"Escalating incident: Egress network verifier failed. Please investigate.","cluster_id":"","pipeline_name":""}
   ```

   ii. if the network verifier runs successfully, the next check is performed:

   ```
   {"level":"info","timestamp":"2026-04-14T16:17:41+02:00","caller":"logging/logging.go:42","msg":"Network verifier passed.","cluster_id":"","pipeline_name":""}
   ```

2. **Check if the cluster owner is banned in OCM** - Check logs for:

   ```
   {"level":"info","timestamp":"2026-04-14T16:17:42+02:00","caller":"notewriter/notewriter.go:38","msg":"✅ User is not banned.\n","cluster_id":"","pipeline_name":""}
   ```
    or:

    ```
    {"level":"info","timestamp":"2026-04-14T16:28:29+02:00","caller":"notewriter/notewriter.go:38","msg":"⚠️ user is banned (export_control_compliance): Export control compliance\n","cluster_id":"","pipeline_name":""}
    ```

    i. If the user is banned due to export control compliance, the investigation is stopped and the incident is escalated
    ii. If the user is banned due for any other reason the incident is escalated, but a service log will be sent once the informing phase tests are over

3. **Validate the pull secret validity**:

    > [!NOTE]
    >Until [ACM !5183](https://gitlab.cee.redhat.com/service/uhc-account-manager/-/merge_requests/5183) is rolled out this fails due to a lack of permissions for CAD's service account.

5. **Post to PagerDuty and escalate for further investigation by SRE** - Verify a note was added to the incident with:

   ```
   🤖 CAD created a cluster report, access it with the following command:
    osdctl cluster reports get --cluster-id <cluster_id> --report-id <report_id>
   ```

# Testing aiassisted Investigation

This document describes how to test the AI-assisted investigation end-to-end in a local environment.

## Overview

The AI-assisted investigation:
1. Serves as a **fallback handler** for alerts without explicit investigation implementations
2. Validates the cluster/organization against the investigation filter config
3. Invokes an AWS Bedrock AgentCore agent runtime with incident details
4. Streams the AI response and logs the investigation results
5. Posts a note to PagerDuty indicating AI automation completed

## Prerequisites

### 1. AWS Bedrock AgentCore Agent

You need a deployed AWS Bedrock AgentCore agent with:
- **Runtime ARN**: The ARN of your agent runtime
- **AWS Region**: The region where the agent is deployed (e.g., `us-east-1`)
- **IAM Permissions**: AWS credentials with permissions to invoke the agent runtime

### 2. Investigation Config File

Create a YAML config file with the AI agent runtime settings and filter rules:

```yaml
# test-config.yaml
ai_agent:
  runtime_arn: "arn:aws:bedrock-agentcore:us-east-1:135808927096:runtime/alert_investigation_agent_v0-c7B2Y68BMr"
  user_id: "cad-test-user"
  region: "us-east-1"
  timeout_seconds: 900
  version: "dev"
  ops_sop_version: "dev"
  rosa_plugins_version: "dev"

filters:
  - investigation: aiassisted
    any:
      - input: ClusterID
        operator: in
        values: ["<test-cluster-id>"]
      - input: OrganizationID
        operator: in
        values: ["<test-org-id>"]
```

Then set the path:

```bash
export CAD_INVESTIGATION_CONFIG_PATH="./test-config.yaml"
```

See `docs/investigation-filter-config.example.yaml` for the full reference.

### 3. AWS Credentials

Set the AWS credentials as environment variables:

```bash
export AGENTCORE_AWS_ACCESS_KEY_ID="YOUR_ACCESS_KEY_ID"
export AGENTCORE_AWS_SECRET_ACCESS_KEY="YOUR_SECRET_ACCESS_KEY"
```

These credentials are used to invoke the AWS Bedrock AgentCore runtime.

### 4. Environment Setup

Source the stage environment to configure OCM and PagerDuty access:

```bash
source test/set_stage_env.sh
```

### 5. Build the Binary

```bash
make build
```

## Manual Testing

### Step 1: Identify a Test Cluster

Choose a cluster that is included in your AI agent allowlist:

```bash
# List available clusters
ocm login --use-auth-code --url "staging"
ocm list cluster -p search="state is 'ready'" --managed

# Get cluster ID and organization ID
CLUSTER_ID="<your-cluster-id>"

# Verify organization ID
ocm get /api/clusters_mgmt/v1/clusters/$CLUSTER_ID | jq -r '.organization.id'
```

Ensure the cluster ID or organization ID is in your config file's `aiassisted` filter entry.

### Step 2: Generate Test Incident Payload

Create a PagerDuty incident payload for an **alert without an explicit CAD handler**:

```bash
# Use console-errorbudgetburn which has no formal investigation handler
./test/generate_incident.sh console-errorbudgetburn $CLUSTER_ID
```

**Important:** The AI investigation only runs for alerts that don't match any explicit investigation handler in CAD. The `console-errorbudgetburn` alert is perfect for testing as it exists but has no formal investigation implementation.

This creates a `payload` file in the current directory and a PagerDuty incident which can be checked for CAD output.

### Step 3: Set Up Configuration and Credentials

```bash
# Set AWS credentials for AgentCore
export AGENTCORE_AWS_ACCESS_KEY_ID="YOUR_ACCESS_KEY_ID"
export AGENTCORE_AWS_SECRET_ACCESS_KEY="YOUR_SECRET_ACCESS_KEY"

# Point to your config file (see step 2 in Prerequisites)
export CAD_INVESTIGATION_CONFIG_PATH="./test-config.yaml"

# Enable experimental investigations
export CAD_EXPERIMENTAL_ENABLED=true
```

### Step 4: Run the Investigation

```bash
./bin/cadctl investigate --payload-path ./payload --log-level debug
```

### Step 5: Verify Results

The investigation should proceed through the following stages:

#### 1. AI Agent Invocation

Look for:
```
🤖 Invoking AI agent for incident <incident-id>
Payload: {"prompt":"{\"investigation_id\":\"...\",\"investigation_payload\":\"\",\"alert_name\":\"...\",\"cluster_id\":\"...\"}"}
```

#### 2. Streaming Response

Check for:
```
🤖 Receiving AI response...
🤖 AI investigation complete
```

#### 3. AI Output

The logs should include the full AI response:
```
AI Output:
🤖 AI Investigation Results 🤖
Session ID: cad-<incident-id>-<timestamp>-<random>
Runtime: arn:aws:bedrock-agentcore:us-east-1:135808927096:runtime/alert_investigation_agent_v0-c7B2Y68BMr
Agent Version: dev
ops-sop Version: dev
rosa-plugins Version: dev

<AI agent response content>
```

#### 4. PagerDuty Note

Verify a note was added to the PagerDuty incident:
```
🤖 AI automation completed. Check cluster report for investigation details.
```

The incident should be **escalated** with the reason:
```
AI investigation completed - manual review required
```

## Expected Behavior

### Success Path

1. ✅ Configuration parsed successfully
2. ✅ Cluster/organization passes allowlist check
3. ✅ AWS credentials loaded from environment variables
4. ✅ AgentCore runtime invoked successfully
5. ✅ AI response streamed and logged
6. ✅ Note posted to PagerDuty
7. ✅ Incident escalated for human review

### Failure Paths

The investigation will **escalate** with a warning note if:
- AI agent runtime config (`ai_agent` section) is missing
- Cluster/organization filtered out by config
- AWS credentials missing or invalid
- AgentCore runtime invocation fails
- Response stream reading fails

## Investigation Payload Structure

The AI agent receives the following payload:

```json
{
  "prompt": "{
    \"investigation_id\": \"<pagerduty-incident-id>\",
    \"investigation_payload\": \"\",
    \"alert_name\": \"<full-pagerduty-incident-title>\",
    \"cluster_id\": \"<cluster-id>\"
  }"
}
```

**Current Limitations:**
- `investigation_payload` is currently empty (future: populate with alert details, severities, runbook links)
- `alert_name` contains the full PagerDuty incident title rather than a parsed alert name

## Session Tracking

Each AI investigation generates a unique session ID for tracking:

**Format**: `cad-<incident-id>-<timestamp>-<random-hex>`

**Example**: `cad-Q3ABC123DEF-1738000000-a1b2c3d4e5f6g7h8`

This session ID can be used to:
- Track the investigation in AWS CloudWatch logs
- Correlate AI responses with PagerDuty incidents
- Debug issues with specific invocations

## Cleanup

The investigation automatically cleans up resources:
- Context is cancelled via `defer cancel()`
- AgentCore response stream is closed via `defer output.Response.Close()`

No manual cleanup is required.

## Notes

- AI investigation is currently **experimental** (`IsExperimental() = true`)
- Only runs for alerts **without explicit investigation handlers** (fallback behavior)
- Requires filter config with `aiassisted` entry (cluster ID or organization ID)
- Timeout defaults to **15 minutes** (900 seconds), configurable via `timeout_seconds`
- Always escalates incidents for human review after AI investigation completes
- Session IDs are unique per invocation for audit trail tracking

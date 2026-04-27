# aiassisted Investigation

AI-powered investigation using AWS Bedrock AgentCore for alerts without formal investigation handlers.

## Overview

The aiassisted investigation serves as a **fallback handler** for alerts that don't have explicit investigation implementations in CAD. When CAD receives an alert without a matching investigation handler, it can invoke an AWS Bedrock AgentCore agent to investigate the issue and provide remediation guidance.

**Trigger**: Any alert without an explicit CAD investigation handler (fallback)
**Clusters**: Allowlist-controlled via investigation filter config (configured clusters and organizations only)
**Status**: Experimental (`IsExperimental() = true`)

## How It Works

The investigation performs the following steps:

1. **Validate configuration** - Checks that the AI runtime config (`ai_agent` section) is present in the global config
2. **Load credentials** - Retrieves AWS credentials from environment variables
3. **Fetch incident details** - Gets PagerDuty incident ID, title, and cluster information
4. **Invoke AI agent** - Calls AWS Bedrock AgentCore runtime with investigation payload
5. **Stream response** - Collects real-time streaming AI output
6. **Post to PagerDuty** - Adds automation note indicating AI investigation completed
7. **Escalate** - Always escalates to SRE for manual review

On any failure (config missing, credential issues, etc.), the investigation escalates with a warning note explaining the issue.

## Architecture

### File Structure

```
pkg/investigations/aiassisted/
├── aiassisted.go           # Main investigation logic
├── metadata.yaml           # RBAC permissions (none required)
├── README.md               # This file
└── testing/
    └── README.md           # Testing documentation

pkg/config/
├── config.go               # Global config including AIAgentConfig
└── filter.go               # Investigation filter evaluation
```

### Key Components

#### aiassisted.go

Main investigation implementation:
- **Investigation** - Struct with `AIConfig *config.AIAgentConfig`, populated by the controller
- **InvestigationPayload** - Struct representing data sent to AI agent (investigation ID, alert name, cluster ID)
- **generateSessionID()** - Creates unique session ID for tracking each investigation in CloudWatch
- **Run()** - Main investigation logic implementing the `investigation.Investigation` interface

The investigation uses the ResourceBuilder pattern to construct notes via `rb.WithNotes().Build()` and marshals the payload directly to JSON for AgentCore.

### Configuration

The AI investigation requires two types of configuration:

#### 1. Global Config (`CAD_INVESTIGATION_CONFIG_PATH`)

The AI runtime config and filter rules are in the YAML config file. See `docs/investigation-filter-config.example.yaml` for the full example.

```yaml
ai_agent:
  runtime_arn: "arn:aws:bedrock-agentcore:us-east-1:123456789012:runtime/agent_name-abc123"
  user_id: "cad-service-account"
  region: "us-east-1"
  timeout_seconds: 900
  version: "v1.0.0"
  ops_sop_version: "v2.3.4"
  rosa_plugins_version: "v1.2.3"

filters:
  - investigation: aiassisted
    filter:
      or:
        - field: ClusterID
          operator: in
          values: ["cluster-id-1", "cluster-id-2"]
        - field: OrganizationID
          operator: in
          values: ["org-id-1", "org-id-2"]
```

**Required `ai_agent` fields:**
- `runtime_arn` - AWS ARN of the AgentCore runtime to invoke
- `user_id` - User identifier for audit trail
- `region` - AWS region (e.g., `us-east-1`)

**Optional `ai_agent` fields:**
- `timeout_seconds` - API call timeout (default: 900 / 15 minutes)
- `version`, `ops_sop_version`, `rosa_plugins_version` - Version metadata for audit

**Filter entry:** The `aiassisted` entry in `filters` controls which clusters/organizations can use AI. Removing the entry disables AI entirely.

#### 2. AWS Credentials

Environment variables for invoking AgentCore:

```bash
export AGENTCORE_AWS_ACCESS_KEY_ID="..."
export AGENTCORE_AWS_SECRET_ACCESS_KEY="..."
```

These credentials are **separate from customer AWS credentials** and are used exclusively to invoke the Red Hat-hosted AgentCore agent.

### Allowlist-Based Access Control

Access control is handled by the investigation filter config at two levels:

1. **Interceptor Level** (`interceptor/pkg/interceptor/pdinterceptor.go`)
   - Evaluates the `aiassisted` filter before launching pipeline
   - Prevents unnecessary pipeline runs for non-allowed clusters

2. **Controller Level** (`pkg/controller/controller.go`)
   - Evaluates the filter again with full OCM context during execution
   - Escalates with a note if filtered out

A cluster or organization must match the filter conditions for AI investigation to proceed.

### Context and Timeouts

The investigation uses a single context with configurable timeout:

| Operation | Timeout | Reason |
|-----------|---------|--------|
| AgentCore runtime invocation | 900 seconds (15 min) | Default, configurable via `timeout_seconds` |

The timeout applies to the entire AI agent invocation including streaming response collection. The context is properly cancelled via `defer cancel()` and the response stream is closed via `defer output.Response.Close()`.

### AI Agent Payload

The agent receives a JSON payload wrapped in a `prompt` field:

```json
{
  "prompt": "{
    \"investigation_id\": \"<pagerduty-incident-id>\",
    \"investigation_payload\": \"\",
    \"alert_name\": \"<pagerduty-incident-title>\",
    \"cluster_id\": \"<cluster-id>\"
  }"
}
```

**Current Limitations:**
- `investigation_payload` is currently empty (future: populate with alert details from PagerDuty)
- `alert_name` contains the full PagerDuty incident title rather than a parsed alert name

### Session Tracking

Each AI investigation generates a unique session ID for tracking:

**Format**: `cad-<incident-id>-<timestamp>-<random-hex>`
**Example**: `cad-Q3ABC123DEF-1738000000-a1b2c3d4e5f6g7h8`

Session IDs are used for:
- Tracking investigations in AWS CloudWatch logs
- Correlating AI responses with PagerDuty incidents
- Debugging specific invocations
- Audit trail for security/compliance

## Output

### PagerDuty Note

On success, the investigation adds an automation note:

```
AI automation completed. Check cluster report for investigation details.
```

The full AI response is logged (not posted to PagerDuty) and includes:
- Session ID
- Runtime ARN
- Agent version metadata (if configured)
- Streaming AI output

### Escalation

The investigation **always escalates** with the reason:
```
AI investigation completed - manual review required
```

This ensures human SREs review the AI's findings before taking action. The investigation **never auto-resolves** incidents.

## Integration Testing

For testing instructions, see [testing/README.md](./testing/README.md).

Testing requires:
- AWS Bedrock AgentCore agent deployed
- AWS credentials with `bedrock-agent-runtime:InvokeAgent` permissions
- Filter config with test cluster or organization in the aiassisted allowlist
- Stage environment access (OCM, PagerDuty)

## Security Considerations

1. **Credential Isolation** - Uses dedicated Red Hat AWS credentials, never customer credentials
2. **Filter-Based Access Control** - Only explicitly configured clusters/organizations can use AI
3. **Fail-Closed Design** - Config errors block pipeline, preventing unintended AI usage; absent config disables AI
4. **Audit Trail** - Session IDs and version metadata tracked for every invocation
5. **No Auto-Remediation** - Always escalates for human review, never takes automated action

## Future Enhancements

Potential improvements when graduating from experimental:

- **Enhanced Payload** - Populate `investigation_payload` with comprehensive alert details from PagerDuty (descriptions, severities, runbook links)
- **Field Naming** - Rename `alert_name` to `incident_title` for clarity
- **Unit Tests** - Add comprehensive unit tests for the investigation
- **Metrics** - Track AI investigation runs, success rates, failures, and response times
- **Response Quality Metrics** - Measure AI response quality and usefulness

## Related Documentation

- [Testing Guide](./testing/README.md)
- [Investigation Filter Config Example](../../../docs/investigation-filter-config.example.yaml)

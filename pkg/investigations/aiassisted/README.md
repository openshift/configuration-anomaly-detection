# aiassisted Investigation

AI-powered investigation using AWS Bedrock AgentCore for alerts without formal investigation handlers.

## Overview

The aiassisted investigation serves as a **fallback handler** for alerts that don't have explicit investigation implementations in CAD. When CAD receives an alert without a matching investigation handler, it can invoke an AWS Bedrock AgentCore agent to investigate the issue and provide remediation guidance.

**Trigger**: Any alert without an explicit CAD investigation handler (fallback)
**Clusters**: Allowlist-controlled (configured clusters and organizations only)
**Status**: Experimental (`IsExperimental() = true`)

## How It Works

The investigation performs the following steps:

1. **Validate configuration** - Parses `CAD_AI_AGENT_CONFIG` and checks if AI is enabled
2. **Check allowlist** - Fetches organization ID from OCM and validates cluster/org is allowlisted
3. **Load credentials** - Retrieves AWS credentials from environment variables
4. **Fetch incident details** - Gets PagerDuty incident ID, title, and cluster information
5. **Invoke AI agent** - Calls AWS Bedrock AgentCore runtime with investigation payload
6. **Stream response** - Collects real-time streaming AI output
7. **Post to PagerDuty** - Adds automation note indicating AI investigation completed
8. **Escalate** - Always escalates to SRE for manual review

On any failure (config parse error, allowlist check failure, credential issues, etc.), the investigation escalates with a warning note explaining the issue.

## Architecture

### File Structure

```
pkg/investigations/aiassisted/
├── aiassisted.go           # Main investigation logic
├── metadata.yaml           # RBAC permissions (none required)
├── README.md               # This file
└── testing/
    └── README.md           # Testing documentation

pkg/aiconfig/
├── config.go               # AI configuration parsing and validation
└── config_test.go          # Unit tests for configuration
```

### Key Components

#### aiassisted.go

Main investigation implementation:
- **InvestigationPayload** - Struct representing data sent to AI agent (investigation ID, alert name, cluster ID)
- **generateSessionID()** - Creates unique session ID for tracking each investigation in CloudWatch
- **Run()** - Main investigation logic implementing the `investigation.Investigation` interface
- **ToAgentCorePayload()** - Wraps investigation data in the "prompt" field expected by AgentCore

The investigation uses the ResourceBuilder pattern to construct notes via `rb.WithNotes().Build()`.

#### pkg/aiconfig/config.go

AI configuration parsing and management:
- **AIAgentConfig** - Struct holding all AI agent configuration (runtime ARN, region, allowlists, timeout, etc.)
- **ParseAIAgentConfig()** - Parses `CAD_AI_AGENT_CONFIG` environment variable, returns disabled config if not set
- **GetTimeout()** - Converts `TimeoutSeconds` to `time.Duration` for use with `context.WithTimeout()`
- **IsAllowedForAI()** - Validates if a cluster ID or organization ID is in the allowlists

The config package provides centralized configuration management used by both the interceptor and investigation.

### Configuration

The AI investigation requires two types of configuration:

#### 1. AI Agent Configuration (`CAD_AI_AGENT_CONFIG`)

JSON environment variable controlling AI behavior:

```json
{
  "runtime_arn": "arn:aws:bedrock-agentcore:us-east-1:123456789012:runtime/agent_name-abc123",
  "user_id": "cad-service-account",
  "region": "us-east-1",
  "organizations": ["org-id-1", "org-id-2"],
  "clusters": ["cluster-id-1", "cluster-id-2"],
  "enabled": true,
  "timeout_seconds": 900,
  "version": "v1.0.0",
  "ops_sop_version": "v2.3.4",
  "rosa_plugins_version": "v1.2.3"
}
```

**Required fields:**
- `runtime_arn` - AWS ARN of the AgentCore runtime to invoke
- `user_id` - User identifier for audit trail
- `region` - AWS region (e.g., `us-east-1`)
- `enabled` - Global on/off switch
- `organizations` - Allowlist of organization IDs
- `clusters` - Allowlist of cluster IDs

**Optional fields:**
- `timeout_seconds` - API call timeout (default: 900 / 15 minutes)
- `version`, `ops_sop_version`, `rosa_plugins_version` - Version metadata for audit

**Note:** At least one cluster ID or organization ID must be specified in the allowlists.

#### 2. AWS Credentials

Environment variables for invoking AgentCore:

```bash
export AGENTCORE_AWS_ACCESS_KEY_ID="..."
export AGENTCORE_AWS_SECRET_ACCESS_KEY="..."
```

These credentials are **separate from customer AWS credentials** and are used exclusively to invoke the Red Hat-hosted AgentCore agent.

### Allowlist-Based Access Control

The investigation implements two-level allowlist enforcement:

1. **Interceptor Level** (`interceptor/pkg/interceptor/pdinterceptor.go`)
   - Checks allowlist before launching pipeline
   - Prevents unnecessary pipeline runs for non-allowed clusters

2. **Investigation Level** (`pkg/investigations/aiassisted/aiassisted.go`)
   - Validates cluster/org against allowlist during execution
   - Escalates with warning if not allowed

A cluster or organization must be in one of the allowlists for AI investigation to proceed.

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
- Allowlisted test cluster or organization
- Stage environment access (OCM, PagerDuty)

## Security Considerations

1. **Credential Isolation** - Uses dedicated Red Hat AWS credentials, never customer credentials
2. **Allowlist Enforcement** - Only explicitly configured clusters/organizations can use AI
3. **Fail-Closed Design** - Config errors block pipeline, preventing unintended AI usage
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
- [AI Agent Configuration](../../../docs/AI_AGENT_CONFIG.md)
- [AgentCore Integration Plan](../../../docs/AGENTCORE_CAD_IMPLEMENTATION_PLAN_FINAL.md)

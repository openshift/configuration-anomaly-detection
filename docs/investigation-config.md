# Investigation Configuration

CAD is configured via a YAML-based configuration file that controls which investigations run and optionally configures the AI agent. This allows you to restrict investigations to specific alerts, clusters, cloud providers, organizations, or other attributes — without code changes.

## Enabling the config

Set the `CAD_INVESTIGATION_CONFIG_PATH` environment variable to the path of your config file:

```sh
export CAD_INVESTIGATION_CONFIG_PATH=/path/to/config.yaml
```

If the variable is not set, the program exits.

## How filtering works

Each alert configuration can have an optional **filter tree** — a boolean expression evaluated against the current alert and cluster context. If the filter passes, the alert is investigated by CAD by running its configured set of investigations; Each investigation can, in turn, have its own filter tree.

Investigations that have **no `when` entry** in the config always run for a given alert.

The `aiassisted` investigation can run in two ways: explicitly listed in an alert's investigation chain, or as an automatic fallback when no alert title matches (or when the alert-level filter rejects). The fallback path triggers whenever the `ai_agent` section is configured, even without an explicit `aiassisted` entry in `alerts`.

## Filter tree structure

A filter is a recursive tree of nodes. Each node is either:

- A **branch** node (`and` / `or`) containing child nodes
- A **leaf** node that compares a field from the current context against a list of values

**Branch nodes**

```yaml
and:           # All children must pass
  - ...
  - ...

or:            # At least one child must pass
  - ...
  - ...
```

Branches can be nested arbitrarily to compose complex logic.

**Leaf nodes**

```yaml
field: ClusterID       # The context field to check
operator: in           # How to compare
values: ["abc123"]     # List of values to compare against
```

**Sampling leaf** (no field required)

```yaml
operator: sample
values: ["0.10"]       # Probability between 0.0 and 1.0
```

## Available operators

| Operator | Description |
|----------|-------------|
| `in` | Field value must be one of the listed values |
| `notin` | Field value must NOT be any of the listed values |
| `matches` | Field value must match at least one regex pattern |
| `notmatches` | Field value must NOT match any of the regex patterns |
| `sample` | Passes probabilistically at the given rate (0.0–1.0) |

## Available context fields

| Field | Source | Description |
|-------|--------|-------------|
| `ClusterID` | OCM | Internal cluster identifier |
| `ClusterName` | OCM | Human-readable cluster name |
| `OrganizationID` | OCM | Organization that owns the cluster |
| `OwnerID` | OCM | Account ID of the subscription creator |
| `OwnerEmail` | OCM | Email of the subscription creator |
| `CloudProvider` | OCM | Cloud provider (`"aws"`, `"gcp"`, etc.) |
| `HCP` | OCM | Hosted Control Plane (`"true"` or `"false"`) |
| `ClusterState` | OCM | Current state (`"ready"`, `"uninstalling"`, etc.) |
| `AlertName` | PagerDuty | Alert name as matched by the investigation |
| `AlertTitle` | PagerDuty | Full PagerDuty incident title |
| `ServiceName` | PagerDuty | PagerDuty service name |

Note: Not all fields are guaranteed to be populated in every context. PagerDuty fields are empty when running via the manual CLI. An empty field will not match any `in` value and will pass any `notin` check.

## Quick examples

Only run an investigation on AWS clusters in `ready` state:

```yaml
alerts:
  - alert_title: "MustGather"
    when:
      and:
        - field: CloudProvider
          operator: in
          values: ["aws"]
        - field: ClusterState
          operator: in
          values: ["ready"]
    investigations:
      - precheck
      - mustgather
```

Exclude a specific cluster:

```yaml
alerts:
  - alert_title: "has gone missing"
    when:
      field: ClusterID
      operator: notin
      values: ["2pr3e91qrgdje312keq8denphqs70tlr"]
    investigations:
      - precheck
      - ccam
      - chgm
```

Sample 10% of internal (`@redhat.com`) traffic for a specific investigation step, always run for external customers:

```yaml
alerts:
  - alert_title: "ClusterMonitoringErrorBudgetBurnSRE"
    investigations:
      - precheck
      - ccam
      - name: clustermonitoringerrorbudgetburn
        when:
          or:
            - field: OwnerEmail
              operator: notmatches
              values: [".*@redhat\\.com$"]
            - operator: sample
              values: ["0.10"]
```

## AI agent configuration

When using the `aiassisted` investigation, the `ai_agent` section must be present and all required fields must be set:

```yaml
ai_agent:
  runtime_arn: "arn:aws:bedrock-agentcore:us-east-1:123456789012:runtime/agent-abc123"
  user_id: "cad-service-account"
  region: "us-east-1"
  invoker_role_arn: "arn:aws:iam::123456789012:role/agent-invoker"
  timeout_seconds: 900              # optional, defaults to 900
  version: "v1.0.0"                 # optional, audit trail only
  ops_sop_version: "v2.0.0"         # optional, audit trail only
  rosa_plugins_version: "v3.0.0"    # optional, audit trail only
```

When the `ai_agent` section is configured, `aiassisted` also acts as a fallback: if no alert title matches the incoming incident (or the matched alert's `when` filter rejects), CAD automatically runs `precheck` followed by `aiassisted`. This fallback does not require an explicit `aiassisted` entry in `alerts`.

## Full reference

See [`docs/investigation-config.example.yaml`](investigation-config.example.yaml) for a fully commented example covering all operators, field types, and composition patterns.

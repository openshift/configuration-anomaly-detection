# Investigation Filter Configuration

CAD supports a YAML-based configuration file that controls which investigations run and optionally configures the AI agent. This allows you to restrict investigations to specific clusters, cloud providers, organizations, or other attributes — without code changes.

## Enabling the config

Set the `CAD_INVESTIGATION_CONFIG_PATH` environment variable to the path of your config file:

```sh
export CAD_INVESTIGATION_CONFIG_PATH=/path/to/config.yaml
```

If the variable is not set, no filtering is applied and all investigations run unconditionally.

## How filtering works

Each investigation can have an optional **filter tree** — a boolean expression evaluated against the current alert and cluster context. If the filter passes, the investigation runs; if it fails, it is skipped.

Investigations that have **no entry** in the config always run. An investigation entry with no `filter` key also always runs.

The one exception is `aiassisted`: it only runs if it has an entry in the config. Without an entry, the AI investigation is entirely disabled.

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
filters:
  - investigation: mustgather
    filter:
      and:
        - field: CloudProvider
          operator: in
          values: ["aws"]
        - field: ClusterState
          operator: in
          values: ["ready"]
```

Exclude a specific cluster:

```yaml
filters:
  - investigation: "Cluster Has Gone Missing (CHGM)"
    filter:
      field: ClusterID
      operator: notin
      values: ["2pr3e91qrgdje312keq8denphqs70tlr"]
```

Sample 10% of internal (`@redhat.com`) traffic, always run for external customers:

```yaml
filters:
  - investigation: clustermonitoringerrorbudgetburn
    filter:
      or:
        - field: OwnerEmail
          operator: notmatches
          values: [".*@redhat\\.com$"]
        - operator: sample
          values: ["0.10"]
```

## AI agent configuration

When using the `aiassisted` investigation, the `ai_agent` section must be present:

```yaml
ai_agent:
  runtime_arn: "arn:aws:bedrock:us-east-1:123456789012:agent-runtime/EXAMPLE"
  user_id: "cad-agent"
  region: "us-east-1"
  timeout_seconds: 900   # optional, defaults to 900
```

The `aiassisted` investigation must also have an entry in `filters`. Without it, AI investigation is disabled even if `ai_agent` is configured.

## Full reference

See [`docs/investigation-filter-config.example.yaml`](investigation-filter-config.example.yaml) for a fully commented example covering all operators, field types, and composition patterns.

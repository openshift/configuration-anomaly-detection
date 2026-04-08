# Dynatrace GRAIL Query Client

This package provides a Go client for querying Dynatrace GRAIL data using DQL (Dynatrace Query Language).

## Overview

The Dynatrace client enables CAD investigations to programmatically fetch logs and other observability data from Dynatrace. This is particularly useful for HCP clusters where debug endpoints are disabled in management cluster namespaces, preventing direct log retrieval via `oc logs`.

## Authentication

Dynatrace uses OAuth 2.0 for authentication. You need either:

1. **OAuth Client Credentials** (recommended for production)
   - Client ID
   - Client Secret
   - These are exchanged for a short-lived access token

2. **Pre-obtained Access Token** (useful for testing)
   - Bearer token obtained separately
   - Must have `storage:logs:read` and `storage:buckets:read` scopes

### Creating OAuth Clients in Dynatrace

1. Go to Dynatrace Account Management
2. Navigate to **Identity & access management** → **OAuth clients**
3. Create a new OAuth client with the following scopes:
   - `storage:logs:read`
   - `storage:buckets:read`
4. Save the Client ID and Client Secret

## Environment Variables

### For Production/Deployment

Set these environment variables in your CAD deployment:

```bash
# Required: Your Dynatrace environment ID
CAD_DYNATRACE_ENVIRONMENT_ID="abc12345"

# Option 1: OAuth credentials (recommended)
CAD_DYNATRACE_CLIENT_ID="your-client-id"
CAD_DYNATRACE_CLIENT_SECRET="your-client-secret"

# Option 2: Pre-obtained access token (for testing)
CAD_DYNATRACE_ACCESS_TOKEN="your-bearer-token"
```

### For Local Testing

1. Export environment variables from your local environment or test script:

```bash
# Using OAuth credentials
export CAD_DYNATRACE_ENVIRONMENT_ID="abc12345"
export CAD_DYNATRACE_CLIENT_ID="your-client-id"
export CAD_DYNATRACE_CLIENT_SECRET="your-client-secret"
```

2. Or add to `test/set_stage_env.sh` alongside other CAD credentials:

```bash
# Dynatrace Configuration
export CAD_DYNATRACE_ENVIRONMENT_ID="$(vault kv get -field=environment_id secret/path/to/dynatrace)"
export CAD_DYNATRACE_CLIENT_ID="$(vault kv get -field=client_id secret/path/to/dynatrace)"
export CAD_DYNATRACE_CLIENT_SECRET="$(vault kv get -field=client_secret secret/path/to/dynatrace)"
```

## Usage Example

### Basic Query Execution

```go
package main

import (
    "context"
    "fmt"
    "os"

    "github.com/openshift/configuration-anomaly-detection/pkg/dynatrace"
)

func main() {
    // Create client from environment variables
    config := dynatrace.Config{
        EnvironmentID: os.Getenv("CAD_DYNATRACE_ENVIRONMENT_ID"),
        ClientID:      os.Getenv("CAD_DYNATRACE_CLIENT_ID"),
        ClientSecret:  os.Getenv("CAD_DYNATRACE_CLIENT_SECRET"),
    }

    client, err := dynatrace.New(config)
    if err != nil {
        panic(err)
    }

    // Execute a DQL query
    query := `fetch logs
        | filter k8s.pod.name == "my-pod"
        | filter k8s.namespace.name == "my-namespace"
        | sort timestamp desc
        | limit 100`

    result, err := client.ExecuteQuery(context.Background(), query)
    if err != nil {
        panic(err)
    }

    fmt.Printf("Retrieved %d log records\n", len(result.Records))
}
```

### Fetching Pod Logs (Convenience Method)

```go
package main

import (
    "context"
    "fmt"
    "os"
    "time"

    "github.com/openshift/configuration-anomaly-detection/pkg/dynatrace"
)

func main() {
    config := dynatrace.Config{
        EnvironmentID: os.Getenv("CAD_DYNATRACE_ENVIRONMENT_ID"),
        ClientID:      os.Getenv("CAD_DYNATRACE_CLIENT_ID"),
        ClientSecret:  os.Getenv("CAD_DYNATRACE_CLIENT_SECRET"),
    }

    client, err := dynatrace.New(config)
    if err != nil {
        panic(err)
    }

    // Get logs for a specific pod from the last hour
    logs, err := client.GetPodLogs(
        context.Background(),
        "etcd-snapshot-analyzer-abc123",  // pod name
        "uhc-production-abc123-api",      // HCP namespace
        "management-cluster-name",         // management cluster name
        1*time.Hour,                       // lookback duration
    )

    if err != nil {
        panic(err)
    }

    for _, log := range logs {
        fmt.Printf("[%s] %s\n", log.Timestamp, log.Content)
    }
}
```

### Integration with CAD Investigations

```go
package myinvestigation

import (
    "context"
    "fmt"
    "os"
    "time"

    "github.com/openshift/configuration-anomaly-detection/pkg/dynatrace"
    "github.com/openshift/configuration-anomaly-detection/pkg/investigations/investigation"
)

func (i *MyInvestigation) Run(builder investigation.ResourceBuilder) (investigation.InvestigationResult, error) {
    resources, err := builder.
        WithCluster().
        WithManagementRestConfig().
        Build()
    if err != nil {
        return investigation.InvestigationResult{}, err
    }

    // Create Dynatrace client
    dtClient, err := dynatrace.New(dynatrace.Config{
        EnvironmentID: os.Getenv("CAD_DYNATRACE_ENVIRONMENT_ID"),
        ClientID:      os.Getenv("CAD_DYNATRACE_CLIENT_ID"),
        ClientSecret:  os.Getenv("CAD_DYNATRACE_CLIENT_SECRET"),
    })
    if err != nil {
        return investigation.InvestigationResult{}, fmt.Errorf("failed to create Dynatrace client: %w", err)
    }

    // Get the management cluster name (you'll need to determine this from resources)
    mcName := "your-management-cluster-name" // TODO: derive from resources

    // Fetch logs from the snapshot analyzer pod
    podName := "etcd-snapshot-analyzer"
    logs, err := dtClient.GetPodLogs(
        context.Background(),
        podName,
        resources.HCPNamespace,
        mcName,
        1*time.Hour,
    )

    if err != nil {
        return investigation.InvestigationResult{}, fmt.Errorf("failed to fetch pod logs: %w", err)
    }

    // Process the logs...
    for _, log := range logs {
        // Analyze log content
        fmt.Printf("Log: %s\n", log.Content)
    }

    return investigation.InvestigationResult{}, nil
}
```

## Secret Management

### Development/Staging

For development and staging environments, credentials should be stored in Vault and retrieved via `test/set_stage_env.sh`:

```bash
# In vault, store at: secret/sre-platform/configuration-anomaly-detection/stage/dynatrace
vault kv put secret/sre-platform/configuration-anomaly-detection/stage/dynatrace \
    environment_id="abc12345" \
    client_id="dt0s02..." \
    client_secret="dt0s02..."
```

### Production

For production deployments, credentials should be:

1. Stored as Kubernetes Secrets in the cluster
2. Mounted as environment variables in the CAD pod
3. Referenced in the Tekton pipeline/pod template

Example Kubernetes Secret:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: dynatrace-credentials
  namespace: configuration-anomaly-detection
type: Opaque
stringData:
  environment-id: "abc12345"
  client-id: "dt0s02..."
  client-secret: "dt0s02..."
```

Example Pod environment variables:

```yaml
env:
  - name: CAD_DYNATRACE_ENVIRONMENT_ID
    valueFrom:
      secretKeyRef:
        name: dynatrace-credentials
        key: environment-id
  - name: CAD_DYNATRACE_CLIENT_ID
    valueFrom:
      secretKeyRef:
        name: dynatrace-credentials
        key: client-id
  - name: CAD_DYNATRACE_CLIENT_SECRET
    valueFrom:
      secretKeyRef:
        name: dynatrace-credentials
        key: client-secret
```

## DQL Query Examples

### Fetch logs for a specific pod

```dql
fetch logs
| filter k8s.pod.name == "snapshot-analyzer-xyz"
| filter k8s.namespace.name == "uhc-production-abc123-api"
| filter k8s.cluster.name == "management-cluster-us-east-1"
| sort timestamp desc
| limit 100
```

### Filter by log content

```dql
fetch logs
| filter k8s.pod.name == "snapshot-analyzer-xyz"
| filter matchesPhrase(content, "ETCD analysis complete")
| sort timestamp asc
```

### Get logs from the last hour

```dql
fetch logs
| filter k8s.pod.name == "snapshot-analyzer-xyz"
| filter timestamp > now() - 1h
| sort timestamp asc
```

### Filter by container within a pod

```dql
fetch logs
| filter k8s.pod.name == "snapshot-analyzer-xyz"
| filter k8s.container.name == "analyzer"
| sort timestamp asc
```

## API Reference

### Client Interface

```go
type Client interface {
    // ExecuteQuery executes a DQL query and returns the results
    ExecuteQuery(ctx context.Context, query string) (*QueryResult, error)

    // GetPodLogs retrieves logs for a specific pod in a namespace
    GetPodLogs(ctx context.Context, podName, namespace, mcName string, since time.Duration) ([]LogRecord, error)
}
```

### Configuration

```go
type Config struct {
    EnvironmentID string  // Required: Dynatrace environment ID
    ClientID      string  // OAuth client ID (required if AccessToken not provided)
    ClientSecret  string  // OAuth client secret (required if AccessToken not provided)
    AccessToken   string  // Pre-obtained access token (optional, alternative to ClientID/Secret)
}
```

## Testing

### Unit Tests

Run unit tests:

```bash
make test
```

### Manual Testing

1. Set up environment variables:
   ```bash
   source test/set_stage_env.sh
   ```

2. Create a test script to query Dynatrace:
   ```bash
   go run examples/dynatrace_query.go
   ```

## Troubleshooting

### Authentication Errors

- **Error: "token request failed with status 401"**
  - Check that your Client ID and Client Secret are correct
  - Verify the OAuth client has the required scopes

### Query Errors

- **Error: "query request failed with status 403"**
  - Ensure your access token has `storage:logs:read` and `storage:buckets:read` scopes
  - Check that the bearer token hasn't expired

- **Error: "query polling timed out"**
  - The query is taking too long (>60 seconds)
  - Try narrowing the time range or adding more filters
  - Increase `maxPollAttempts` if needed

### No Results Returned

- Verify the pod name, namespace, and cluster name are correct
- Check that logs are actually being sent to Dynatrace
- Ensure the time range includes when the logs were generated
- Verify field names match your Dynatrace configuration (e.g., `k8s.pod.name` vs `pod.name`)

## Field Name Reference

Dynatrace log field names may vary based on your configuration. Common field names include:

- `k8s.pod.name` - Kubernetes pod name
- `k8s.namespace.name` - Kubernetes namespace
- `k8s.cluster.name` - Kubernetes cluster name
- `k8s.container.name` - Container name within the pod
- `content` - Log message content
- `timestamp` - Log timestamp
- `severity` - Log severity level
- `dt.system.bucket` - Dynatrace bucket name

Check your Dynatrace environment's log structure to confirm the exact field names.

## Next Steps

1. **Add Dynatrace client to investigation ResourceBuilder** - Extend the investigation framework to optionally build a Dynatrace client
2. **Implement ETCD analysis investigation** - Use this client to retrieve ETCD snapshot analysis logs
3. **Add metrics** - Track Dynatrace API usage and errors
4. **Add retry logic** - Implement exponential backoff for transient failures
5. **Cache access tokens** - Store and reuse OAuth tokens until they expire

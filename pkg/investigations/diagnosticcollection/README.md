# Diagnostic Collection Investigation

A **generic, reusable investigation framework** for collecting and analyzing cluster diagnostics using `oc adm inspect`. This investigation is designed to handle multiple alert types with minimal code changes.

## Overview

This investigation provides a flexible system for:
1. Collecting cluster diagnostic data via `oc adm inspect`
2. Parsing collected YAML resources
3. Analyzing resources for common issues
4. Posting actionable findings to PagerDuty

## Architecture

```
Alert → Mapping → Inspect → Parse → Analyze → Report
```

### Components

#### 1. **Alert Mappings** (`mappings.go`)
- Maps alert types to resources to inspect
- Defines which resources to collect for each alert
- Easy to extend with new alert types

#### 2. **Inspect Executor** (`inspect/executor.go`)
- Runs `oc adm inspect` commands
- Manages temporary directories for collected data
- Handles cleanup

#### 3. **Parsers** (`parsers/`)
- Parse YAML files from inspect output
- Extract structured information from Kubernetes resources
- Currently supports:
  - ClusterVersion
  - ClusterOperator
  - Easy to add more resource types

#### 4. **Analyzers** (`analyzers/`)
- Analyze parsed resources for issues
- Implement `ResourceAnalyzer` interface
- Return structured findings
- Currently supports:
  - ClusterVersion: upgrade status, stuck upgrades
  - ClusterOperator: degraded/unavailable operators

#### 5. **Findings** (`findings/`)
- Structured representation of diagnostic results
- Severity levels: Info, Warning, Critical
- Formatted output for PagerDuty notes

## Current Alert Support

### UpgradeConfigSyncFailureOver4HrSRE
- **Resources Collected**: clusterversion, clusteroperators
- **Analysis**:
  - Checks if upgrade is stuck (>4 hours)
  - Identifies degraded cluster operators
  - Provides operator-specific remediation recommendations
- **RBAC Required**: read access to config.openshift.io clusterversions and clusteroperators

## Adding New Alert Types

Adding support for a new alert is straightforward:

### Step 1: Add Mapping

In `mappings.go`, add a new entry to `diagnosticMappings`:

```go
{
    AlertPattern: "InsightsOperatorDown",
    Resources:    []string{"clusteroperator/insights", "ns/openshift-insights"},
    Description:  "Collects insights operator status and namespace resources",
},
```

### Step 2: Create Parser (if needed)

If inspecting a new resource type, create a parser in `parsers/`:

```go
// parsers/pods.go
type PodInfo struct {
    Name      string
    Namespace string
    Phase     string
    // ...
}

func ParsePods(inspectDir string) ([]PodInfo, error) {
    // Parse pod YAML files
}
```

### Step 3: Create Analyzer

Create an analyzer in `analyzers/`:

```go
// analyzers/insights.go
type InsightsAnalyzer struct{}

func (a *InsightsAnalyzer) Analyze(inspectDir string) (*findings.Findings, error) {
    f := findings.New()

    // Parse resources
    pods, err := parsers.ParsePods(inspectDir)
    if err != nil {
        return nil, err
    }

    // Analyze and add findings
    for _, pod := range pods {
        if pod.Phase != "Running" {
            f.AddWarning(
                fmt.Sprintf("Pod not running: %s", pod.Name),
                fmt.Sprintf("Phase: %s", pod.Phase),
                "Check pod logs",
            )
        }
    }

    return f, nil
}
```

### Step 4: Register Analyzer

In `diagnosticcollection.go`, update `getAnalyzersForResources()`:

```go
if strings.Contains(resourceLower, "insights") {
    analyzerList = append(analyzerList, analyzers.NewInsightsAnalyzer())
}
```

### Step 5: Update RBAC

In `metadata.yaml`, add required permissions:

```yaml
- verbs:
    - "get"
    - "list"
  apiGroups:
    - ""
  resources:
    - "pods"
```

### Step 6: Add Test Samples

Add sample YAML files to `testing/samples/`:
- `insights-pod-degraded.yaml`
- `insights-pod-healthy.yaml`

That's it! The investigation will now handle the new alert type.

## Design Benefits

✅ **Reusable**: Core logic shared across all alert types
✅ **Maintainable**: New alerts don't require core logic changes
✅ **Testable**: Each component independently testable
✅ **Extensible**: Clear pattern for adding new alert types
✅ **Gradual**: Start with one alert, add more over time

## Example Output

```
🤖 Automated diagnosticcollection pre-investigation 🤖
===========================
🤖 Collecting diagnostics: Collects upgrade status and operator health for stuck upgrades
✅ Diagnostic data collected successfully
🤖 Diagnostic Analysis Results (4 findings)
🔴 Critical Issues (2)
==================
1. Upgrade Stuck
   Upgrade from 4.14.10 to 4.14.15 has been running for 5h30m (threshold: 4h)
   💡 Check degraded cluster operators and machine config pools

2. Operator Degraded: authentication
   Reason: OAuthServerDeploymentDegraded
   Message: deployment/oauth-openshift has 0/1 replicas available
   💡 Check authentication operator: oc -n openshift-authentication get pods
       Check OAuth resources: oc get oauth cluster -o yaml

⚠️ Warnings (1)
============
1. Operator Unavailable: ingress
   Reason: IngressControllerUnavailable
   Message: router-default pod in CrashLoopBackOff
   💡 Check ingress operator: oc -n openshift-ingress-operator get pods
       Check routers: oc -n openshift-ingress get pods

ℹ️ Information (1)
===============
1. Cluster Version Information
   Current: 4.14.10
   Desired: 4.14.15
   Upgrading: true
```

## Testing

Refer to the [testing README](./testing/README.md) for detailed instructions on testing this investigation.

## Future Enhancements

- Support for more resource types (Pods, Nodes, MachineConfigs, etc.)
- Pattern-based finding correlation
- Historical data comparison
- Automatic remediation for common issues
- Upload complete diagnostics to S3 bucket for deep investigation (tar the inspect output, upload with cluster ID and timestamp, post S3 URL to PagerDuty)

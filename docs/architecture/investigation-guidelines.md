# Investigation Guidelines

## Overview

This document provides guidelines for implementing investigations in the Configuration Anomaly Detection (CAD) system. It covers the executor pattern, action-based architecture, and best practices for creating robust, maintainable investigations.

## Architecture: Separation of Investigation and Execution

### The Executor Pattern

CAD uses an **executor pattern** where investigations focus on **analyzing problems** and **returning actions**, while the executor handles **executing those actions** against external systems.

```
┌─────────────────┐
│  Investigation  │  ← Analyzes cluster state, builds investigation logic
└────────┬────────┘
         │ returns
         ▼
┌─────────────────┐
│     Actions     │  ← Describes what to do (ServiceLog, LimitedSupport, etc.)
└────────┬────────┘
         │ executes
         ▼
┌─────────────────┐
│    Executor     │  ← Handles execution, retries, metrics, error handling
└────────┬────────┘
         │ calls
         ▼
┌─────────────────┐
│ External Systems│  ← PagerDuty, OCM, Backplane
└─────────────────┘
```

### Why This Pattern?

**Benefits:**
- ✅ **Accurate Metrics**: Metrics are emitted only when actions actually succeed
- ✅ **Separation of Concerns**: Investigation logic is separate from execution details
- ✅ **Testability**: Can test investigations without mocking external clients
- ✅ **Retry Logic**: Executor provides automatic retry for transient failures
- ✅ **Consistency**: All investigations follow the same pattern
- ✅ **Observability**: Centralized logging and metrics for all actions

**Anti-Pattern (Old Way - DON'T DO THIS):**
```go
// ❌ BAD: Investigation directly calls external systems
func (i *Investigation) Run(rb investigation.ResourceBuilder) (result investigation.InvestigationResult, err error) {
    r, err := rb.Build()
    if err != nil {
        return result, err
    }

    // ❌ DON'T: Direct PagerDuty call
    err = r.PdClient.SilenceIncidentWithNote(notes.String())

    // ❌ DON'T: Direct OCM call
    err = r.OcmClient.PostServiceLog(r.Cluster, serviceLog)

    // ❌ DON'T: Manual metric tracking (might be incorrect if action fails later)
    result.ServiceLogSent = investigation.InvestigationStep{Performed: true}

    return result, err
}
```

**Correct Pattern (New Way - DO THIS):**
```go
// ✅ GOOD: Investigation returns actions
func (i *Investigation) Run(rb investigation.ResourceBuilder) (result investigation.InvestigationResult, err error) {
    r, err := rb.Build()
    if err != nil {
        return result, err
    }

    // Perform investigation logic
    if problemDetected {
        notes.AppendAutomation("Problem detected, sending service log and silencing alert")

        // ✅ DO: Return actions for the executor to handle
        result.Actions = []types.Action{
            executor.NewServiceLogAction(sl.Severity, sl.Summary).
                WithDescription(sl.Description).
                WithServiceName(sl.ServiceName).
                Build(),
            executor.NoteFrom(notes),
            executor.Silence("Reason for silencing"),
        }
        return result, nil
    }

    // No issues found
    notes.AppendSuccess("No issues detected")
    result.Actions = []types.Action{
        executor.NoteFrom(notes),
        executor.Escalate("Manual investigation required"),
    }
    return result, nil
}
```

## Available Actions

### 1. ServiceLogAction

Send a service log to the customer via OCM.

```go
// Basic usage
action := executor.NewServiceLogAction("Major", "Action required: review configuration").
    WithDescription("Your cluster configuration needs attention...").
    WithServiceName("SREManualAction").
    Build()

// Convenience function
action := executor.ServiceLog("Major", "Summary", "Description")
```

**Parameters:**
- `severity`: "Info", "Warning", "Major", "Critical"
- `summary`: Brief title of the service log
- `description`: Detailed explanation and remediation steps
- `serviceName`: Defaults to "SREManualAction"

**Options:**
- `.InternalOnly()`: Mark as internal-only (not visible to customer)
- `.AllowDuplicates()`: Send even if identical service log exists
- `.WithReason(string)`: Add reason for logging purposes

### 2. LimitedSupportAction

Set a cluster into limited support with a specific reason.

```go
// Basic usage
action := executor.NewLimitedSupportAction(summary, details).
    WithContext("EgressBlocked").
    Build()

// Convenience function
action := executor.LimitedSupport("Summary", "Detailed explanation...")
```

**Parameters:**
- `summary`: Brief reason for limited support
- `details`: Detailed explanation including remediation steps

**Options:**
- `.WithContext(string)`: Add context for logging and metrics (used as metric label)
- `.AllowDuplicates()`: Set even if identical LS exists

### 3. Combined Note and Report (Recommended)

**This is the recommended pattern for all investigations.** Combines a PagerDuty note with a Backplane report in a single helper function.

```go
// Recommended: Use NoteAndReportFrom for both note and report
actions := executor.NoteAndReportFrom(r.Notes, r.Cluster.ID(), i.Name())

// This is equivalent to manually creating both:
actions := []types.Action{
    executor.NewBackplaneReportAction(r.Cluster.ID(), summary, r.Notes.String()).Build(),
    executor.NoteFrom(r.Notes),
}

// Typical usage in investigations
result.Actions = append(
    executor.NoteAndReportFrom(r.Notes, r.Cluster.ID(), i.Name()),
    executor.Escalate("Manual investigation required"),
)
```

**Parameters:**
- `notewriter`: The NoteWriter containing investigation findings
- `clusterID`: The cluster ID (use `r.Cluster.ID()`)
- `summary`: Investigation name (use `i.Name()`)

**Benefits:**
- Automatically creates both PagerDuty note and Backplane report
- Timestamps the report for historical tracking and searchability
- Reduces boilerplate - replaces manual BackplaneReportAction creation
- Ensures consistent reporting across all investigations

**When to use:**
- This should be the default for all investigations
- When completing any investigation (success or failure paths)
- Replaces standalone `NoteFrom()` usage in most cases

### 4. PagerDutyNoteAction

Add a note to the current PagerDuty incident.

```go
// From notewriter
action := executor.NoteFrom(notewriter)

// Direct string
action := executor.Note("Investigation findings...")

// Builder pattern
action := executor.NewPagerDutyNoteAction().
    AppendLine("Finding 1").
    AppendLine("Finding 2").
    AppendSection("Details", "More information...").
    Build()
```

### 5. SilenceIncidentAction

Silence (resolve) the current PagerDuty incident.

```go
action := executor.Silence("Customer misconfigured UWM - sent service log")

// Builder pattern
action := executor.NewSilenceIncidentAction("Reason for silencing").Build()
```

### 6. EscalateIncidentAction

Escalate the current PagerDuty incident to primary.

```go
action := executor.Escalate("Manual investigation required")

// Builder pattern
action := executor.NewEscalateIncidentAction("Reason for escalation").Build()
```

### 7. BackplaneReportAction (Low-Level)

Upload a report to the Backplane reports API. **Note:** Most investigations should use `NoteAndReportFrom()` instead of this action directly.

```go
// Low-level usage (rarely needed)
action := executor.NewBackplaneReportAction(clusterID, summary, reportData).Build()

// Preferred: Use the convenience function
actions := executor.NoteAndReportFrom(r.Notes, r.Cluster.ID(), i.Name())
```

## Action Execution Order

Actions are executed in the following order based on their type:

1. **PagerDuty actions** (sequentially):
   - PagerDutyNoteAction
   - SilenceIncidentAction or EscalateIncidentAction

2. **OCM actions** (in parallel):
   - ServiceLogAction
   - LimitedSupportAction

3. **Backplane actions** (in parallel):
   - BackplaneReportAction

**Example:**
```go
result.Actions = []types.Action{
    executor.ServiceLog(...),      // Executes in parallel with LimitedSupport
    executor.LimitedSupport(...),  // Executes in parallel with ServiceLog
    executor.NoteFrom(notes),      // Executes sequentially (first PD action)
    executor.Silence("reason"),    // Executes sequentially (after Note)
}
```

## Common Patterns

### Pattern 1: Customer Misconfiguration → Service Log + Silence

Use when the customer has misconfigured something and can fix it themselves.

```go
if customerMisconfigurationDetected {
    notes.AppendAutomation("Customer misconfigured X, sending service log and silencing alert")

    serviceLog := &ocm.ServiceLog{
        Severity:    "Major",
        Summary:     "Action required: review X configuration",
        Description: "Your cluster's X is misconfigured. Please review...",
        ServiceName: "SREManualAction",
    }

    result.Actions = append(
        executor.NoteAndReportFrom(notes, r.Cluster.ID(), i.Name()),
        executor.NewServiceLogAction(serviceLog.Severity, serviceLog.Summary).
            WithDescription(serviceLog.Description).
            WithServiceName(serviceLog.ServiceName).
            Build(),
        executor.Silence("Customer misconfigured X"),
    )
    return result, nil
}
```

### Pattern 2: Unsupported Action → Limited Support + Silence

Use when the customer performed an unsupported action (e.g., stopped instances).

```go
if unsupportedActionDetected {
    notes.AppendAutomation("Customer performed unsupported action, setting limited support")

    limitedSupportReason := ocm.LimitedSupportReason{
        Summary: "Cluster is in Limited Support due to unsupported action",
        Details: "Your cluster performed X which is not supported. Please...",
    }

    result.Actions = append(
        executor.NoteAndReportFrom(notes, r.Cluster.ID(), i.Name()),
        executor.NewLimitedSupportAction(limitedSupportReason.Summary, limitedSupportReason.Details, "ActionType").
            Build(),
        executor.Silence("Customer performed unsupported action"),
    )
    return result, nil
}
```

### Pattern 3: No Automation Available → Note + Escalate

Use when CAD cannot automatically remediate the issue.

```go
notes.AppendSuccess("Investigation completed, no automated remediation available")
notes.AppendWarning("Found issue X, requires manual investigation")

result.Actions = append(
    executor.NoteAndReportFrom(r.Notes, r.Cluster.ID(), i.Name()),
    executor.Escalate("Manual investigation required"),
)
return result, nil
```

### Pattern 4: Network/Egress Issues → Service Log + Escalate

Use when issues are detected but don't warrant limited support.

```go
if issueDetectedButNotCritical {
    notes.AppendWarning("Network issue detected, sending service log")

    result.Actions = append(
        executor.NoteAndReportFrom(notes, r.Cluster.ID(), i.Name()),
        executor.NewServiceLogAction("Warning", "Network connectivity issue detected").
            WithDescription("We detected that...").
            Build(),
        executor.Escalate("Manual investigation required"),
    )
    return result, nil
}
```

## Error Handling

### Error Type Classification

CAD uses three distinct error types (and one additional "outcome") to help the system properly handle different failure modes:

| Error Type | When to Use | System Behavior |
|------------|-------------|-----------------|
| **InfrastructureError** | Transient failures (AWS timeouts, rate limits, network issues) | Triggers retry |
| **FindingError** | Investigation findings that should be reported to SRE | Returns actions to notify SRE |
| **Regular error** | Code bugs, logic errors | Hard failure, requires code fix |
| **Success with Actions** | Investigation completed, actions determined | Executor runs actions |

### Infrastructure Errors

Use `investigation.WrapInfrastructure()` for transient failures that should trigger a retry:

```go
// AWS API timeout - should retry
events, err := r.AwsClient.GetCloudTrailEvents(...)
if err != nil {
    return result, investigation.WrapInfrastructure(
        fmt.Errorf("failed to get CloudTrail events: %w", err),
        "CloudTrail API call failed")
}

// Rate limiting - should retry
if isRateLimited(err) {
    return result, investigation.WrapInfrastructure(err, "API rate limit exceeded")
}
```

**Examples of infrastructure errors:**
- AWS API timeouts or rate limits
- OCM service temporary unavailability
- Network connectivity issues
- Kubernetes API server temporarily unavailable

### Finding Errors

Use `investigation.WrapFinding()` for investigation findings that should be reported to the SRE rather than causing a hard failure:

```go
// CloudTrail data too old - report as finding
events, err := r.AwsClient.GetCloudTrailEvents(...)
if err != nil && isDataTooOld(err) {
    notes.AppendWarning("CloudTrail data is too old to investigate")
    result.Actions = []types.Action{
        executor.NoteFrom(notes),
        executor.Escalate("CloudTrail data unavailable"),
    }
    return result, nil
}

// Missing data - convert to actions and return nil error
if len(events) == 0 {
    notes.AppendWarning("No relevant CloudTrail events found")
    result.Actions = []types.Action{
        executor.NoteFrom(notes),
        executor.Escalate("Insufficient data for investigation"),
    }
    return result, nil
}
```

**Examples of finding errors:**
- CloudTrail data older than retention period
- Missing configuration data
- No events matching criteria
- Cluster in unexpected state

### Checking Error Types

Use the helper functions to check error types:

```go
if investigation.IsInfrastructureError(err) {
    // Will be retried by the system
    return result, err
}

if investigation.IsFindingError(err) {
    // Should be handled with Actions
    // (Usually you don't return FindingError directly, but convert to Actions)
}
```

### Investigation Errors vs Action Failures

**Investigation Errors**: Return error from `Run()` when the investigation itself fails.

```go
// Infrastructure/transient errors (retry the investigation)
if err != nil {
    return result, investigation.WrapInfrastructure(
        fmt.Errorf("failed to get instance info: %w", err),
        "AWS API failure")
}

// Investigation findings that need manual review
notes.AppendWarning("Could not complete: %s", err.Error())
result.Actions = []types.Action{
    executor.NoteFrom(notes),
    executor.Escalate("Investigation incomplete - manual review required"),
}
return result, nil
```

**Action Failures**: The executor handles action failures with retry logic and error reporting.

```go
// ❌ DON'T: Handle action failures in investigation
if err := r.OcmClient.PostServiceLog(...); err != nil {
    return result, err  // Wrong!
}

// ✅ DO: Return actions, let executor handle failures
result.Actions = []types.Action{
    executor.ServiceLog(...),  // Executor will retry on failure
}
return result, nil
```

### K8s Client Errors

Handle K8s client errors specially to escalate with appropriate context:

```go
func (i *Investigation) Run(rb investigation.ResourceBuilder) (result investigation.InvestigationResult, err error) {
    r, err := rb.WithK8sClient().Build()
    if err != nil {
        k8sErr := &investigation.K8SClientError{}
        if errors.As(err, k8sErr) {
            if errors.Is(k8sErr.Err, k8sclient.ErrAPIServerUnavailable) {
                result.Actions = []types.Action{
                    executor.Escalate("CAD was unable to access cluster's kube-api. Please investigate manually."),
                }
                return result, nil
            }
            if errors.Is(k8sErr.Err, k8sclient.ErrCannotAccessInfra) {
                result.Actions = []types.Action{
                    executor.Escalate("CAD is not allowed to access hive, management or service cluster's kube-api. Please investigate manually."),
                }
                return result, nil
            }
            return result, err
        }
        return result, err
    }

    // Continue with investigation...
}
```

## Metrics

### Automatic Metrics Emission

The executor **automatically emits metrics** when actions succeed. You do not need to manually set `InvestigationStep` fields.

```go
// ❌ DON'T: Manually track metrics
result.ServiceLogSent = investigation.InvestigationStep{Performed: true}
result.LimitedSupportSet = investigation.InvestigationStep{Performed: true}

// ✅ DO: Just return actions - executor emits metrics
result.Actions = []types.Action{
    executor.ServiceLog(...),      // Executor emits servicelog_sent metric on success
    executor.LimitedSupport(...),  // Executor emits limitedsupport_set metric on success
}
```

### Metric Labels

Metrics are automatically labeled with:
- `investigationName`: From the investigation's `Name()` method
- Additional labels based on action context:
  - `LimitedSupportAction.Context`: Used as secondary label for LS metrics

```go
// Metric: limitedsupport_set{investigation="chgm", context="EgressBlocked"}
executor.NewLimitedSupportAction(summary, details).
    WithContext("EgressBlocked").
    Build()
```

## Testing

### Testing Investigations

Test investigations by verifying the **actions** they return, not by mocking external clients.

```go
// ✅ GOOD: Test actions returned
It("should send service log and silence when misconfiguration detected", func() {
    result, err := investigation.Run(builder)

    Expect(err).NotTo(HaveOccurred())
    Expect(result.Actions).To(HaveLen(3))
    Expect(hasServiceLogAction(result.Actions)).To(BeTrue())
    Expect(hasNoteAction(result.Actions)).To(BeTrue())
    Expect(hasSilenceAction(result.Actions)).To(BeTrue())
})

// Helper functions
func hasServiceLogAction(actions []types.Action) bool {
    for _, action := range actions {
        if _, ok := action.(*executor.ServiceLogAction); ok {
            return true
        }
    }
    return false
}
```

### Testing the Executor

The executor has its own test suite. Investigation tests should focus on the investigation logic.

## Migration Guide

### Migrating Existing Investigations

If you're working on an investigation that still uses the old pattern:

1. **Replace direct PagerDuty calls:**
   ```go
   // Before
   return result, r.PdClient.SilenceIncidentWithNote(notes.String())

   // After
   result.Actions = []types.Action{
       executor.NoteFrom(notes),
       executor.Silence("Reason"),
   }
   return result, nil
   ```

2. **Replace direct OCM calls:**
   ```go
   // Before
   err = r.OcmClient.PostServiceLog(r.Cluster, serviceLog)
   if err != nil {
       return result, fmt.Errorf("failed posting servicelog: %w", err)
   }

   // After
   result.Actions = []types.Action{
       executor.NewServiceLogAction(serviceLog.Severity, serviceLog.Summary).
           WithDescription(serviceLog.Description).
           Build(),
   }
   ```

3. **Remove manual metric tracking:**
   ```go
   // Before
   result.ServiceLogSent = investigation.InvestigationStep{Performed: true}

   // After
   // Remove this line - executor handles metrics automatically
   ```

4. **Update tests:**
   ```go
   // Before
   Expect(result.ServiceLogSent.Performed).To(BeTrue())

   // After
   Expect(hasServiceLogAction(result.Actions)).To(BeTrue())
   ```

## Best Practices

### Error Handling Contract

The `Investigation.Run()` method follows a strict error contract:

| Outcome | Return Pattern |
|---------|---------------|
| **Success** | `return result, nil` with `result.Actions` populated |
| **Infrastructure failure** | `return result, investigation.WrapInfrastructure(err, "context")` |
| **Investigation finding** | `return result, nil` with actions that escalate/note |
| **Code bug** | `return result, err` (regular error, should not happen) |

### DO ✅

- **Return actions instead of executing**: Let the executor handle external system calls
- **Use notewriter for investigation findings**: Build notes throughout investigation
- **Return nil error on success**: When actions are created successfully, return `nil` error
- **Use builder pattern**: Chain method calls for readable action construction
- **Provide clear reasons**: Always include reason strings for Silence/Escalate actions
- **Use context for metrics**: Add `.WithContext()` to LimitedSupportAction for better metrics
- **Wrap infrastructure errors at source**: Use `investigation.WrapInfrastructure()` when the error occurs
- **Convert findings to Actions**: Don't return `FindingError` directly, use Actions with Note/Escalate

### DON'T ❌

- **Call PagerDuty/OCM directly**: Never call `r.PdClient.*` or `r.OcmClient.PostServiceLog()`
- **Manually track metrics**: Don't set `result.ServiceLogSent` or `result.LimitedSupportSet`
- **Return errors for action failures**: Only return errors when investigation logic fails
- **Mock external clients in tests**: Test the actions returned, not execution details
- **Skip note context**: Always add notes before silencing/escalating for SRE visibility
- **Return regular errors for transient failures**: Always wrap with `WrapInfrastructure()`
- **Return regular errors for findings**: Always convert to Actions with appropriate escalation

## Examples

### Complete Investigation Example

See the CHGM investigation (`pkg/investigations/chgm/chgm.go`) for a complete example of:
- Handling multiple scenarios
- Using different action combinations
- Error handling
- Note building

### ClusterMonitoringErrorBudgetBurn Example

See the clustermonitoringerrorbudgetburn investigation for examples of:
- K8s client error handling
- Service log creation
- Multiple detection scenarios

## Reference

### Investigation Interface

```go
type Investigation interface {
    Run(builder ResourceBuilder) (InvestigationResult, error)
    Name() string
    AlertTitle() string
    Description() string
    IsExperimental() bool
}
```

### InvestigationResult

```go
type InvestigationResult struct {
    // NEW: Actions to execute via executor (modern approach)
    Actions []types.Action

    // DEPRECATED: Legacy fields (maintained for backwards compatibility)
    // These will be removed once all investigations are migrated
    LimitedSupportSet  InvestigationStep
    ServiceLogPrepared InvestigationStep
    ServiceLogSent     InvestigationStep

    // If not nil, indicates fatal error preventing further investigations
    StopInvestigations error
}
```

### Action Interface

```go
type Action interface {
    // Execute performs the action with the provided execution context
    Execute(ctx context.Context, execCtx *ExecutionContext) error

    // Type returns the action type identifier as a string
    Type() string

    // Validate checks if the action can be executed
    Validate() error
}
```

## Questions or Issues?

If you have questions about implementing investigations or encounter issues with the executor pattern, please:

1. Review existing migrated investigations (CHGM, clustermonitoringerrorbudgetburn)
2. Check this documentation and `docs/architecture/builder-pattern.md`
3. Reach out to the CAD team for guidance

---

**Document Version**: 1.0
**Last Updated**: 2025-11-21
**Applies to**: CAD with executor module (post-migration)

# Proposal: `pkg/micro` — Shared Microinvestigation Library

**Jira:** ROSAENG-67744 / MCS-157
**Status:** Implementation in progress (stacked branches `micro/phase-1a` through `micro/phase-8-outcome`)

## Why

CAD currently has 18+ alert investigations, many of which copy-paste the same patterns — ClusterAccessError, BannedUser, ClusterCreator, PullSecret checks — duplicating 100-150 lines per investigation. `pkg/micro` extracts these into a shared library with a typed `Result{Done, Actions}` / `DataResult[T]` API and an `Outcome` helper that replaces ad-hoc early-exit boilerplate.

Four problems drive this work:

### 1. Increase testability

Today, common investigation logic is inlined and interleaved with per-alert code. The only way to test a BannedUser check is to test the entire investigation end-to-end, which requires mocking every external dependency (OCM, AWS, PagerDuty, K8s) even when the test is only about ban detection.

`pkg/micro` exposes each pattern as a standalone function with explicit inputs. Pure checks like `CheckBan` accept already-fetched data and return typed results — they can be tested with zero mocks. Fetching wrappers like `BannedUser` take an `ocm.Client` interface and nothing else. Each function has its own focused test file.

### 2. Increase iteration speed

Adding a new investigation or modifying shared behavior (e.g., changing how ClusterAccessError escalations are worded) currently means touching 10-19 files that each have their own copy. Reviewers must verify that each copy was updated consistently.

With `pkg/micro`, the shared logic lives in one place. A change to ClusterAccessError escalation is a single-function edit with a single test update. New investigations consume these patterns as function calls instead of copy-pasting blocks they need to keep in sync.

### 3. Increase trust in investigation quality

Duplicated logic drifts. Different investigations handle the same scenario in subtly different ways — some escalate on cluster access errors, others only note them; some check ban status before pull secrets, others don't. These inconsistencies undermine confidence that investigations produce correct, complete results.

`pkg/micro` establishes canonical implementations with well-defined contracts:
- Pure functions (`Check*` prefix) make no external calls and are deterministic.
- Fetching functions (noun phrases) call a single external system and return structured results.
- `Outcome` provides a consistent Stop/Collect/Finalize pattern for result assembly.

When the shared function is correct and tested, every investigation that uses it inherits that correctness.

### 4. Unblock automation of additional alert handling to reduce on-call load

CAD's value proposition is reducing manual SRE effort. Each alert we automate is one fewer page that requires human investigation. But the current cost of writing a new investigation is high: authors must re-implement all the common patterns (access checks, ban detection, pull secret verification, OHSS case creation, result finalization) from scratch, correctly, and get each copy reviewed.

This cost is the bottleneck. `pkg/micro` lowers it to the alert-specific logic: consume the shared patterns as function calls, focus the new code on what's actually unique to the alert. The `Outcome` helper further reduces ceremony — `Stop()` for early exits, `Collect()` for accumulated actions, `Finalize()` for the terminal path.

By making investigations cheaper to write and review, we can automate more alerts faster and reduce on-call load.

## What

### Core types (`pkg/micro/result.go`)

```go
type Result struct {
    Done    bool
    Actions []types.Action
}

type DataResult[T any] struct {
    Result
    Value T
}
```

`Done: true` means the investigation has a finding and should stop (or at least handle the finding). `Actions` describes what to do (escalate, send service log, file OHSS case). `DataResult[T]` carries a typed value for callers that need to branch on the finding details.

### Shared functions

| Function | Type | What it does |
|----------|------|-------------|
| `ClusterAccessError` | Pure check | Detects backplane/cluster access failures, returns escalation |
| `CheckBan` | Pure check | Inspects account ban status, returns ban info + appropriate actions |
| `BannedUser` | Fetching | Fetches cluster creator via OCM, delegates to `CheckBan` |
| `ClusterCreator` | Fetching | Fetches cluster creator account |
| `PullSecret` | Fetching | Validates pull secret via K8s, returns diagnostic actions |

### Outcome helper (`pkg/micro/outcome.go`)

```go
outcome := micro.NewOutcome(notes, clusterID, investigationName)

// Early exit on finding
if accessErr := micro.ClusterAccessError(err, notes); accessErr.Done {
    return outcome.Stop(accessErr.Actions...), nil
}

// Accumulate non-terminal actions
outcome.Collect(ohssAction)

// Final result
return outcome.Finalize(additionalActions...), nil
```

### Naming convention

- **`Check*`** prefix: pure functions, no external calls, deterministic
- **Noun phrases** (`BannedUser`, `ClusterCreator`, `PullSecret`): fetching functions that call external systems

## Migration path

Stacked branches, each independently reviewable:

1. **phase-1a/b/c**: Result types, initial functions, first investigation migrated (`upgradeconfigsync`)
2. **phase-2***: Migrate ClusterAccessError, ClusterCreator, FinalizeResult across investigations
3. **phase-4***: Jira client + OHSS case action
4. **phase-5**: PullSecret tests
5. **phase-6**: CheckBan pure function + migration
6. **phase-7**: Thread `context.Context` through `Investigation.Run`
7. **phase-8**: Outcome helper, replacing the checks framework

Each phase builds on the previous. Investigations are migrated incrementally — no big-bang rewrite.

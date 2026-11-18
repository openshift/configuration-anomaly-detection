// Package micro provides reusable building blocks for investigations.
//
// Functions follow two conventions:
//   - Pure checks (Check* prefix): no external calls, deterministic.
//     They inspect already-fetched data and return a result with actions.
//   - Fetching functions (noun phrases like ClusterCreator, PullSecret):
//     make external calls (OCM, K8s) and return a result or error.
package micro

import "github.com/openshift/configuration-anomaly-detection/pkg/types"

// Result is the return type for micro functions that produce a terminal
// finding. Done indicates the caller should treat this as a complete
// finding and stop further checks in the current branch.
type Result struct {
	Done    bool
	Actions []types.Action
}

// DataResult extends Result with a typed value for callers that need
// to inspect the fetched data (e.g., ban code, error message).
type DataResult[T any] struct {
	Result
	Value T
}

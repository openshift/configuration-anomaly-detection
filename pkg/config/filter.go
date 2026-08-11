// Package config provides configuration and tree-based filtering for
// investigation actions.
//
// Filters are evaluated against a FilterContext populated from OCM and
// PagerDuty data. A filter is a recursive tree of AND/OR branch nodes
// and leaf comparison nodes. A nil or empty filter always passes.
//
// Example YAML:
//
//	filter:
//	  and:
//	    - field: CloudProvider
//	      operator: in
//	      values: ["aws"]
//	    - or:
//	        - field: OwnerEmail
//	          operator: notmatches
//	          values: [".*@redhat\\.com$"]
//	        - operator: sample
//	          values: ["0.10"]
package config

import (
	"fmt"
	"math/rand"
	"regexp"
	"strconv"

	"github.com/openshift/configuration-anomaly-detection/pkg/types"
)

// Operator constants for filter leaf nodes.
const (
	OperatorIn         = "in"
	OperatorNotIn      = "notin"
	OperatorMatches    = "matches"
	OperatorNotMatches = "notmatches"
	OperatorSample     = "sample"
)

// Field name constants for FilterContext fields.
// Use these in filter configs, resolveField, and anywhere a field is referenced by name.
const (
	FieldClusterID      = "ClusterID"
	FieldClusterName    = "ClusterName"
	FieldOrganizationID = "OrganizationID"
	FieldOwnerID        = "OwnerID"
	FieldOwnerEmail     = "OwnerEmail"
	FieldCloudProvider  = "CloudProvider"
	FieldHCP            = "HCP"
	FieldClusterState   = "ClusterState"
	FieldAlertName      = "AlertName"
	FieldAlertTitle     = "AlertTitle"
	FieldServiceName    = "ServiceName"
)

// validFields lists all FilterContext field names that can be used in leaf nodes.
// This must be kept in sync with FilterContext and resolveField.
var validFields = []string{
	FieldClusterID,
	FieldClusterName,
	FieldOrganizationID,
	FieldOwnerID,
	FieldOwnerEmail,
	FieldCloudProvider,
	FieldHCP,
	FieldClusterState,
	FieldAlertName,
	FieldAlertTitle,
	FieldServiceName,
}

// FilterNode is a recursive filter tree node. It is either:
//   - A branch: exactly one of And/Or is set (children evaluated with AND/OR logic)
//   - A leaf: Operator is set (field comparison or probabilistic sampling)
//
// Mutual exclusivity is enforced by Validate — a node cannot be both a branch and a leaf,
// and cannot have both And and Or set.
type FilterNode struct {
	// Branch node fields — exactly one of And/Or must be set for a branch.
	And []FilterNode `yaml:"and,omitempty"`
	Or  []FilterNode `yaml:"or,omitempty"`

	// Leaf node fields — Field+Operator+Values for comparison, or just Operator+Values for sample.
	Field    string   `yaml:"field,omitempty"`
	Operator string   `yaml:"operator,omitempty"`
	Values   []string `yaml:"values,omitempty"`
}

// InvestigationFilter associates a filter tree with an investigation by name.
// A nil Filter means the investigation always runs (no restrictions).
type InvestigationFilter struct {
	// Investigation is the investigation name, matching Investigation.Name() or a short name
	// from the manual controller's shortNameToInvestigation map.
	Investigation string `yaml:"investigation"`
	// Filter is the root of the filter tree. nil means always run.
	Filter *FilterNode `yaml:"when,omitempty"`
}

// Evaluate checks the filter tree for an investigation.
// Returns (result, reason, error) where reason describes which leaf determined the outcome.
// A nil InvestigationFilter or nil Filter always returns true.
// A nil FilterContext always returns true (manual mode bypass).
func (f *InvestigationFilter) Evaluate(ctx *types.FilterContext) (bool, string, error) {
	if f == nil || f.Filter == nil {
		return true, "no filter configured", nil
	}
	if ctx == nil {
		return true, "no filter context (manual mode)", nil
	}
	return f.Filter.evaluate(ctx)
}

// Keys returns all field names referenced by leaf nodes in the filter tree.
// Used to determine which FilterContext fields need to be populated.
func (f InvestigationFilter) Keys() []string {
	keys := make([]string, 0)
	if f.Filter != nil {
		f.Filter.keys(&keys)
	}
	return keys
}

// evaluate recursively evaluates the filter node tree against the FilterContext.
// Returns (result, reason, error) where reason describes the deciding leaf node.
func (n *FilterNode) evaluate(ctx *types.FilterContext) (bool, string, error) {
	// Branch: AND — all children must pass.
	if len(n.And) > 0 {
		for i := range n.And {
			pass, reason, err := n.And[i].evaluate(ctx)
			if err != nil {
				return false, reason, err
			}
			if !pass {
				return false, reason, nil
			}
		}
		return true, "all AND conditions passed", nil
	}

	// Branch: OR — at least one child must pass.
	if len(n.Or) > 0 {
		var lastReason string
		for i := range n.Or {
			pass, reason, err := n.Or[i].evaluate(ctx)
			if err != nil {
				return false, reason, err
			}
			if pass {
				return true, reason, nil
			}
			lastReason = reason
		}
		return false, lastReason, nil
	}

	// Leaf node.
	return n.evaluateLeaf(ctx)
}

// evaluateLeaf evaluates a single leaf node against the FilterContext.
// Returns (result, reason, error) where reason describes the leaf evaluation.
func (n *FilterNode) evaluateLeaf(ctx *types.FilterContext) (bool, string, error) {
	switch n.Operator {
	case OperatorSample:
		rate, err := strconv.ParseFloat(n.Values[0], 64)
		if err != nil {
			return false, "", fmt.Errorf("sample: invalid rate %q: %w", n.Values[0], err)
		}
		roll := rand.Float64() //nolint:gosec // not security-sensitive, used for traffic sampling
		passed := roll < rate
		reason := fmt.Sprintf("sample(%.2f): roll=%.4f → %s", rate, roll, passOrReject(passed))
		return passed, reason, nil

	case OperatorIn:
		resolved, err := resolveField(n.Field, ctx)
		if err != nil {
			return false, "", err
		}
		passed := contains(n.Values, resolved)
		reason := fmt.Sprintf("%s %s %v: %q → %s", n.Field, n.Operator, n.Values, resolved, passOrReject(passed))
		return passed, reason, nil

	case OperatorNotIn:
		resolved, err := resolveField(n.Field, ctx)
		if err != nil {
			return false, "", err
		}
		passed := !contains(n.Values, resolved)
		reason := fmt.Sprintf("%s %s %v: %q → %s", n.Field, n.Operator, n.Values, resolved, passOrReject(passed))
		return passed, reason, nil

	case OperatorMatches:
		resolved, err := resolveField(n.Field, ctx)
		if err != nil {
			return false, "", err
		}
		for _, pattern := range n.Values {
			matched, err := regexp.MatchString(pattern, resolved)
			if err != nil {
				return false, "", fmt.Errorf("matches: invalid regex %q: %w", pattern, err)
			}
			if matched {
				return true, fmt.Sprintf("%s matches %q: %q → pass", n.Field, pattern, resolved), nil
			}
		}
		return false, fmt.Sprintf("%s matches %v: %q → reject", n.Field, n.Values, resolved), nil

	case OperatorNotMatches:
		resolved, err := resolveField(n.Field, ctx)
		if err != nil {
			return false, "", err
		}
		for _, pattern := range n.Values {
			matched, err := regexp.MatchString(pattern, resolved)
			if err != nil {
				return false, "", fmt.Errorf("notmatches: invalid regex %q: %w", pattern, err)
			}
			if matched {
				return false, fmt.Sprintf("%s notmatches %q: %q matched → reject", n.Field, pattern, resolved), nil
			}
		}
		return true, fmt.Sprintf("%s notmatches %v: %q → pass", n.Field, n.Values, resolved), nil

	default:
		return false, "", fmt.Errorf("unsupported operator %q", n.Operator)
	}
}

// passOrReject returns "pass" or "reject" based on a boolean result.
func passOrReject(passed bool) string {
	if passed {
		return "pass"
	}
	return "reject"
}

// keys recursively collects all field names referenced by leaf nodes.
func (n *FilterNode) keys(out *[]string) {
	if len(n.And) > 0 {
		for i := range n.And {
			n.And[i].keys(out)
		}
		return
	}
	if len(n.Or) > 0 {
		for i := range n.Or {
			n.Or[i].keys(out)
		}
		return
	}
	// Leaf: sample has no field.
	if n.Field != "" {
		*out = append(*out, n.Field)
	}
}

// validate recursively validates the filter node tree.
// The path parameter builds a human-readable path for error messages (e.g. "filter.and[0].or[1]").
func (n *FilterNode) validate(path string) error {
	hasAnd := len(n.And) > 0
	hasOr := len(n.Or) > 0
	hasOp := n.Operator != ""

	// Mutual exclusivity.
	if hasAnd && hasOr {
		return fmt.Errorf("%s: node cannot have both 'and' and 'or'", path)
	}
	if (hasAnd || hasOr) && hasOp {
		return fmt.Errorf("%s: node cannot be both a branch (and/or) and a leaf (operator)", path)
	}
	if !hasAnd && !hasOr && !hasOp {
		return fmt.Errorf("%s: node must have 'and', 'or', or 'operator'", path)
	}

	// Branch validation.
	if hasAnd {
		for i := range n.And {
			if err := n.And[i].validate(fmt.Sprintf("%s.and[%d]", path, i)); err != nil {
				return err
			}
		}
		return nil
	}
	if hasOr {
		for i := range n.Or {
			if err := n.Or[i].validate(fmt.Sprintf("%s.or[%d]", path, i)); err != nil {
				return err
			}
		}
		return nil
	}

	// Leaf validation.
	return n.validateLeaf(path)
}

// validateLeaf validates a single leaf node.
func (n *FilterNode) validateLeaf(path string) error {
	switch n.Operator {
	case OperatorIn, OperatorNotIn:
		if n.Field == "" {
			return fmt.Errorf("%s: operator %q requires a field", path, n.Operator)
		}
		if !isValidField(n.Field) {
			return fmt.Errorf("%s: unknown field %q; valid fields: %v", path, n.Field, validFields)
		}
		if len(n.Values) == 0 {
			return fmt.Errorf("%s: values must not be empty", path)
		}

	case OperatorMatches, OperatorNotMatches:
		if n.Field == "" {
			return fmt.Errorf("%s: operator %q requires a field", path, n.Operator)
		}
		if !isValidField(n.Field) {
			return fmt.Errorf("%s: unknown field %q; valid fields: %v", path, n.Field, validFields)
		}
		if len(n.Values) == 0 {
			return fmt.Errorf("%s: values must not be empty", path)
		}
		for i, pattern := range n.Values {
			if _, err := regexp.Compile(pattern); err != nil {
				return fmt.Errorf("%s: values[%d]: invalid regex %q: %w", path, i, pattern, err)
			}
		}

	case OperatorSample:
		if n.Field != "" {
			return fmt.Errorf("%s: operator %q must not have a field", path, n.Operator)
		}
		if len(n.Values) != 1 {
			return fmt.Errorf("%s: operator %q requires exactly one value", path, n.Operator)
		}
		rate, err := strconv.ParseFloat(n.Values[0], 64)
		if err != nil {
			return fmt.Errorf("%s: operator %q: invalid rate %q: %w", path, n.Operator, n.Values[0], err)
		}
		if rate < 0 || rate > 1 {
			return fmt.Errorf("%s: operator %q: rate must be between 0 and 1, got %v", path, n.Operator, rate)
		}

	default:
		return fmt.Errorf("%s: unsupported operator %q", path, n.Operator)
	}

	return nil
}

// resolveField looks up a FilterContext field by its struct field name and returns
// the value as a string.
func resolveField(field string, ctx *types.FilterContext) (string, error) {
	switch field {
	case FieldClusterID:
		return ctx.ClusterID, nil
	case FieldClusterName:
		return ctx.ClusterName, nil
	case FieldOrganizationID:
		return ctx.OrganizationID, nil
	case FieldOwnerID:
		return ctx.OwnerID, nil
	case FieldOwnerEmail:
		return ctx.OwnerEmail, nil
	case FieldCloudProvider:
		return ctx.CloudProvider, nil
	case FieldHCP:
		return strconv.FormatBool(ctx.HCP), nil
	case FieldClusterState:
		return ctx.ClusterState, nil
	case FieldAlertName:
		return ctx.AlertName, nil
	case FieldAlertTitle:
		return ctx.AlertTitle, nil
	case FieldServiceName:
		return ctx.ServiceName, nil
	default:
		return "", fmt.Errorf("unknown field %q; valid fields: %v", field, validFields)
	}
}

// isValidField checks whether a field name is a known FilterContext field.
func isValidField(field string) bool {
	for _, f := range validFields {
		if f == field {
			return true
		}
	}
	return false
}

// contains checks if a string is present in a slice.
func contains(values []string, target string) bool {
	for _, v := range values {
		if v == target {
			return true
		}
	}
	return false
}

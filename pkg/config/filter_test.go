package config

import (
	"testing"

	"github.com/openshift/configuration-anomaly-detection/pkg/types"
)

func TestFilterEvaluate(t *testing.T) { //nolint:maintidx // table-driven test with many cases
	baseCtx := &types.FilterContext{
		ClusterID:      "abc-123",
		ClusterName:    "my-cluster",
		OrganizationID: "org-456",
		OwnerID:        "owner-789",
		OwnerEmail:     "user@redhat.com",
		CloudProvider:  "aws",
		HCP:            false,
		ClusterState:   "ready",
		AlertName:      "ClusterHasGoneMissing",
		AlertTitle:     "ClusterHasGoneMissing CRITICAL (1)",
		ServiceName:    "prod-osd",
	}

	tests := []struct {
		name    string
		filter  *InvestigationFilter
		ctx     *types.FilterContext
		want    bool
		wantErr bool
	}{
		// --- nil / empty ---
		{
			name:   "nil filter passes",
			filter: nil,
			ctx:    baseCtx,
			want:   true,
		},
		{
			name:   "empty filter (nil tree) passes",
			filter: &InvestigationFilter{},
			ctx:    baseCtx,
			want:   true,
		},
		{
			name: "nil context passes",
			filter: &InvestigationFilter{
				Filter: &FilterNode{Field: "AlertName", Operator: OperatorIn, Values: []string{"chgm"}},
			},
			ctx:  nil,
			want: true,
		},
		// --- single leaf: in ---
		{
			name: "in operator matches",
			filter: &InvestigationFilter{
				Filter: &FilterNode{Field: "CloudProvider", Operator: OperatorIn, Values: []string{"aws", "gcp"}},
			},
			ctx:  baseCtx,
			want: true,
		},
		{
			name: "in operator does not match",
			filter: &InvestigationFilter{
				Filter: &FilterNode{Field: "CloudProvider", Operator: OperatorIn, Values: []string{"gcp", "azure"}},
			},
			ctx:  baseCtx,
			want: false,
		},
		// --- single leaf: notin ---
		{
			name: "notin operator matches",
			filter: &InvestigationFilter{
				Filter: &FilterNode{Field: "CloudProvider", Operator: OperatorNotIn, Values: []string{"gcp"}},
			},
			ctx:  baseCtx,
			want: true,
		},
		{
			name: "notin operator does not match",
			filter: &InvestigationFilter{
				Filter: &FilterNode{Field: "CloudProvider", Operator: OperatorNotIn, Values: []string{"aws"}},
			},
			ctx:  baseCtx,
			want: false,
		},
		// --- single leaf: matches ---
		{
			name: "matches operator matches",
			filter: &InvestigationFilter{
				Filter: &FilterNode{Field: "OwnerEmail", Operator: OperatorMatches, Values: []string{".*@redhat\\.com$"}},
			},
			ctx:  baseCtx,
			want: true,
		},
		{
			name: "matches operator does not match",
			filter: &InvestigationFilter{
				Filter: &FilterNode{Field: "OwnerEmail", Operator: OperatorMatches, Values: []string{".*@ibm\\.com$"}},
			},
			ctx:  baseCtx,
			want: false,
		},
		{
			name: "matches with multiple patterns matches second",
			filter: &InvestigationFilter{
				Filter: &FilterNode{Field: "OwnerEmail", Operator: OperatorMatches, Values: []string{".*@ibm\\.com$", ".*@redhat\\.com$"}},
			},
			ctx:  baseCtx,
			want: true,
		},
		// --- single leaf: notmatches ---
		{
			name: "notmatches operator matches (no regex match = true)",
			filter: &InvestigationFilter{
				Filter: &FilterNode{Field: "OwnerEmail", Operator: OperatorNotMatches, Values: []string{".*@ibm\\.com$"}},
			},
			ctx:  baseCtx,
			want: true,
		},
		{
			name: "notmatches operator does not match (regex matches = false)",
			filter: &InvestigationFilter{
				Filter: &FilterNode{Field: "OwnerEmail", Operator: OperatorNotMatches, Values: []string{".*@redhat\\.com$"}},
			},
			ctx:  baseCtx,
			want: false,
		},
		// --- AND branch ---
		{
			name: "AND all pass",
			filter: &InvestigationFilter{
				Filter: &FilterNode{
					And: []FilterNode{
						{Field: "CloudProvider", Operator: OperatorIn, Values: []string{"aws"}},
						{Field: "ClusterState", Operator: OperatorIn, Values: []string{"ready"}},
						{Field: "AlertName", Operator: OperatorIn, Values: []string{"ClusterHasGoneMissing", "cpd"}},
					},
				},
			},
			ctx:  baseCtx,
			want: true,
		},
		{
			name: "AND one fails",
			filter: &InvestigationFilter{
				Filter: &FilterNode{
					And: []FilterNode{
						{Field: "CloudProvider", Operator: OperatorIn, Values: []string{"aws"}},
						{Field: "ClusterState", Operator: OperatorIn, Values: []string{"uninstalling"}},
					},
				},
			},
			ctx:  baseCtx,
			want: false,
		},
		// --- OR branch ---
		{
			name: "OR one matches",
			filter: &InvestigationFilter{
				Filter: &FilterNode{
					Or: []FilterNode{
						{Field: "ClusterID", Operator: OperatorIn, Values: []string{"abc-123"}},
						{Field: "ClusterID", Operator: OperatorIn, Values: []string{"other"}},
					},
				},
			},
			ctx:  baseCtx,
			want: true,
		},
		{
			name: "OR none match",
			filter: &InvestigationFilter{
				Filter: &FilterNode{
					Or: []FilterNode{
						{Field: "ClusterID", Operator: OperatorIn, Values: []string{"other1"}},
						{Field: "ClusterID", Operator: OperatorIn, Values: []string{"other2"}},
					},
				},
			},
			ctx:  baseCtx,
			want: false,
		},
		{
			name: "OR second matches",
			filter: &InvestigationFilter{
				Filter: &FilterNode{
					Or: []FilterNode{
						{Field: "ClusterID", Operator: OperatorIn, Values: []string{"no-match"}},
						{Field: "OrganizationID", Operator: OperatorIn, Values: []string{"org-456"}},
					},
				},
			},
			ctx:  baseCtx,
			want: true,
		},
		// --- nested AND + OR ---
		{
			name: "AND+OR both pass",
			filter: &InvestigationFilter{
				Filter: &FilterNode{
					And: []FilterNode{
						{Field: "CloudProvider", Operator: OperatorIn, Values: []string{"aws"}},
						{Or: []FilterNode{
							{Field: "ClusterID", Operator: OperatorIn, Values: []string{"abc-123"}},
						}},
					},
				},
			},
			ctx:  baseCtx,
			want: true,
		},
		{
			name: "AND+OR AND fails",
			filter: &InvestigationFilter{
				Filter: &FilterNode{
					And: []FilterNode{
						{Field: "CloudProvider", Operator: OperatorIn, Values: []string{"gcp"}},
						{Or: []FilterNode{
							{Field: "ClusterID", Operator: OperatorIn, Values: []string{"abc-123"}},
						}},
					},
				},
			},
			ctx:  baseCtx,
			want: false,
		},
		{
			name: "AND+OR OR fails",
			filter: &InvestigationFilter{
				Filter: &FilterNode{
					And: []FilterNode{
						{Field: "CloudProvider", Operator: OperatorIn, Values: []string{"aws"}},
						{Or: []FilterNode{
							{Field: "ClusterID", Operator: OperatorIn, Values: []string{"no-match"}},
						}},
					},
				},
			},
			ctx:  baseCtx,
			want: false,
		},
		// --- deeply nested (3 levels) ---
		{
			name: "3-level nesting",
			filter: &InvestigationFilter{
				Filter: &FilterNode{
					And: []FilterNode{
						{Field: "CloudProvider", Operator: OperatorIn, Values: []string{"aws"}},
						{Or: []FilterNode{
							{And: []FilterNode{
								{Field: "ClusterID", Operator: OperatorIn, Values: []string{"abc-123"}},
								{Field: "ClusterState", Operator: OperatorIn, Values: []string{"ready"}},
							}},
							{Field: "OrganizationID", Operator: OperatorIn, Values: []string{"other-org"}},
						}},
					},
				},
			},
			ctx:  baseCtx,
			want: true,
		},
		// --- field types ---
		{
			name: "HCP bool field false",
			filter: &InvestigationFilter{
				Filter: &FilterNode{Field: "HCP", Operator: OperatorIn, Values: []string{"false"}},
			},
			ctx:  baseCtx,
			want: true,
		},
		{
			name: "HCP bool field true",
			filter: &InvestigationFilter{
				Filter: &FilterNode{Field: "HCP", Operator: OperatorIn, Values: []string{"true"}},
			},
			ctx:  &types.FilterContext{HCP: true},
			want: true,
		},
		{
			name: "OwnerEmail field",
			filter: &InvestigationFilter{
				Filter: &FilterNode{Field: "OwnerEmail", Operator: OperatorIn, Values: []string{"user@redhat.com"}},
			},
			ctx:  baseCtx,
			want: true,
		},
		{
			name: "OrganizationID field",
			filter: &InvestigationFilter{
				Filter: &FilterNode{Field: "OrganizationID", Operator: OperatorIn, Values: []string{"org-456"}},
			},
			ctx:  baseCtx,
			want: true,
		},
		{
			name: "ServiceName field",
			filter: &InvestigationFilter{
				Filter: &FilterNode{Field: "ServiceName", Operator: OperatorIn, Values: []string{"prod-osd"}},
			},
			ctx:  baseCtx,
			want: true,
		},
		{
			name: "empty context field does not match in",
			filter: &InvestigationFilter{
				Filter: &FilterNode{Field: "OwnerEmail", Operator: OperatorIn, Values: []string{"user@redhat.com"}},
			},
			ctx:  &types.FilterContext{},
			want: false,
		},
		{
			name: "empty context field matches notin",
			filter: &InvestigationFilter{
				Filter: &FilterNode{Field: "OwnerEmail", Operator: OperatorNotIn, Values: []string{"user@redhat.com"}},
			},
			ctx:  &types.FilterContext{},
			want: true,
		},
		// --- sample operator ---
		{
			name: "sample 1.0 always passes",
			filter: &InvestigationFilter{
				Filter: &FilterNode{Operator: OperatorSample, Values: []string{"1.0"}},
			},
			ctx:  baseCtx,
			want: true,
		},
		{
			name: "sample 0 always fails",
			filter: &InvestigationFilter{
				Filter: &FilterNode{Operator: OperatorSample, Values: []string{"0"}},
			},
			ctx:  baseCtx,
			want: false,
		},
		// --- sample with exemption pattern ---
		{
			name: "sample exemption: redhat email bypasses sampling",
			filter: &InvestigationFilter{
				Filter: &FilterNode{
					Or: []FilterNode{
						{Field: "OwnerEmail", Operator: OperatorNotMatches, Values: []string{".*@redhat\\.com$"}},
						{Operator: OperatorSample, Values: []string{"1.0"}},
					},
				},
			},
			ctx:  baseCtx,
			want: true, // notmatches fails (is redhat), but sample 1.0 passes via OR
		},
		{
			name: "sample exemption: non-redhat email passes via notmatches",
			filter: &InvestigationFilter{
				Filter: &FilterNode{
					Or: []FilterNode{
						{Field: "OwnerEmail", Operator: OperatorNotMatches, Values: []string{".*@redhat\\.com$"}},
						{Operator: OperatorSample, Values: []string{"0"}},
					},
				},
			},
			ctx:  &types.FilterContext{OwnerEmail: "user@example.com"},
			want: true, // notmatches passes (not redhat), short-circuits OR
		},
		{
			name: "sample exemption: redhat email with sample 0 fails",
			filter: &InvestigationFilter{
				Filter: &FilterNode{
					Or: []FilterNode{
						{Field: "OwnerEmail", Operator: OperatorNotMatches, Values: []string{".*@redhat\\.com$"}},
						{Operator: OperatorSample, Values: []string{"0"}},
					},
				},
			},
			ctx:  baseCtx,
			want: false, // notmatches fails (is redhat), sample 0 fails
		},
		// --- error cases ---
		{
			name: "unknown field returns error",
			filter: &InvestigationFilter{
				Filter: &FilterNode{Field: "UnknownField", Operator: OperatorIn, Values: []string{"x"}},
			},
			ctx:     baseCtx,
			wantErr: true,
		},
		{
			name: "unsupported operator returns error",
			filter: &InvestigationFilter{
				Filter: &FilterNode{Field: "CloudProvider", Operator: "equals", Values: []string{"aws"}},
			},
			ctx:     baseCtx,
			wantErr: true,
		},
		{
			name: "error in AND child propagates",
			filter: &InvestigationFilter{
				Filter: &FilterNode{
					And: []FilterNode{
						{Field: "BadField", Operator: OperatorIn, Values: []string{"x"}},
					},
				},
			},
			ctx:     baseCtx,
			wantErr: true,
		},
		{
			name: "error in OR child propagates",
			filter: &InvestigationFilter{
				Filter: &FilterNode{
					Or: []FilterNode{
						{Field: "BadField", Operator: OperatorIn, Values: []string{"x"}},
					},
				},
			},
			ctx:     baseCtx,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, reason, err := tt.filter.Evaluate(tt.ctx)
			if (err != nil) != tt.wantErr {
				t.Errorf("Evaluate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("Evaluate() = %v, want %v (reason: %s)", got, tt.want, reason)
			}
		})
	}
}

func TestFilterNodeValidate(t *testing.T) {
	tests := []struct {
		name    string
		node    FilterNode
		wantErr bool
	}{
		// --- valid leaves ---
		{
			name:    "valid in leaf",
			node:    FilterNode{Field: "AlertName", Operator: OperatorIn, Values: []string{"chgm"}},
			wantErr: false,
		},
		{
			name:    "valid notin leaf",
			node:    FilterNode{Field: "CloudProvider", Operator: OperatorNotIn, Values: []string{"gcp"}},
			wantErr: false,
		},
		{
			name:    "valid matches leaf",
			node:    FilterNode{Field: "OwnerEmail", Operator: OperatorMatches, Values: []string{".*@redhat\\.com$"}},
			wantErr: false,
		},
		{
			name:    "valid notmatches leaf",
			node:    FilterNode{Field: "OwnerEmail", Operator: OperatorNotMatches, Values: []string{".*@redhat\\.com$"}},
			wantErr: false,
		},
		{
			name:    "valid sample leaf",
			node:    FilterNode{Operator: OperatorSample, Values: []string{"0.10"}},
			wantErr: false,
		},
		{
			name:    "sample rate 0 valid",
			node:    FilterNode{Operator: OperatorSample, Values: []string{"0"}},
			wantErr: false,
		},
		{
			name:    "sample rate 1 valid",
			node:    FilterNode{Operator: OperatorSample, Values: []string{"1"}},
			wantErr: false,
		},
		// --- valid branches ---
		{
			name: "valid and branch",
			node: FilterNode{
				And: []FilterNode{
					{Field: "AlertName", Operator: OperatorIn, Values: []string{"chgm"}},
				},
			},
			wantErr: false,
		},
		{
			name: "valid or branch",
			node: FilterNode{
				Or: []FilterNode{
					{Field: "AlertName", Operator: OperatorIn, Values: []string{"chgm"}},
				},
			},
			wantErr: false,
		},
		// --- invalid: mutual exclusivity ---
		{
			name: "both 'and' and 'or'",
			node: FilterNode{
				And: []FilterNode{{Field: "AlertName", Operator: OperatorIn, Values: []string{"a"}}},
				Or:  []FilterNode{{Field: "AlertName", Operator: OperatorIn, Values: []string{"b"}}},
			},
			wantErr: true,
		},
		{
			name: "branch with operator",
			node: FilterNode{
				And:      []FilterNode{{Field: "AlertName", Operator: OperatorIn, Values: []string{"a"}}},
				Operator: OperatorIn,
			},
			wantErr: true,
		},
		{
			name:    "empty node",
			node:    FilterNode{},
			wantErr: true,
		},
		// --- invalid leaves ---
		{
			name:    "in without field",
			node:    FilterNode{Operator: OperatorIn, Values: []string{"aws"}},
			wantErr: true,
		},
		{
			name:    "unknown field",
			node:    FilterNode{Field: "NonExistent", Operator: OperatorIn, Values: []string{"x"}},
			wantErr: true,
		},
		{
			name:    "in with empty values",
			node:    FilterNode{Field: "AlertName", Operator: OperatorIn, Values: []string{}},
			wantErr: true,
		},
		{
			name:    "in with nil values",
			node:    FilterNode{Field: "AlertName", Operator: OperatorIn},
			wantErr: true,
		},
		{
			name:    "unsupported operator",
			node:    FilterNode{Field: "AlertName", Operator: "equals", Values: []string{"x"}},
			wantErr: true,
		},
		{
			name:    "matches with invalid regex",
			node:    FilterNode{Field: "OwnerEmail", Operator: OperatorMatches, Values: []string{"[invalid"}},
			wantErr: true,
		},
		{
			name:    "notmatches with invalid regex",
			node:    FilterNode{Field: "OwnerEmail", Operator: OperatorNotMatches, Values: []string{"[invalid"}},
			wantErr: true,
		},
		{
			name:    "matches without field",
			node:    FilterNode{Operator: OperatorMatches, Values: []string{".*"}},
			wantErr: true,
		},
		{
			name:    "sample with field",
			node:    FilterNode{Field: "CloudProvider", Operator: OperatorSample, Values: []string{"0.5"}},
			wantErr: true,
		},
		{
			name:    "sample with multiple values",
			node:    FilterNode{Operator: OperatorSample, Values: []string{"0.5", "0.3"}},
			wantErr: true,
		},
		{
			name:    "sample with non-numeric value",
			node:    FilterNode{Operator: OperatorSample, Values: []string{"abc"}},
			wantErr: true,
		},
		{
			name:    "sample rate negative",
			node:    FilterNode{Operator: OperatorSample, Values: []string{"-0.1"}},
			wantErr: true,
		},
		{
			name:    "sample rate greater than 1",
			node:    FilterNode{Operator: OperatorSample, Values: []string{"1.5"}},
			wantErr: true,
		},
		// --- invalid children propagate ---
		{
			name: "invalid child in and branch",
			node: FilterNode{
				And: []FilterNode{
					{Field: "BadField", Operator: OperatorIn, Values: []string{"x"}},
				},
			},
			wantErr: true,
		},
		{
			name: "invalid child in or branch",
			node: FilterNode{
				Or: []FilterNode{
					{Field: "BadField", Operator: OperatorIn, Values: []string{"x"}},
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.node.validate("test")
			if (err != nil) != tt.wantErr {
				t.Errorf("validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestKeys(t *testing.T) {
	tests := []struct {
		name string
		f    InvestigationFilter
		want []string
	}{
		{
			name: "nil filter",
			f:    InvestigationFilter{},
			want: []string{},
		},
		{
			name: "single leaf",
			f:    InvestigationFilter{Filter: &FilterNode{Field: "CloudProvider", Operator: OperatorIn, Values: []string{"aws"}}},
			want: []string{"CloudProvider"},
		},
		{
			name: "sample leaf has no keys",
			f:    InvestigationFilter{Filter: &FilterNode{Operator: OperatorSample, Values: []string{"0.5"}}},
			want: []string{},
		},
		{
			name: "and branch collects all keys",
			f: InvestigationFilter{Filter: &FilterNode{
				And: []FilterNode{
					{Field: "CloudProvider", Operator: OperatorIn, Values: []string{"aws"}},
					{Field: "ClusterState", Operator: OperatorIn, Values: []string{"ready"}},
				},
			}},
			want: []string{"CloudProvider", "ClusterState"},
		},
		{
			name: "nested tree collects all keys",
			f: InvestigationFilter{Filter: &FilterNode{
				And: []FilterNode{
					{Field: "CloudProvider", Operator: OperatorIn, Values: []string{"aws"}},
					{Or: []FilterNode{
						{Field: "ClusterID", Operator: OperatorIn, Values: []string{"abc"}},
						{Field: "OrganizationID", Operator: OperatorIn, Values: []string{"org"}},
						{Operator: OperatorSample, Values: []string{"0.5"}},
					}},
				},
			}},
			want: []string{"CloudProvider", "ClusterID", "OrganizationID"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.f.Keys()
			if len(got) != len(tt.want) {
				t.Fatalf("Keys() = %v, want %v", got, tt.want)
			}
			for i := range tt.want {
				if got[i] != tt.want[i] {
					t.Errorf("Keys()[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestResolveAllFields(t *testing.T) {
	ctx := &types.FilterContext{
		ClusterID:      "cid",
		ClusterName:    "cname",
		OrganizationID: "oid",
		OwnerID:        "uid",
		OwnerEmail:     "e@r.com",
		CloudProvider:  "aws",
		HCP:            true,
		ClusterState:   "ready",
		AlertName:      "alert",
		AlertTitle:     "title",
		ServiceName:    "svc",
	}

	expected := map[string]string{
		"ClusterID":      "cid",
		"ClusterName":    "cname",
		"OrganizationID": "oid",
		"OwnerID":        "uid",
		"OwnerEmail":     "e@r.com",
		"CloudProvider":  "aws",
		"HCP":            "true",
		"ClusterState":   "ready",
		"AlertName":      "alert",
		"AlertTitle":     "title",
		"ServiceName":    "svc",
	}

	for field, want := range expected {
		t.Run(field, func(t *testing.T) {
			got, err := resolveField(field, ctx)
			if err != nil {
				t.Fatalf("resolveField(%q) error = %v", field, err)
			}
			if got != want {
				t.Errorf("resolveField(%q) = %q, want %q", field, got, want)
			}
		})
	}
}

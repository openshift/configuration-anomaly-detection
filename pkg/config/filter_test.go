package config

import (
	"testing"

	"github.com/openshift/configuration-anomaly-detection/pkg/types"
)

func TestChainEntryShouldRun(t *testing.T) { //nolint:maintidx // table-driven test with many cases
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
		entry   *ChainEntry
		ctx     *types.FilterContext
		want    bool
		wantErr bool
	}{
		// --- nil / empty ---
		{
			name:  "nil when passes",
			entry: &ChainEntry{Name: "test"},
			ctx:   baseCtx,
			want:  true,
		},
		{
			name:  "nil when with nil filter node passes",
			entry: &ChainEntry{Name: "test", When: nil},
			ctx:   baseCtx,
			want:  true,
		},
		{
			name: "nil context passes",
			entry: &ChainEntry{
				Name: "test",
				When: &FilterNode{Field: FieldAlertName, Operator: OperatorIn, Values: []string{"chgm"}},
			},
			ctx:  nil,
			want: true,
		},
		// --- single leaf: in ---
		{
			name: "in operator matches",
			entry: &ChainEntry{
				Name: "test",
				When: &FilterNode{Field: FieldCloudProvider, Operator: OperatorIn, Values: []string{"aws", "gcp"}},
			},
			ctx:  baseCtx,
			want: true,
		},
		{
			name: "in operator does not match",
			entry: &ChainEntry{
				Name: "test",
				When: &FilterNode{Field: FieldCloudProvider, Operator: OperatorIn, Values: []string{"gcp", "azure"}},
			},
			ctx:  baseCtx,
			want: false,
		},
		// --- single leaf: notin ---
		{
			name: "notin operator matches",
			entry: &ChainEntry{
				Name: "test",
				When: &FilterNode{Field: FieldCloudProvider, Operator: OperatorNotIn, Values: []string{"gcp"}},
			},
			ctx:  baseCtx,
			want: true,
		},
		{
			name: "notin operator does not match",
			entry: &ChainEntry{
				Name: "test",
				When: &FilterNode{Field: FieldCloudProvider, Operator: OperatorNotIn, Values: []string{"aws"}},
			},
			ctx:  baseCtx,
			want: false,
		},
		// --- single leaf: matches ---
		{
			name: "matches operator matches",
			entry: &ChainEntry{
				Name: "test",
				When: &FilterNode{Field: FieldOwnerEmail, Operator: OperatorMatches, Values: []string{".*@redhat\\.com$"}},
			},
			ctx:  baseCtx,
			want: true,
		},
		{
			name: "matches operator does not match",
			entry: &ChainEntry{
				Name: "test",
				When: &FilterNode{Field: FieldOwnerEmail, Operator: OperatorMatches, Values: []string{".*@ibm\\.com$"}},
			},
			ctx:  baseCtx,
			want: false,
		},
		{
			name: "matches with multiple patterns matches second",
			entry: &ChainEntry{
				Name: "test",
				When: &FilterNode{Field: FieldOwnerEmail, Operator: OperatorMatches, Values: []string{".*@ibm\\.com$", ".*@redhat\\.com$"}},
			},
			ctx:  baseCtx,
			want: true,
		},
		// --- single leaf: notmatches ---
		{
			name: "notmatches operator matches (no regex match = true)",
			entry: &ChainEntry{
				Name: "test",
				When: &FilterNode{Field: FieldOwnerEmail, Operator: OperatorNotMatches, Values: []string{".*@ibm\\.com$"}},
			},
			ctx:  baseCtx,
			want: true,
		},
		{
			name: "notmatches operator does not match (regex matches = false)",
			entry: &ChainEntry{
				Name: "test",
				When: &FilterNode{Field: FieldOwnerEmail, Operator: OperatorNotMatches, Values: []string{".*@redhat\\.com$"}},
			},
			ctx:  baseCtx,
			want: false,
		},
		// --- AND branch ---
		{
			name: "AND all pass",
			entry: &ChainEntry{
				Name: "test",
				When: &FilterNode{
					And: []FilterNode{
						{Field: FieldCloudProvider, Operator: OperatorIn, Values: []string{"aws"}},
						{Field: FieldClusterState, Operator: OperatorIn, Values: []string{"ready"}},
						{Field: FieldAlertName, Operator: OperatorIn, Values: []string{"ClusterHasGoneMissing", "cpd"}},
					},
				},
			},
			ctx:  baseCtx,
			want: true,
		},
		{
			name: "AND one fails",
			entry: &ChainEntry{
				Name: "test",
				When: &FilterNode{
					And: []FilterNode{
						{Field: FieldCloudProvider, Operator: OperatorIn, Values: []string{"aws"}},
						{Field: FieldClusterState, Operator: OperatorIn, Values: []string{"uninstalling"}},
					},
				},
			},
			ctx:  baseCtx,
			want: false,
		},
		// --- OR branch ---
		{
			name: "OR one matches",
			entry: &ChainEntry{
				Name: "test",
				When: &FilterNode{
					Or: []FilterNode{
						{Field: FieldClusterID, Operator: OperatorIn, Values: []string{"abc-123"}},
						{Field: FieldClusterID, Operator: OperatorIn, Values: []string{"other"}},
					},
				},
			},
			ctx:  baseCtx,
			want: true,
		},
		{
			name: "OR none match",
			entry: &ChainEntry{
				Name: "test",
				When: &FilterNode{
					Or: []FilterNode{
						{Field: FieldClusterID, Operator: OperatorIn, Values: []string{"other1"}},
						{Field: FieldClusterID, Operator: OperatorIn, Values: []string{"other2"}},
					},
				},
			},
			ctx:  baseCtx,
			want: false,
		},
		{
			name: "OR second matches",
			entry: &ChainEntry{
				Name: "test",
				When: &FilterNode{
					Or: []FilterNode{
						{Field: FieldClusterID, Operator: OperatorIn, Values: []string{"no-match"}},
						{Field: FieldOrganizationID, Operator: OperatorIn, Values: []string{"org-456"}},
					},
				},
			},
			ctx:  baseCtx,
			want: true,
		},
		// --- nested AND + OR ---
		{
			name: "AND+OR both pass",
			entry: &ChainEntry{
				Name: "test",
				When: &FilterNode{
					And: []FilterNode{
						{Field: FieldCloudProvider, Operator: OperatorIn, Values: []string{"aws"}},
						{Or: []FilterNode{
							{Field: FieldClusterID, Operator: OperatorIn, Values: []string{"abc-123"}},
						}},
					},
				},
			},
			ctx:  baseCtx,
			want: true,
		},
		{
			name: "AND+OR AND fails",
			entry: &ChainEntry{
				Name: "test",
				When: &FilterNode{
					And: []FilterNode{
						{Field: FieldCloudProvider, Operator: OperatorIn, Values: []string{"gcp"}},
						{Or: []FilterNode{
							{Field: FieldClusterID, Operator: OperatorIn, Values: []string{"abc-123"}},
						}},
					},
				},
			},
			ctx:  baseCtx,
			want: false,
		},
		{
			name: "AND+OR OR fails",
			entry: &ChainEntry{
				Name: "test",
				When: &FilterNode{
					And: []FilterNode{
						{Field: FieldCloudProvider, Operator: OperatorIn, Values: []string{"aws"}},
						{Or: []FilterNode{
							{Field: FieldClusterID, Operator: OperatorIn, Values: []string{"no-match"}},
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
			entry: &ChainEntry{
				Name: "test",
				When: &FilterNode{
					And: []FilterNode{
						{Field: FieldCloudProvider, Operator: OperatorIn, Values: []string{"aws"}},
						{Or: []FilterNode{
							{And: []FilterNode{
								{Field: FieldClusterID, Operator: OperatorIn, Values: []string{"abc-123"}},
								{Field: FieldClusterState, Operator: OperatorIn, Values: []string{"ready"}},
							}},
							{Field: FieldOrganizationID, Operator: OperatorIn, Values: []string{"other-org"}},
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
			entry: &ChainEntry{
				Name: "test",
				When: &FilterNode{Field: FieldHCP, Operator: OperatorIn, Values: []string{"false"}},
			},
			ctx:  baseCtx,
			want: true,
		},
		{
			name: "HCP bool field true",
			entry: &ChainEntry{
				Name: "test",
				When: &FilterNode{Field: FieldHCP, Operator: OperatorIn, Values: []string{"true"}},
			},
			ctx:  &types.FilterContext{HCP: true},
			want: true,
		},
		{
			name: "OwnerEmail field",
			entry: &ChainEntry{
				Name: "test",
				When: &FilterNode{Field: FieldOwnerEmail, Operator: OperatorIn, Values: []string{"user@redhat.com"}},
			},
			ctx:  baseCtx,
			want: true,
		},
		{
			name: "OrganizationID field",
			entry: &ChainEntry{
				Name: "test",
				When: &FilterNode{Field: FieldOrganizationID, Operator: OperatorIn, Values: []string{"org-456"}},
			},
			ctx:  baseCtx,
			want: true,
		},
		{
			name: "ServiceName field",
			entry: &ChainEntry{
				Name: "test",
				When: &FilterNode{Field: FieldServiceName, Operator: OperatorIn, Values: []string{"prod-osd"}},
			},
			ctx:  baseCtx,
			want: true,
		},
		{
			name: "empty context field does not match in",
			entry: &ChainEntry{
				Name: "test",
				When: &FilterNode{Field: FieldOwnerEmail, Operator: OperatorIn, Values: []string{"user@redhat.com"}},
			},
			ctx:  &types.FilterContext{},
			want: false,
		},
		{
			name: "empty context field matches notin",
			entry: &ChainEntry{
				Name: "test",
				When: &FilterNode{Field: FieldOwnerEmail, Operator: OperatorNotIn, Values: []string{"user@redhat.com"}},
			},
			ctx:  &types.FilterContext{},
			want: true,
		},
		// --- sample operator ---
		{
			name: "sample 1.0 always passes",
			entry: &ChainEntry{
				Name: "test",
				When: &FilterNode{Operator: OperatorSample, Values: []string{"1.0"}},
			},
			ctx:  baseCtx,
			want: true,
		},
		{
			name: "sample 0 always fails",
			entry: &ChainEntry{
				Name: "test",
				When: &FilterNode{Operator: OperatorSample, Values: []string{"0"}},
			},
			ctx:  baseCtx,
			want: false,
		},
		// --- sample with exemption pattern ---
		{
			name: "sample exemption: redhat email bypasses sampling",
			entry: &ChainEntry{
				Name: "test",
				When: &FilterNode{
					Or: []FilterNode{
						{Field: FieldOwnerEmail, Operator: OperatorNotMatches, Values: []string{".*@redhat\\.com$"}},
						{Operator: OperatorSample, Values: []string{"1.0"}},
					},
				},
			},
			ctx:  baseCtx,
			want: true, // notmatches fails (is redhat), but sample 1.0 passes via OR
		},
		{
			name: "sample exemption: non-redhat email passes via notmatches",
			entry: &ChainEntry{
				Name: "test",
				When: &FilterNode{
					Or: []FilterNode{
						{Field: FieldOwnerEmail, Operator: OperatorNotMatches, Values: []string{".*@redhat\\.com$"}},
						{Operator: OperatorSample, Values: []string{"0"}},
					},
				},
			},
			ctx:  &types.FilterContext{OwnerEmail: "user@example.com"},
			want: true, // notmatches passes (not redhat), short-circuits OR
		},
		{
			name: "sample exemption: redhat email with sample 0 fails",
			entry: &ChainEntry{
				Name: "test",
				When: &FilterNode{
					Or: []FilterNode{
						{Field: FieldOwnerEmail, Operator: OperatorNotMatches, Values: []string{".*@redhat\\.com$"}},
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
			entry: &ChainEntry{
				Name: "test",
				When: &FilterNode{Field: "UnknownField", Operator: OperatorIn, Values: []string{"x"}},
			},
			ctx:     baseCtx,
			wantErr: true,
		},
		{
			name: "unsupported operator returns error",
			entry: &ChainEntry{
				Name: "test",
				When: &FilterNode{Field: FieldCloudProvider, Operator: "equals", Values: []string{"aws"}},
			},
			ctx:     baseCtx,
			wantErr: true,
		},
		{
			name: "error in AND child propagates",
			entry: &ChainEntry{
				Name: "test",
				When: &FilterNode{
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
			entry: &ChainEntry{
				Name: "test",
				When: &FilterNode{
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
			got, reason, err := tt.entry.ShouldRun(tt.ctx)
			if (err != nil) != tt.wantErr {
				t.Errorf("ShouldRun() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("ShouldRun() = %v, want %v (reason: %s)", got, tt.want, reason)
			}
		})
	}
}

func TestInvestigationConfigShouldRun(t *testing.T) {
	baseCtx := &types.FilterContext{
		ClusterID:      "abc-123",
		OrganizationID: "org-456",
		CloudProvider:  "aws",
	}

	tests := []struct {
		name    string
		ic      *InvestigationConfig
		ctx     *types.FilterContext
		want    bool
		wantErr bool
	}{
		{
			name: "nil when passes",
			ic:   &InvestigationConfig{AlertTitle: "Test", When: nil},
			ctx:  baseCtx,
			want: true,
		},
		{
			name: "nil context passes",
			ic: &InvestigationConfig{
				AlertTitle: "Test",
				When:       &FilterNode{Field: FieldCloudProvider, Operator: OperatorIn, Values: []string{"gcp"}},
			},
			ctx:  nil,
			want: true,
		},
		{
			name: "chain-level filter passes",
			ic: &InvestigationConfig{
				AlertTitle: "Test",
				When:       &FilterNode{Field: FieldCloudProvider, Operator: OperatorIn, Values: []string{"aws"}},
			},
			ctx:  baseCtx,
			want: true,
		},
		{
			name: "chain-level filter blocks",
			ic: &InvestigationConfig{
				AlertTitle: "Test",
				When:       &FilterNode{Field: FieldOrganizationID, Operator: OperatorNotIn, Values: []string{"org-456"}},
			},
			ctx:  baseCtx,
			want: false,
		},
		{
			name: "chain-level filter error propagates",
			ic: &InvestigationConfig{
				AlertTitle: "Test",
				When:       &FilterNode{Field: "BadField", Operator: OperatorIn, Values: []string{"x"}},
			},
			ctx:     baseCtx,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, reason, err := tt.ic.ShouldRun(tt.ctx)
			if (err != nil) != tt.wantErr {
				t.Errorf("ShouldRun() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("ShouldRun() = %v, want %v (reason: %s)", got, tt.want, reason)
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
			node:    FilterNode{Field: FieldAlertName, Operator: OperatorIn, Values: []string{"chgm"}},
			wantErr: false,
		},
		{
			name:    "valid notin leaf",
			node:    FilterNode{Field: FieldCloudProvider, Operator: OperatorNotIn, Values: []string{"gcp"}},
			wantErr: false,
		},
		{
			name:    "valid matches leaf",
			node:    FilterNode{Field: FieldOwnerEmail, Operator: OperatorMatches, Values: []string{".*@redhat\\.com$"}},
			wantErr: false,
		},
		{
			name:    "valid notmatches leaf",
			node:    FilterNode{Field: FieldOwnerEmail, Operator: OperatorNotMatches, Values: []string{".*@redhat\\.com$"}},
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
					{Field: FieldAlertName, Operator: OperatorIn, Values: []string{"chgm"}},
				},
			},
			wantErr: false,
		},
		{
			name: "valid or branch",
			node: FilterNode{
				Or: []FilterNode{
					{Field: FieldAlertName, Operator: OperatorIn, Values: []string{"chgm"}},
				},
			},
			wantErr: false,
		},
		// --- invalid: mutual exclusivity ---
		{
			name: "both 'and' and 'or'",
			node: FilterNode{
				And: []FilterNode{{Field: FieldAlertName, Operator: OperatorIn, Values: []string{"a"}}},
				Or:  []FilterNode{{Field: FieldAlertName, Operator: OperatorIn, Values: []string{"b"}}},
			},
			wantErr: true,
		},
		{
			name: "branch with operator",
			node: FilterNode{
				And:      []FilterNode{{Field: FieldAlertName, Operator: OperatorIn, Values: []string{"a"}}},
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
			node:    FilterNode{Field: FieldAlertName, Operator: OperatorIn, Values: []string{}},
			wantErr: true,
		},
		{
			name:    "in with nil values",
			node:    FilterNode{Field: FieldAlertName, Operator: OperatorIn},
			wantErr: true,
		},
		{
			name:    "unsupported operator",
			node:    FilterNode{Field: FieldAlertName, Operator: "equals", Values: []string{"x"}},
			wantErr: true,
		},
		{
			name:    "matches with invalid regex",
			node:    FilterNode{Field: FieldOwnerEmail, Operator: OperatorMatches, Values: []string{"[invalid"}},
			wantErr: true,
		},
		{
			name:    "notmatches with invalid regex",
			node:    FilterNode{Field: FieldOwnerEmail, Operator: OperatorNotMatches, Values: []string{"[invalid"}},
			wantErr: true,
		},
		{
			name:    "matches without field",
			node:    FilterNode{Operator: OperatorMatches, Values: []string{".*"}},
			wantErr: true,
		},
		{
			name:    "sample with field",
			node:    FilterNode{Field: FieldCloudProvider, Operator: OperatorSample, Values: []string{"0.5"}},
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

func TestChainEntryKeys(t *testing.T) {
	tests := []struct {
		name  string
		entry ChainEntry
		want  []string
	}{
		{
			name:  "nil when",
			entry: ChainEntry{Name: "test"},
			want:  []string{},
		},
		{
			name:  "single leaf",
			entry: ChainEntry{Name: "test", When: &FilterNode{Field: FieldCloudProvider, Operator: OperatorIn, Values: []string{"aws"}}},
			want:  []string{FieldCloudProvider},
		},
		{
			name:  "sample leaf has no keys",
			entry: ChainEntry{Name: "test", When: &FilterNode{Operator: OperatorSample, Values: []string{"0.5"}}},
			want:  []string{},
		},
		{
			name: "and branch collects all keys",
			entry: ChainEntry{Name: "test", When: &FilterNode{
				And: []FilterNode{
					{Field: FieldCloudProvider, Operator: OperatorIn, Values: []string{"aws"}},
					{Field: FieldClusterState, Operator: OperatorIn, Values: []string{"ready"}},
				},
			}},
			want: []string{FieldCloudProvider, FieldClusterState},
		},
		{
			name: "nested tree collects all keys",
			entry: ChainEntry{Name: "test", When: &FilterNode{
				And: []FilterNode{
					{Field: FieldCloudProvider, Operator: OperatorIn, Values: []string{"aws"}},
					{Or: []FilterNode{
						{Field: FieldClusterID, Operator: OperatorIn, Values: []string{"abc"}},
						{Field: FieldOrganizationID, Operator: OperatorIn, Values: []string{"org"}},
						{Operator: OperatorSample, Values: []string{"0.5"}},
					}},
				},
			}},
			want: []string{FieldCloudProvider, FieldClusterID, FieldOrganizationID},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.entry.Keys()
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
		FieldClusterID:      "cid",
		FieldClusterName:    "cname",
		FieldOrganizationID: "oid",
		FieldOwnerID:        "uid",
		FieldOwnerEmail:     "e@r.com",
		FieldCloudProvider:  "aws",
		FieldHCP:            "true",
		FieldClusterState:   "ready",
		FieldAlertName:      "alert",
		FieldAlertTitle:     "title",
		FieldServiceName:    "svc",
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

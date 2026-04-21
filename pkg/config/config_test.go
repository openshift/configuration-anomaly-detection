package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

const testMustgatherFilterYAML = `
filters:
  - investigation: mustgather
    filter:
      field: CloudProvider
      operator: in
      values: ["aws"]
`

var testInvestigations = []string{
	"aiassisted",
	"Cluster Has Gone Missing (CHGM)",
	"clustermonitoringerrorbudgetburn",
	"ClusterProvisioningDelay",
	"etcddatabasequotalowspace",
	"insightsoperatordown",
	"upgradeconfigsyncfailureover4hr",
	"machinehealthcheckunterminatedshortcircuitsre",
	"restartcontrolplane",
	"cannotretrieveupdatessre",
	"mustgather",
}

func TestParseConfig(t *testing.T) { //nolint:maintidx,gocyclo // table-driven test with many cases
	tests := []struct {
		name    string
		yaml    string
		wantErr bool
		check   func(t *testing.T, cfg *Config)
	}{
		{
			name: "valid config with one filter",
			yaml: testMustgatherFilterYAML,
			check: func(t *testing.T, cfg *Config) { //nolint:thelper // not a helper, inline check
				if len(cfg.Filters) != 1 {
					t.Fatalf("expected 1 filter, got %d", len(cfg.Filters))
				}
				if cfg.Filters[0].Investigation != "mustgather" {
					t.Errorf("expected investigation mustgather, got %q", cfg.Filters[0].Investigation)
				}
				if cfg.Filters[0].Filter == nil {
					t.Fatal("expected filter node, got nil")
				}
			},
		},
		{
			name: "valid config with multiple filters",
			yaml: `
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
  - investigation: etcddatabasequotalowspace
    filter:
      field: HCP
      operator: in
      values: ["false"]
`,
			check: func(t *testing.T, cfg *Config) { //nolint:thelper // not a helper, inline check
				if len(cfg.Filters) != 2 {
					t.Fatalf("expected 2 filters, got %d", len(cfg.Filters))
				}
				f := cfg.GetFilter("mustgather")
				if f == nil || f.Filter == nil {
					t.Fatal("expected filter for mustgather")
				}
				if len(f.Filter.And) != 2 {
					t.Errorf("mustgather: expected 2 AND children, got %d", len(f.Filter.And))
				}
				f = cfg.GetFilter("etcddatabasequotalowspace")
				if f == nil || f.Filter == nil {
					t.Fatal("expected filter for etcddatabasequotalowspace")
				}
				if f.Filter.Field != "HCP" {
					t.Errorf("etcddatabasequotalowspace: expected field HCP, got %q", f.Filter.Field)
				}
			},
		},
		{
			name: "empty filters list is valid",
			yaml: `
filters: []
`,
			check: func(t *testing.T, cfg *Config) { //nolint:thelper // not a helper, inline check
				if len(cfg.Filters) != 0 {
					t.Fatalf("expected 0 filters, got %d", len(cfg.Filters))
				}
			},
		},
		{
			name: "valid config with OR filter",
			yaml: `
filters:
  - investigation: mustgather
    filter:
      or:
        - field: ClusterID
          operator: in
          values: ["abc-123"]
        - field: OrganizationID
          operator: in
          values: ["org-456"]
`,
			check: func(t *testing.T, cfg *Config) { //nolint:thelper // not a helper, inline check
				if len(cfg.Filters) != 1 {
					t.Fatalf("expected 1 filter, got %d", len(cfg.Filters))
				}
				f := cfg.GetFilter("mustgather")
				if f == nil || f.Filter == nil {
					t.Fatal("expected filter for mustgather, got nil")
				}
				if len(f.Filter.Or) != 2 {
					t.Fatalf("expected 2 OR children, got %d", len(f.Filter.Or))
				}
			},
		},
		{
			name: "valid config with AND+OR combined",
			yaml: `
filters:
  - investigation: mustgather
    filter:
      and:
        - field: CloudProvider
          operator: in
          values: ["aws"]
        - or:
            - field: ClusterID
              operator: in
              values: ["abc-123"]
            - field: OrganizationID
              operator: in
              values: ["org-456"]
`,
			check: func(t *testing.T, cfg *Config) { //nolint:thelper // not a helper, inline check
				f := cfg.GetFilter("mustgather")
				if f == nil || f.Filter == nil {
					t.Fatal("expected filter for mustgather, got nil")
				}
				if len(f.Filter.And) != 2 {
					t.Errorf("expected 2 AND children, got %d", len(f.Filter.And))
				}
				if len(f.Filter.And[1].Or) != 2 {
					t.Errorf("expected 2 OR children in second AND child, got %d", len(f.Filter.And[1].Or))
				}
			},
		},
		{
			name: "invalid filter with bad field",
			yaml: `
filters:
  - investigation: mustgather
    filter:
      field: BadField
      operator: in
      values: ["x"]
`,
			wantErr: true,
		},
		{
			name: "unknown investigation name",
			yaml: `
filters:
  - investigation: nonexistent
    filter:
      field: CloudProvider
      operator: in
      values: ["aws"]
`,
			wantErr: true,
		},
		{
			name: "empty investigation name",
			yaml: `
filters:
  - investigation: ""
    filter:
      field: CloudProvider
      operator: in
      values: ["aws"]
`,
			wantErr: true,
		},
		{
			name: "duplicate investigation name",
			yaml: `
filters:
  - investigation: mustgather
    filter:
      field: CloudProvider
      operator: in
      values: ["aws"]
  - investigation: mustgather
    filter:
      field: ClusterState
      operator: in
      values: ["ready"]
`,
			wantErr: true,
		},
		{
			name: "invalid filter field name",
			yaml: `
filters:
  - investigation: mustgather
    filter:
      field: BadFieldName
      operator: in
      values: ["aws"]
`,
			wantErr: true,
		},
		{
			name: "invalid operator",
			yaml: `
filters:
  - investigation: mustgather
    filter:
      field: CloudProvider
      operator: equals
      values: ["aws"]
`,
			wantErr: true,
		},
		{
			name: "empty values",
			yaml: `
filters:
  - investigation: mustgather
    filter:
      field: CloudProvider
      operator: in
      values: []
`,
			wantErr: true,
		},
		{
			name:    "invalid yaml",
			yaml:    `not: [valid: yaml`,
			wantErr: true,
		},
		// --- ai_agent tests ---
		{
			name: "valid ai_agent config",
			yaml: `
ai_agent:
  runtime_arn: "arn:aws:bedrock:us-east-1:123456789012:agent-runtime/test"
  user_id: "cad-agent"
  region: "us-east-1"
  timeout_seconds: 600
  version: "v1.0.0"
  ops_sop_version: "v2.0.0"
  rosa_plugins_version: "v3.0.0"
filters: []
`,
			check: func(t *testing.T, cfg *Config) { //nolint:thelper // not a helper, inline check
				if cfg.AIAgent == nil {
					t.Fatal("expected ai_agent config, got nil")
				}
				if cfg.AIAgent.RuntimeARN != "arn:aws:bedrock:us-east-1:123456789012:agent-runtime/test" {
					t.Errorf("RuntimeARN = %q", cfg.AIAgent.RuntimeARN)
				}
				if cfg.AIAgent.UserID != "cad-agent" {
					t.Errorf("UserID = %q", cfg.AIAgent.UserID)
				}
				if cfg.AIAgent.Region != "us-east-1" {
					t.Errorf("Region = %q", cfg.AIAgent.Region)
				}
				if cfg.AIAgent.TimeoutSeconds != 600 {
					t.Errorf("TimeoutSeconds = %d, want 600", cfg.AIAgent.TimeoutSeconds)
				}
				if cfg.AIAgent.Version != "v1.0.0" {
					t.Errorf("Version = %q", cfg.AIAgent.Version)
				}
			},
		},
		{
			name: "ai_agent with default timeout",
			yaml: `
ai_agent:
  runtime_arn: "arn:test"
  user_id: "user"
  region: "us-east-1"
filters: []
`,
			check: func(t *testing.T, cfg *Config) { //nolint:thelper // not a helper, inline check
				if cfg.AIAgent == nil {
					t.Fatal("expected ai_agent config, got nil")
				}
				if cfg.AIAgent.TimeoutSeconds != 900 {
					t.Errorf("TimeoutSeconds = %d, want 900 (default)", cfg.AIAgent.TimeoutSeconds)
				}
			},
		},
		{
			name: "ai_agent missing runtime_arn",
			yaml: `
ai_agent:
  user_id: "user"
  region: "us-east-1"
filters: []
`,
			wantErr: true,
		},
		{
			name: "ai_agent missing region",
			yaml: `
ai_agent:
  runtime_arn: "arn:test"
  user_id: "user"
filters: []
`,
			wantErr: true,
		},
		{
			name: "ai_agent missing user_id",
			yaml: `
ai_agent:
  runtime_arn: "arn:test"
  region: "us-east-1"
filters: []
`,
			wantErr: true,
		},
		{
			name: "config without ai_agent is valid",
			yaml: testMustgatherFilterYAML,
			check: func(t *testing.T, cfg *Config) { //nolint:thelper // not a helper, inline check
				if cfg.AIAgent != nil {
					t.Errorf("expected nil ai_agent, got %+v", cfg.AIAgent)
				}
			},
		},
		{
			name: "aiassisted filter without ai_agent is invalid",
			yaml: `
filters:
  - investigation: aiassisted
    filter:
      or:
        - field: ClusterID
          operator: in
          values: ["cluster-1"]
`,
			wantErr: true,
		},
		// --- sample operator tests ---
		{
			name: "valid sample operator",
			yaml: `
filters:
  - investigation: mustgather
    filter:
      operator: sample
      values: ["0.10"]
`,
			check: func(t *testing.T, cfg *Config) { //nolint:thelper // not a helper, inline check
				f := cfg.GetFilter("mustgather")
				if f == nil || f.Filter == nil {
					t.Fatal("expected filter for mustgather, got nil")
				}
				if f.Filter.Operator != OperatorSample {
					t.Errorf("expected operator sample, got %q", f.Filter.Operator)
				}
			},
		},
		{
			name: "sample rate 0 is valid",
			yaml: `
filters:
  - investigation: mustgather
    filter:
      operator: sample
      values: ["0"]
`,
			check: func(t *testing.T, cfg *Config) { //nolint:thelper // not a helper, inline check
				f := cfg.GetFilter("mustgather")
				if f == nil || f.Filter == nil {
					t.Fatal("expected filter for mustgather, got nil")
				}
			},
		},
		{
			name: "sample rate 1 is valid",
			yaml: `
filters:
  - investigation: mustgather
    filter:
      operator: sample
      values: ["1"]
`,
			check: func(t *testing.T, cfg *Config) { //nolint:thelper // not a helper, inline check
				f := cfg.GetFilter("mustgather")
				if f == nil || f.Filter == nil {
					t.Fatal("expected filter for mustgather, got nil")
				}
			},
		},
		{
			name: "sample rate negative is invalid",
			yaml: `
filters:
  - investigation: mustgather
    filter:
      operator: sample
      values: ["-0.1"]
`,
			wantErr: true,
		},
		{
			name: "sample rate greater than 1 is invalid",
			yaml: `
filters:
  - investigation: mustgather
    filter:
      operator: sample
      values: ["1.5"]
`,
			wantErr: true,
		},
		{
			name: "no filter leaves it nil",
			yaml: `
filters:
  - investigation: mustgather
`,
			check: func(t *testing.T, cfg *Config) { //nolint:thelper // not a helper, inline check
				f := cfg.GetFilter("mustgather")
				if f == nil {
					t.Fatal("expected filter for mustgather, got nil")
				}
				if f.Filter != nil {
					t.Errorf("expected nil filter tree, got %+v", f.Filter)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := ParseConfig([]byte(tt.yaml), testInvestigations)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseConfig() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && tt.check != nil {
				tt.check(t, cfg)
			}
		})
	}
}

func TestGetFilter(t *testing.T) {
	cfg, err := ParseConfig([]byte(testMustgatherFilterYAML), testInvestigations)
	if err != nil {
		t.Fatalf("ParseConfig() error = %v", err)
	}

	// Configured investigation returns its filter.
	f := cfg.GetFilter("mustgather")
	if f == nil {
		t.Fatal("expected filter for mustgather, got nil")
	}
	if f.Filter == nil {
		t.Fatal("expected filter tree, got nil")
	}
	if f.Filter.Field != "CloudProvider" {
		t.Fatalf("expected field CloudProvider, got %q", f.Filter.Field)
	}

	// Unconfigured investigation returns nil (always runs).
	f = cfg.GetFilter("etcddatabasequotalowspace")
	if f != nil {
		t.Fatalf("expected nil filter for unconfigured investigation, got %v", f)
	}

	// Nil config returns nil.
	var nilCfg *Config
	f = nilCfg.GetFilter("mustgather")
	if f != nil {
		t.Fatalf("expected nil filter from nil config, got %v", f)
	}
}

func TestGetAIAgentConfig(t *testing.T) {
	// nil config returns nil
	var nilCfg *Config
	if nilCfg.GetAIAgentConfig() != nil {
		t.Fatal("expected nil from nil config")
	}

	// config without ai_agent returns nil
	cfg := &Config{}
	if cfg.GetAIAgentConfig() != nil {
		t.Fatal("expected nil when ai_agent not set")
	}

	// config with ai_agent returns it
	cfg = &Config{AIAgent: &AIAgentConfig{RuntimeARN: "arn:test"}}
	got := cfg.GetAIAgentConfig()
	if got == nil || got.RuntimeARN != "arn:test" {
		t.Fatalf("expected ai_agent config, got %v", got)
	}
}

func TestAIAgentConfigGetTimeout(t *testing.T) {
	c := &AIAgentConfig{TimeoutSeconds: 300}
	got := c.GetTimeout()
	want := 5 * time.Minute
	if got != want {
		t.Errorf("GetTimeout() = %v, want %v", got, want)
	}
}

func TestLoadConfig(t *testing.T) {
	t.Run("env var not set returns nil", func(t *testing.T) {
		t.Setenv(ConfigEnvVar, "")
		cfg, err := LoadConfig("", testInvestigations)
		if err != nil {
			t.Fatalf("LoadConfig() error = %v", err)
		}
		if cfg != nil {
			t.Fatal("expected nil config when env var is not set")
		}
	})

	t.Run("valid file loads successfully", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "config.yaml")
		if err := os.WriteFile(path, []byte(testMustgatherFilterYAML), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Setenv(ConfigEnvVar, path)

		cfg, err := LoadConfig("", testInvestigations)
		if err != nil {
			t.Fatalf("LoadConfig() error = %v", err)
		}
		if cfg == nil || len(cfg.Filters) != 1 {
			t.Fatal("expected config with 1 filter")
		}
	})

	t.Run("nonexistent file returns error", func(t *testing.T) {
		t.Setenv(ConfigEnvVar, "/nonexistent/path.yaml")
		_, err := LoadConfig("", testInvestigations)
		if err == nil {
			t.Fatal("expected error for nonexistent file")
		}
	})

	t.Run("invalid content returns error", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "bad.yaml")
		if err := os.WriteFile(path, []byte(`filters: [{investigation: fake}]`), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Setenv(ConfigEnvVar, path)

		_, err := LoadConfig("", testInvestigations)
		if err == nil {
			t.Fatal("expected error for invalid investigation name")
		}
	})

	t.Run("path override takes precedence over env var", func(t *testing.T) {
		// Set env var to a nonexistent file — if it were used, LoadConfig would fail.
		t.Setenv(ConfigEnvVar, "/nonexistent/should-not-be-used.yaml")

		path := filepath.Join(t.TempDir(), "override.yaml")
		if err := os.WriteFile(path, []byte(testMustgatherFilterYAML), 0o600); err != nil {
			t.Fatal(err)
		}

		cfg, err := LoadConfig(path, testInvestigations)
		if err != nil {
			t.Fatalf("LoadConfig() error = %v", err)
		}
		if cfg == nil || len(cfg.Filters) != 1 {
			t.Fatal("expected config with 1 filter from override path")
		}
	})

	t.Run("empty override falls back to env var", func(t *testing.T) {
		content := `
filters:
  - investigation: mustgather
`
		path := filepath.Join(t.TempDir(), "envvar.yaml")
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Setenv(ConfigEnvVar, path)

		cfg, err := LoadConfig("", testInvestigations)
		if err != nil {
			t.Fatalf("LoadConfig() error = %v", err)
		}
		if cfg == nil || len(cfg.Filters) != 1 {
			t.Fatal("expected config with 1 filter from env var path")
		}
	})
}

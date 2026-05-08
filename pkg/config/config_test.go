package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

const testMustgatherChainYAML = `
investigations:
  - alert_title: "TestAlert"
    chain:
      - mustgather
`

var testInvestigations = []string{
	"precheck",
	"ccam",
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
	"ocmagentresponsefailure",
	"describenodes",
}

func TestParseConfig(t *testing.T) { //nolint:maintidx,gocyclo // table-driven test with many cases
	tests := []struct {
		name    string
		yaml    string
		wantErr bool
		check   func(t *testing.T, cfg *Config)
	}{
		{
			name: "valid config with one chain",
			yaml: testMustgatherChainYAML,
			check: func(t *testing.T, cfg *Config) { //nolint:thelper // not a helper, inline check
				if len(cfg.Investigations) != 1 {
					t.Fatalf("expected 1 investigation, got %d", len(cfg.Investigations))
				}
				if cfg.Investigations[0].AlertTitle != "TestAlert" {
					t.Errorf("expected alert_title TestAlert, got %q", cfg.Investigations[0].AlertTitle)
				}
				if len(cfg.Investigations[0].Chain) != 1 {
					t.Fatalf("expected 1 chain entry, got %d", len(cfg.Investigations[0].Chain))
				}
				if cfg.Investigations[0].Chain[0].Name != "mustgather" {
					t.Errorf("expected chain entry mustgather, got %q", cfg.Investigations[0].Chain[0].Name)
				}
			},
		},
		{
			name: "valid config with multiple chain entries and bare strings",
			yaml: `
investigations:
  - alert_title: "has gone missing"
    chain:
      - precheck
      - ccam
      - "Cluster Has Gone Missing (CHGM)"
`,
			check: func(t *testing.T, cfg *Config) { //nolint:thelper // not a helper, inline check
				if len(cfg.Investigations[0].Chain) != 3 {
					t.Fatalf("expected 3 chain entries, got %d", len(cfg.Investigations[0].Chain))
				}
				if cfg.Investigations[0].Chain[0].Name != "precheck" {
					t.Errorf("chain[0] = %q, want precheck", cfg.Investigations[0].Chain[0].Name)
				}
				if cfg.Investigations[0].Chain[2].Name != "Cluster Has Gone Missing (CHGM)" {
					t.Errorf("chain[2] = %q", cfg.Investigations[0].Chain[2].Name)
				}
			},
		},
		{
			name: "chain entry with when filter (object form)",
			yaml: `
investigations:
  - alert_title: "has gone missing"
    chain:
      - precheck
      - name: mustgather
        when:
          operator: sample
          values: ["0.10"]
`,
			check: func(t *testing.T, cfg *Config) { //nolint:thelper // not a helper, inline check
				entry := cfg.Investigations[0].Chain[1]
				if entry.Name != "mustgather" {
					t.Errorf("entry name = %q, want mustgather", entry.Name)
				}
				if entry.When == nil {
					t.Fatal("expected when filter on mustgather entry")
				}
				if entry.When.Operator != OperatorSample {
					t.Errorf("operator = %q, want sample", entry.When.Operator)
				}
			},
		},
		{
			name: "chain-level when filter",
			yaml: `
investigations:
  - alert_title: "ClusterProvisioningDelay -"
    when:
      field: OrganizationID
      operator: notin
      values: ["org-exclude"]
    chain:
      - precheck
      - ccam
      - ClusterProvisioningDelay
`,
			check: func(t *testing.T, cfg *Config) { //nolint:thelper // not a helper, inline check
				ic := cfg.Investigations[0]
				if ic.When == nil {
					t.Fatal("expected chain-level when filter")
				}
				if ic.When.Field != FieldOrganizationID {
					t.Errorf("when field = %q, want OrganizationID", ic.When.Field)
				}
				if ic.When.Operator != OperatorNotIn {
					t.Errorf("when operator = %q, want notin", ic.When.Operator)
				}
			},
		},
		{
			name: "experimental flag",
			yaml: `
investigations:
  - alert_title: "TestExperimental"
    experimental: true
    chain:
      - mustgather
`,
			check: func(t *testing.T, cfg *Config) { //nolint:thelper // not a helper, inline check
				if !cfg.Investigations[0].Experimental {
					t.Error("expected experimental=true")
				}
			},
		},
		{
			name: "empty investigations list is valid",
			yaml: `
investigations: []
`,
			check: func(t *testing.T, cfg *Config) { //nolint:thelper // not a helper, inline check
				if len(cfg.Investigations) != 0 {
					t.Fatalf("expected 0 investigations, got %d", len(cfg.Investigations))
				}
			},
		},
		{
			name: "empty chain is invalid",
			yaml: `
investigations:
  - alert_title: "TestAlert"
    chain: []
`,
			wantErr: true,
		},
		{
			name: "empty alert_title is invalid",
			yaml: `
investigations:
  - alert_title: ""
    chain:
      - mustgather
`,
			wantErr: true,
		},
		{
			name: "duplicate alert_title is invalid",
			yaml: `
investigations:
  - alert_title: "TestAlert"
    chain:
      - mustgather
  - alert_title: "TestAlert"
    chain:
      - precheck
`,
			wantErr: true,
		},
		{
			name: "unknown investigation name in chain is invalid",
			yaml: `
investigations:
  - alert_title: "TestAlert"
    chain:
      - nonexistent
`,
			wantErr: true,
		},
		{
			name: "empty chain entry name is invalid",
			yaml: `
investigations:
  - alert_title: "TestAlert"
    chain:
      - name: ""
`,
			wantErr: true,
		},
		{
			name: "invalid when filter field is invalid",
			yaml: `
investigations:
  - alert_title: "TestAlert"
    chain:
      - name: mustgather
        when:
          field: BadField
          operator: in
          values: ["x"]
`,
			wantErr: true,
		},
		{
			name: "invalid chain-level when filter is invalid",
			yaml: `
investigations:
  - alert_title: "TestAlert"
    when:
      field: BadField
      operator: in
      values: ["x"]
    chain:
      - mustgather
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
  invoker_role_arn: "arn:aws:iam::123456789012:role/cad-invoker"
  timeout_seconds: 600
  version: "v1.0.0"
  ops_sop_version: "v2.0.0"
  rosa_plugins_version: "v3.0.0"
investigations:
  - alert_title: "TestAI"
    when:
      field: ClusterID
      operator: in
      values: ["cluster-1"]
    chain:
      - aiassisted
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
  invoker_role_arn: "arn:aws:iam::123456789012:role/cad-invoker"
investigations:
  - alert_title: "TestAI"
    when:
      field: ClusterID
      operator: in
      values: ["cluster-1"]
    chain:
      - aiassisted
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
investigations: []
`,
			wantErr: true,
		},
		{
			name: "ai_agent missing region",
			yaml: `
ai_agent:
  runtime_arn: "arn:test"
  user_id: "user"
investigations: []
`,
			wantErr: true,
		},
		{
			name: "ai_agent missing user_id",
			yaml: `
ai_agent:
  runtime_arn: "arn:test"
  region: "us-east-1"
investigations: []
`,
			wantErr: true,
		},
		{
			name: "ai_agent missing invoker_role_arn",
			yaml: `
ai_agent:
  runtime_arn: "arn:test"
  user_id: "user"
  region: "us-east-1"
filters: []
`,
			wantErr: true,
		},
		{
			name: "config without ai_agent is valid",
			yaml: testMustgatherChainYAML,
			check: func(t *testing.T, cfg *Config) { //nolint:thelper // not a helper, inline check
				if cfg.AIAgent != nil {
					t.Errorf("expected nil ai_agent, got %+v", cfg.AIAgent)
				}
			},
		},
		{
			name: "aiassisted in chain without ai_agent is invalid",
			yaml: `
investigations:
  - alert_title: "TestAI"
    chain:
      - aiassisted
`,
			wantErr: true,
		},
		{
			name: "ai_agent without aiassisted in any chain is valid",
			yaml: `
ai_agent:
  runtime_arn: "arn:test"
  user_id: "user"
  region: "us-east-1"
  invoker_role_arn: "arn:aws:iam::123456789012:role/cad-invoker"
investigations:
  - alert_title: "TestAlert"
    chain:
      - mustgather
`,
			check: func(t *testing.T, cfg *Config) { //nolint:thelper // not a helper, inline check
				if cfg.AIAgent == nil {
					t.Fatal("expected ai_agent config")
				}
			},
		},
		// --- aiassisted filter requirement ---
		{
			name: "aiassisted without any when filter is invalid",
			yaml: `
ai_agent:
  runtime_arn: "arn:test"
  user_id: "user"
  region: "us-east-1"
  invoker_role_arn: "arn:aws:iam::123456789012:role/cad-invoker"
investigations:
  - alert_title: "TestAI"
    chain:
      - precheck
      - aiassisted
`,
			wantErr: true,
		},
		{
			name: "aiassisted with chain-level when is valid",
			yaml: `
ai_agent:
  runtime_arn: "arn:test"
  user_id: "user"
  region: "us-east-1"
  invoker_role_arn: "arn:aws:iam::123456789012:role/cad-invoker"
investigations:
  - alert_title: "TestAI"
    when:
      field: OrganizationID
      operator: in
      values: ["org-1"]
    chain:
      - precheck
      - aiassisted
`,
			check: func(t *testing.T, cfg *Config) { //nolint:thelper // not a helper, inline check
				if cfg.Investigations[0].When == nil {
					t.Fatal("expected chain-level when filter")
				}
			},
		},
		{
			name: "aiassisted with entry-level when is valid",
			yaml: `
ai_agent:
  runtime_arn: "arn:test"
  user_id: "user"
  region: "us-east-1"
  invoker_role_arn: "arn:aws:iam::123456789012:role/cad-invoker"
investigations:
  - alert_title: "TestAI"
    chain:
      - precheck
      - name: aiassisted
        when:
          field: ClusterID
          operator: in
          values: ["cluster-1"]
`,
			check: func(t *testing.T, cfg *Config) { //nolint:thelper // not a helper, inline check
				entry := cfg.Investigations[0].Chain[1]
				if entry.When == nil {
					t.Fatal("expected entry-level when filter on aiassisted")
				}
			},
		},
		// --- sample operator in chain entry ---
		{
			name: "valid sample operator in chain entry",
			yaml: `
investigations:
  - alert_title: "TestAlert"
    chain:
      - name: mustgather
        when:
          operator: sample
          values: ["0.10"]
`,
			check: func(t *testing.T, cfg *Config) { //nolint:thelper // not a helper, inline check
				entry := cfg.Investigations[0].Chain[0]
				if entry.When == nil {
					t.Fatal("expected when filter")
				}
				if entry.When.Operator != OperatorSample {
					t.Errorf("operator = %q, want sample", entry.When.Operator)
				}
			},
		},
		{
			name: "sample rate negative is invalid",
			yaml: `
investigations:
  - alert_title: "TestAlert"
    chain:
      - name: mustgather
        when:
          operator: sample
          values: ["-0.1"]
`,
			wantErr: true,
		},
		{
			name: "sample rate greater than 1 is invalid",
			yaml: `
investigations:
  - alert_title: "TestAlert"
    chain:
      - name: mustgather
        when:
          operator: sample
          values: ["1.5"]
`,
			wantErr: true,
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

func TestGetChain(t *testing.T) {
	cfg, err := ParseConfig([]byte(`
investigations:
  - alert_title: "has gone missing"
    chain:
      - precheck
      - ccam
      - "Cluster Has Gone Missing (CHGM)"
  - alert_title: "ExperimentalAlert"
    experimental: true
    chain:
      - mustgather
`), testInvestigations)
	if err != nil {
		t.Fatalf("ParseConfig() error = %v", err)
	}

	// Matching alert title returns the chain.
	ic := cfg.GetChain("Cluster xyz has gone missing", false)
	if ic == nil {
		t.Fatal("expected chain for 'has gone missing'")
	}
	if ic.AlertTitle != "has gone missing" {
		t.Errorf("AlertTitle = %q", ic.AlertTitle)
	}
	if len(ic.Chain) != 3 {
		t.Fatalf("expected 3 chain entries, got %d", len(ic.Chain))
	}

	// No match returns nil.
	ic = cfg.GetChain("UnknownAlert", false)
	if ic != nil {
		t.Fatalf("expected nil for unmatched alert, got %+v", ic)
	}

	// Experimental chain is hidden when experimentalEnabled=false.
	ic = cfg.GetChain("ExperimentalAlert fired", false)
	if ic != nil {
		t.Fatal("expected nil for experimental chain with experimental=false")
	}

	// Experimental chain is visible when experimentalEnabled=true.
	ic = cfg.GetChain("ExperimentalAlert fired", true)
	if ic == nil {
		t.Fatal("expected chain for experimental alert with experimental=true")
	}

	// Nil config returns nil.
	var nilCfg *Config
	ic = nilCfg.GetChain("has gone missing", false)
	if ic != nil {
		t.Fatalf("expected nil from nil config, got %+v", ic)
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
		if err := os.WriteFile(path, []byte(testMustgatherChainYAML), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Setenv(ConfigEnvVar, path)

		cfg, err := LoadConfig("", testInvestigations)
		if err != nil {
			t.Fatalf("LoadConfig() error = %v", err)
		}
		if cfg == nil || len(cfg.Investigations) != 1 {
			t.Fatal("expected config with 1 investigation")
		}
	})

	t.Run("nonexistent file returns nil config", func(t *testing.T) {
		t.Setenv(ConfigEnvVar, "/nonexistent/path.yaml")
		cfg, err := LoadConfig("", testInvestigations)
		if err != nil {
			t.Fatalf("expected no error for nonexistent file, got: %v", err)
		}
		if cfg != nil {
			t.Fatal("expected nil config for nonexistent file")
		}
	})

	t.Run("invalid content returns error", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "bad.yaml")
		if err := os.WriteFile(path, []byte(`investigations: [{alert_title: "X", chain: [{name: fake}]}]`), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Setenv(ConfigEnvVar, path)

		_, err := LoadConfig("", testInvestigations)
		if err == nil {
			t.Fatal("expected error for invalid investigation name")
		}
	})

	t.Run("path override takes precedence over env var", func(t *testing.T) {
		t.Setenv(ConfigEnvVar, "/nonexistent/should-not-be-used.yaml")

		path := filepath.Join(t.TempDir(), "override.yaml")
		if err := os.WriteFile(path, []byte(testMustgatherChainYAML), 0o600); err != nil {
			t.Fatal(err)
		}

		cfg, err := LoadConfig(path, testInvestigations)
		if err != nil {
			t.Fatalf("LoadConfig() error = %v", err)
		}
		if cfg == nil || len(cfg.Investigations) != 1 {
			t.Fatal("expected config with 1 investigation from override path")
		}
	})

	t.Run("empty override falls back to env var", func(t *testing.T) {
		content := `
investigations:
  - alert_title: "TestAlert"
    chain:
      - mustgather
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
		if cfg == nil || len(cfg.Investigations) != 1 {
			t.Fatal("expected config with 1 investigation from env var path")
		}
	})
}

func TestChainEntryUnmarshal(t *testing.T) {
	yaml := `
investigations:
  - alert_title: "TestAlert"
    chain:
      - precheck
      - name: mustgather
        when:
          operator: sample
          values: ["0.50"]
`
	cfg, err := ParseConfig([]byte(yaml), testInvestigations)
	if err != nil {
		t.Fatalf("ParseConfig() error = %v", err)
	}
	if len(cfg.Investigations[0].Chain) != 2 {
		t.Fatalf("expected 2 chain entries, got %d", len(cfg.Investigations[0].Chain))
	}

	// First entry: bare string
	if cfg.Investigations[0].Chain[0].Name != "precheck" {
		t.Errorf("chain[0].Name = %q, want precheck", cfg.Investigations[0].Chain[0].Name)
	}
	if cfg.Investigations[0].Chain[0].When != nil {
		t.Error("chain[0].When should be nil for bare string entry")
	}

	// Second entry: object with when
	if cfg.Investigations[0].Chain[1].Name != "mustgather" {
		t.Errorf("chain[1].Name = %q, want mustgather", cfg.Investigations[0].Chain[1].Name)
	}
	if cfg.Investigations[0].Chain[1].When == nil {
		t.Fatal("chain[1].When should not be nil")
	}
	if cfg.Investigations[0].Chain[1].When.Operator != OperatorSample {
		t.Errorf("chain[1].When.Operator = %q, want sample", cfg.Investigations[0].Chain[1].When.Operator)
	}
}

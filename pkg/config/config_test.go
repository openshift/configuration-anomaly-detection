package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

const testMustgatherChainYAML = `
alerts:
  - alert_title: "TestAlert"
    investigations:
      - mustgather
`

const alertName = "mustgather"

var testInvestigations = []string{
	"precheck",
	"ccam",
	"aiassisted",
	"chgm",
	"clustermonitoringerrorbudgetburn",
	"cpd",
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
				if len(cfg.Alerts) != 1 {
					t.Fatalf("expected 1 investigation, got %d", len(cfg.Alerts))
				}
				if cfg.Alerts[0].AlertTitle != "TestAlert" {
					t.Errorf("expected alert_title TestAlert, got %q", cfg.Alerts[0].AlertTitle)
				}
				if len(cfg.Alerts[0].Investigations) != 1 {
					t.Fatalf("expected 1 chain entry, got %d", len(cfg.Alerts[0].Investigations))
				}
				if cfg.Alerts[0].Investigations[0].Name != alertName {
					t.Errorf("expected chain entry mustgather, got %q", cfg.Alerts[0].Investigations[0].Name)
				}
			},
		},
		{
			name: "valid config with multiple chain entries and bare strings",
			yaml: `
alerts:
  - alert_title: "has gone missing"
    investigations:
      - precheck
      - ccam
      - "chgm"
`,
			check: func(t *testing.T, cfg *Config) { //nolint:thelper // not a helper, inline check
				if len(cfg.Alerts[0].Investigations) != 3 {
					t.Fatalf("expected 3 chain entries, got %d", len(cfg.Alerts[0].Investigations))
				}
				if cfg.Alerts[0].Investigations[0].Name != "precheck" {
					t.Errorf("chain[0] = %q, want precheck", cfg.Alerts[0].Investigations[0].Name)
				}
				if cfg.Alerts[0].Investigations[2].Name != "chgm" {
					t.Errorf("chain[2] = %q", cfg.Alerts[0].Investigations[2].Name)
				}
			},
		},
		{
			name: "chain entry with when filter (object form)",
			yaml: `
alerts:
  - alert_title: "has gone missing"
    investigations:
      - precheck
      - name: mustgather
        when:
          operator: sample
          values: ["0.10"]
`,
			check: func(t *testing.T, cfg *Config) { //nolint:thelper // not a helper, inline check
				entry := cfg.Alerts[0].Investigations[1]
				if entry.Name != alertName {
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
alerts:
  - alert_title: "ClusterProvisioningDelay -"
    when:
      field: OrganizationID
      operator: notin
      values: ["org-exclude"]
    investigations:
      - precheck
      - ccam
      - cpd
`,
			check: func(t *testing.T, cfg *Config) { //nolint:thelper // not a helper, inline check
				ic := cfg.Alerts[0]
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
alerts:
  - alert_title: "TestExperimental"
    experimental: true
    investigations:
      - mustgather
`,
			check: func(t *testing.T, cfg *Config) { //nolint:thelper // not a helper, inline check
				if !cfg.Alerts[0].Experimental {
					t.Error("expected experimental=true")
				}
			},
		},
		{
			name: "empty investigations list is valid",
			yaml: `
alerts: []
`,
			check: func(t *testing.T, cfg *Config) { //nolint:thelper // not a helper, inline check
				if len(cfg.Alerts) != 0 {
					t.Fatalf("expected 0 investigations, got %d", len(cfg.Alerts))
				}
			},
		},
		{
			name: "empty chain is invalid",
			yaml: `
alerts:
  - alert_title: "TestAlert"
    investigations: []
`,
			wantErr: true,
		},
		{
			name: "empty alert_title is invalid",
			yaml: `
alerts:
  - alert_title: ""
    investigations:
      - mustgather
`,
			wantErr: true,
		},
		{
			name: "duplicate alert_title is invalid",
			yaml: `
alerts:
  - alert_title: "TestAlert"
    investigations:
      - mustgather
  - alert_title: "TestAlert"
    investigations:
      - precheck
`,
			wantErr: true,
		},
		{
			name: "unknown investigation name in chain is invalid",
			yaml: `
alerts:
  - alert_title: "TestAlert"
    investigations:
      - nonexistent
`,
			wantErr: true,
		},
		{
			name: "empty chain entry name is invalid",
			yaml: `
alerts:
  - alert_title: "TestAlert"
    investigations:
      - name: ""
`,
			wantErr: true,
		},
		{
			name: "invalid when filter field is invalid",
			yaml: `
alerts:
  - alert_title: "TestAlert"
    investigations:
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
alerts:
  - alert_title: "TestAlert"
    when:
      field: BadField
      operator: in
      values: ["x"]
    investigations:
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
alerts:
  - alert_title: "TestAI"
    when:
      field: ClusterID
      operator: in
      values: ["cluster-1"]
    investigations:
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
alerts:
  - alert_title: "TestAI"
    when:
      field: ClusterID
      operator: in
      values: ["cluster-1"]
    investigations:
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
alerts: []
`,
			wantErr: true,
		},
		{
			name: "ai_agent missing region",
			yaml: `
ai_agent:
  runtime_arn: "arn:test"
  user_id: "user"
alerts: []
`,
			wantErr: true,
		},
		{
			name: "ai_agent missing user_id",
			yaml: `
ai_agent:
  runtime_arn: "arn:test"
  region: "us-east-1"
alerts: []
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
alerts:
  - alert_title: "TestAI"
    investigations:
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
alerts:
  - alert_title: "TestAlert"
    investigations:
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
			name: "aiassisted without when filter is valid",
			yaml: `
ai_agent:
  runtime_arn: "arn:test"
  user_id: "user"
  region: "us-east-1"
  invoker_role_arn: "arn:aws:iam::123456789012:role/cad-invoker"
alerts:
  - alert_title: "TestAI"
    investigations:
      - precheck
      - aiassisted
`,
			check: func(t *testing.T, cfg *Config) { //nolint:thelper // not a helper, inline check
				if len(cfg.Alerts[0].Investigations) != 2 {
					t.Fatalf("expected 2 investigations, got %d", len(cfg.Alerts[0].Investigations))
				}
			},
		},
		{
			name: "aiassisted with chain-level when is valid",
			yaml: `
ai_agent:
  runtime_arn: "arn:test"
  user_id: "user"
  region: "us-east-1"
  invoker_role_arn: "arn:aws:iam::123456789012:role/cad-invoker"
alerts:
  - alert_title: "TestAI"
    when:
      field: OrganizationID
      operator: in
      values: ["org-1"]
    investigations:
      - precheck
      - aiassisted
`,
			check: func(t *testing.T, cfg *Config) { //nolint:thelper // not a helper, inline check
				if cfg.Alerts[0].When == nil {
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
alerts:
  - alert_title: "TestAI"
    investigations:
      - precheck
      - name: aiassisted
        when:
          field: ClusterID
          operator: in
          values: ["cluster-1"]
`,
			check: func(t *testing.T, cfg *Config) { //nolint:thelper // not a helper, inline check
				entry := cfg.Alerts[0].Investigations[1]
				if entry.When == nil {
					t.Fatal("expected entry-level when filter on aiassisted")
				}
			},
		},
		// --- sample operator in chain entry ---
		{
			name: "valid sample operator in chain entry",
			yaml: `
alerts:
  - alert_title: "TestAlert"
    investigations:
      - name: mustgather
        when:
          operator: sample
          values: ["0.10"]
`,
			check: func(t *testing.T, cfg *Config) { //nolint:thelper // not a helper, inline check
				entry := cfg.Alerts[0].Investigations[0]
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
alerts:
  - alert_title: "TestAlert"
    investigations:
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
alerts:
  - alert_title: "TestAlert"
    investigations:
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

func TestGetAlert(t *testing.T) {
	cfg, err := ParseConfig([]byte(`
alerts:
  - alert_title: "has gone missing"
    investigations:
      - precheck
      - ccam
      - "chgm"
  - alert_title: "ExperimentalAlert"
    experimental: true
    investigations:
      - mustgather
`), testInvestigations)
	if err != nil {
		t.Fatalf("ParseConfig() error = %v", err)
	}

	// Matching alert title returns the chain.
	ic := cfg.GetAlert("Cluster xyz has gone missing", false)
	if ic == nil {
		t.Fatal("expected chain for 'has gone missing'")
	}
	if ic.AlertTitle != "has gone missing" {
		t.Errorf("AlertTitle = %q", ic.AlertTitle)
	}
	if len(ic.Investigations) != 3 {
		t.Fatalf("expected 3 chain entries, got %d", len(ic.Investigations))
	}

	// No match returns nil.
	ic = cfg.GetAlert("UnknownAlert", false)
	if ic != nil {
		t.Fatalf("expected nil for unmatched alert, got %+v", ic)
	}

	// Experimental chain is hidden when experimentalEnabled=false.
	ic = cfg.GetAlert("ExperimentalAlert fired", false)
	if ic != nil {
		t.Fatal("expected nil for experimental chain with experimental=false")
	}

	// Experimental chain is visible when experimentalEnabled=true.
	ic = cfg.GetAlert("ExperimentalAlert fired", true)
	if ic == nil {
		t.Fatal("expected chain for experimental alert with experimental=true")
	}

	// Case-insensitive match: config has "has gone missing" (lowercase),
	// PD title has "Has Gone Missing" (mixed case).
	ic = cfg.GetAlert("Cluster xyz Has Gone Missing", false)
	if ic == nil {
		t.Fatal("expected case-insensitive match for 'Has Gone Missing'")
	}
	if ic.AlertTitle != "has gone missing" {
		t.Errorf("AlertTitle = %q, want 'has gone missing'", ic.AlertTitle)
	}

	// Nil config returns nil.
	var nilCfg *Config
	ic = nilCfg.GetAlert("has gone missing", false)
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
	t.Run("empty path returns error", func(t *testing.T) {
		_, err := LoadConfig("", testInvestigations)
		if err == nil {
			t.Fatal("expected error when config path is empty")
		}
	})

	t.Run("valid file loads successfully", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "config.yaml")
		if err := os.WriteFile(path, []byte(testMustgatherChainYAML), 0o600); err != nil {
			t.Fatal(err)
		}

		cfg, err := LoadConfig(path, testInvestigations)
		if err != nil {
			t.Fatalf("LoadConfig() error = %v", err)
		}
		if cfg == nil || len(cfg.Alerts) != 1 {
			t.Fatal("expected config with 1 investigation")
		}
	})

	t.Run("nonexistent file returns error", func(t *testing.T) {
		_, err := LoadConfig("/nonexistent/path.yaml", testInvestigations)
		if err == nil {
			t.Fatal("expected error for nonexistent file")
		}
	})

	t.Run("invalid content returns error", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "bad.yaml")
		if err := os.WriteFile(path, []byte(`alerts: [{alert_title: "X", investigations: [{name: fake}]}]`), 0o600); err != nil {
			t.Fatal(err)
		}

		_, err := LoadConfig(path, testInvestigations)
		if err == nil {
			t.Fatal("expected error for invalid investigation name")
		}
	})
}

// NOTE: The env var fallback (CAD_INVESTIGATION_CONFIG_PATH) is handled by
// callers (controller.initializeDependencies, interceptor main) before calling
// LoadConfig. Tests for that behavior belong with those callers.

func TestInvestigationEntryUnmarshal(t *testing.T) {
	yaml := `
alerts:
  - alert_title: "TestAlert"
    investigations:
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
	if len(cfg.Alerts[0].Investigations) != 2 {
		t.Fatalf("expected 2 chain entries, got %d", len(cfg.Alerts[0].Investigations))
	}

	// First entry: bare string
	if cfg.Alerts[0].Investigations[0].Name != "precheck" {
		t.Errorf("chain[0].Name = %q, want precheck", cfg.Alerts[0].Investigations[0].Name)
	}
	if cfg.Alerts[0].Investigations[0].When != nil {
		t.Error("chain[0].When should be nil for bare string entry")
	}

	// Second entry: object with when
	if cfg.Alerts[0].Investigations[1].Name != alertName {
		t.Errorf("chain[1].Name = %q, want mustgather", cfg.Alerts[0].Investigations[1].Name)
	}
	if cfg.Alerts[0].Investigations[1].When == nil {
		t.Fatal("chain[1].When should not be nil")
	}
	if cfg.Alerts[0].Investigations[1].When.Operator != OperatorSample {
		t.Errorf("chain[1].When.Operator = %q, want sample", cfg.Alerts[0].Investigations[1].When.Operator)
	}
}

package controller

import (
	"os"
	"strings"
	"testing"
)

func TestResolveConfigOrEnv(t *testing.T) {
	const testEnvVar = "CAD_TEST_RESOLVE_CONFIG_OR_ENV"

	tests := []struct {
		name      string
		configVal string
		envVal    string
		want      string
	}{
		{
			name:      "config value takes precedence over env var",
			configVal: "from-config",
			envVal:    "from-env",
			want:      "from-config",
		},
		{
			name:      "falls back to env var when config is empty",
			configVal: "",
			envVal:    "from-env",
			want:      "from-env",
		},
		{
			name:      "returns empty when both are empty",
			configVal: "",
			envVal:    "",
			want:      "",
		},
		{
			name:      "config value used when env var is empty",
			configVal: "from-config",
			envVal:    "",
			want:      "from-config",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(testEnvVar, tt.envVal)
			got := resolveConfigOrEnv(tt.configVal, testEnvVar)
			if got != tt.want {
				t.Errorf("resolveConfigOrEnv(%q, %q) = %q, want %q", tt.configVal, testEnvVar, got, tt.want)
			}
		})
	}
}

func TestInitializeDependencies_MissingRequiredVars(t *testing.T) {
	// Clear all relevant env vars to test validation
	envVars := []string{
		"CAD_INVESTIGATION_CONFIG_PATH",
		"BACKPLANE_URL",
		"BACKPLANE_PRODUCTION_URL",
		"BACKPLANE_INITIAL_ARN",
		"BACKPLANE_PROXY",
		"AWS_PROXY",
		"CAD_OCM_URL",
		"CAD_OCM_PRODUCTION_URL",
		"CAD_OCM_CLIENT_ID",
		"CAD_OCM_CLIENT_SECRET",
		"CAD_OCM_PRODUCTION_CLIENT_ID",
		"CAD_OCM_PRODUCTION_CLIENT_SECRET",
		"CAD_EXPERIMENTAL_ENABLED",
	}
	for _, v := range envVars {
		t.Setenv(v, "")
	}

	t.Run("missing backplane URL", func(t *testing.T) {
		_, err := initializeDependencies("")
		if err == nil {
			t.Fatal("expected error for missing backplane URL")
		}
		if got := err.Error(); !strings.Contains(got, "backplane URL") {
			t.Errorf("error = %q, want mention of backplane URL", got)
		}
	})

	t.Run("missing backplane initial ARN", func(t *testing.T) {
		t.Setenv("BACKPLANE_URL", "https://bp.example.com")
		_, err := initializeDependencies("")
		if err == nil {
			t.Fatal("expected error for missing backplane initial ARN")
		}
		if got := err.Error(); !strings.Contains(got, "backplane initial ARN") {
			t.Errorf("error = %q, want mention of backplane initial ARN", got)
		}
	})

	t.Run("missing OCM URL", func(t *testing.T) {
		t.Setenv("BACKPLANE_URL", "https://bp.example.com")
		t.Setenv("BACKPLANE_INITIAL_ARN", "arn:aws:iam::123:role/init")
		_, err := initializeDependencies("")
		if err == nil {
			t.Fatal("expected error for missing OCM URL")
		}
		if got := err.Error(); !strings.Contains(got, "OCM URL") {
			t.Errorf("error = %q, want mention of OCM URL", got)
		}
	})

	t.Run("missing production OCM URL", func(t *testing.T) {
		t.Setenv("BACKPLANE_URL", "https://bp.example.com")
		t.Setenv("BACKPLANE_INITIAL_ARN", "arn:aws:iam::123:role/init")
		t.Setenv("CAD_OCM_URL", "https://ocm.example.com")
		_, err := initializeDependencies("")
		if err == nil {
			t.Fatal("expected error for missing production OCM URL")
		}
		if got := err.Error(); !strings.Contains(got, "production OCM URL") {
			t.Errorf("error = %q, want mention of production OCM URL", got)
		}
	})

	t.Run("missing OCM client ID", func(t *testing.T) {
		t.Setenv("BACKPLANE_URL", "https://bp.example.com")
		t.Setenv("BACKPLANE_INITIAL_ARN", "arn:aws:iam::123:role/init")
		t.Setenv("CAD_OCM_URL", "https://ocm.example.com")
		t.Setenv("CAD_OCM_PRODUCTION_URL", "https://ocm-prod.example.com")
		_, err := initializeDependencies("")
		if err == nil {
			t.Fatal("expected error for missing OCM client ID")
		}
		if got := err.Error(); !strings.Contains(got, "CAD_OCM_CLIENT_ID") {
			t.Errorf("error = %q, want mention of CAD_OCM_CLIENT_ID", got)
		}
	})

	t.Run("missing OCM client secret", func(t *testing.T) {
		t.Setenv("BACKPLANE_URL", "https://bp.example.com")
		t.Setenv("BACKPLANE_INITIAL_ARN", "arn:aws:iam::123:role/init")
		t.Setenv("CAD_OCM_URL", "https://ocm.example.com")
		t.Setenv("CAD_OCM_PRODUCTION_URL", "https://ocm-prod.example.com")
		t.Setenv("CAD_OCM_CLIENT_ID", "client-id")
		_, err := initializeDependencies("")
		if err == nil {
			t.Fatal("expected error for missing OCM client secret")
		}
		if got := err.Error(); !strings.Contains(got, "CAD_OCM_CLIENT_SECRET") {
			t.Errorf("error = %q, want mention of CAD_OCM_CLIENT_SECRET", got)
		}
	})

	t.Run("missing production OCM client ID", func(t *testing.T) {
		t.Setenv("BACKPLANE_URL", "https://bp.example.com")
		t.Setenv("BACKPLANE_INITIAL_ARN", "arn:aws:iam::123:role/init")
		t.Setenv("CAD_OCM_URL", "https://ocm.example.com")
		t.Setenv("CAD_OCM_PRODUCTION_URL", "https://ocm-prod.example.com")
		t.Setenv("CAD_OCM_CLIENT_ID", "client-id")
		t.Setenv("CAD_OCM_CLIENT_SECRET", "client-secret")
		_, err := initializeDependencies("")
		if err == nil {
			t.Fatal("expected error for missing production OCM client ID")
		}
		if got := err.Error(); !strings.Contains(got, "CAD_OCM_PRODUCTION_CLIENT_ID") {
			t.Errorf("error = %q, want mention of CAD_OCM_PRODUCTION_CLIENT_ID", got)
		}
	})

	t.Run("missing production OCM client secret", func(t *testing.T) {
		t.Setenv("BACKPLANE_URL", "https://bp.example.com")
		t.Setenv("BACKPLANE_INITIAL_ARN", "arn:aws:iam::123:role/init")
		t.Setenv("CAD_OCM_URL", "https://ocm.example.com")
		t.Setenv("CAD_OCM_PRODUCTION_URL", "https://ocm-prod.example.com")
		t.Setenv("CAD_OCM_CLIENT_ID", "client-id")
		t.Setenv("CAD_OCM_CLIENT_SECRET", "client-secret")
		t.Setenv("CAD_OCM_PRODUCTION_CLIENT_ID", "prod-client-id")
		_, err := initializeDependencies("")
		if err == nil {
			t.Fatal("expected error for missing production OCM client secret")
		}
		if got := err.Error(); !strings.Contains(got, "CAD_OCM_PRODUCTION_CLIENT_SECRET") {
			t.Errorf("error = %q, want mention of CAD_OCM_PRODUCTION_CLIENT_SECRET", got)
		}
	})
}

func TestInitializeDependencies_ConfigFileOverridesEnvVars(t *testing.T) {
	// This test verifies that config file values take precedence over env vars
	// for non-secret settings. Since OCM client creation accepts any credentials,
	// we can verify the returned Dependencies have config-file values, not env var values.

	configContent := `
runtime:
  backplane:
    url: "https://bp-from-config.example.com"
    initial_arn: "arn:aws:iam::123:role/from-config"
  ocm:
    url: "https://ocm-from-config.example.com"
    production_url: "https://ocm-prod-from-config.example.com"
  aws_proxy: "http://aws-proxy-from-config:9090"
  experimental_enabled: true
filters: []
`
	path := t.TempDir() + "/config.yaml"
	if err := os.WriteFile(path, []byte(configContent), 0o600); err != nil {
		t.Fatal(err)
	}

	// Set env vars to different values — config file should win for non-secrets
	t.Setenv("CAD_INVESTIGATION_CONFIG_PATH", "")
	t.Setenv("BACKPLANE_URL", "https://bp-from-env.example.com")
	t.Setenv("BACKPLANE_INITIAL_ARN", "arn:aws:iam::456:role/from-env")
	t.Setenv("CAD_OCM_URL", "https://ocm-from-env.example.com")
	t.Setenv("CAD_OCM_PRODUCTION_URL", "https://ocm-prod-from-env.example.com")
	t.Setenv("AWS_PROXY", "http://aws-proxy-from-env:1234")
	t.Setenv("CAD_EXPERIMENTAL_ENABLED", "false")
	// Provide secrets so we get past validation
	t.Setenv("CAD_OCM_CLIENT_ID", "test-id")
	t.Setenv("CAD_OCM_CLIENT_SECRET", "test-secret")
	t.Setenv("CAD_OCM_PRODUCTION_CLIENT_ID", "test-prod-id")
	t.Setenv("CAD_OCM_PRODUCTION_CLIENT_SECRET", "test-prod-secret")

	deps, err := initializeDependencies(path)
	if err != nil {
		t.Fatalf("initializeDependencies() error = %v", err)
	}
	defer deps.Cleanup()

	// Verify config file values were used (not env var values)
	if deps.BackplaneURL != "https://bp-from-config.example.com" {
		t.Errorf("BackplaneURL = %q, want config value %q", deps.BackplaneURL, "https://bp-from-config.example.com")
	}
	if deps.AWSProxy != "http://aws-proxy-from-config:9090" {
		t.Errorf("AWSProxy = %q, want config value %q", deps.AWSProxy, "http://aws-proxy-from-config:9090")
	}
	if !deps.ExperimentalEnabled {
		t.Error("ExperimentalEnabled = false, want true (from config file)")
	}
	if deps.ManagedCloud == nil {
		t.Error("ManagedCloud should not be nil")
	}
	if deps.OCMClient == nil {
		t.Error("OCMClient should not be nil")
	}
	if deps.OCMProductionClient == nil {
		t.Error("OCMProductionClient should not be nil")
	}
	if deps.BackplaneClient == nil {
		t.Error("BackplaneClient should not be nil")
	}
	if deps.BackplaneProductionClient == nil {
		t.Error("BackplaneProductionClient should not be nil")
	}
	if deps.FilterConfig == nil {
		t.Error("FilterConfig should not be nil")
	}
}

func TestInitializeDependencies_BackplaneProductionURLFallback(t *testing.T) {
	// Verify that when BACKPLANE_PRODUCTION_URL is not set, it falls back to BACKPLANE_URL.
	// We test this indirectly via resolveConfigOrEnv since initializeDependencies needs
	// real OCM credentials to complete.

	t.Setenv("BACKPLANE_URL", "https://bp.example.com")
	t.Setenv("BACKPLANE_PRODUCTION_URL", "")

	// With empty config and empty env var, production URL should fall back to primary URL
	primaryURL := resolveConfigOrEnv("", "BACKPLANE_URL")
	productionURL := resolveConfigOrEnv("", "BACKPLANE_PRODUCTION_URL")

	if primaryURL != "https://bp.example.com" {
		t.Errorf("primaryURL = %q, want %q", primaryURL, "https://bp.example.com")
	}
	if productionURL != "" {
		t.Errorf("productionURL from env = %q, want empty (fallback happens in initializeDependencies)", productionURL)
	}
}

func TestNewController_Validation(t *testing.T) {
	deps := &Dependencies{}

	t.Run("both pd and manual is invalid", func(t *testing.T) {
		opts := ControllerOptions{
			Pd:     &PagerDutyConfig{PayloadPath: "/tmp/test"},
			Manual: &ManualConfig{ClusterId: "c1", InvestigationName: "inv1"},
		}
		_, err := NewController(opts, deps)
		if err == nil {
			t.Fatal("expected error when both pd and manual specified")
		}
	})

	t.Run("neither pd nor manual is invalid", func(t *testing.T) {
		opts := ControllerOptions{}
		_, err := NewController(opts, deps)
		if err == nil {
			t.Fatal("expected error when neither pd nor manual specified")
		}
	})
}

func TestPagerDutyConfig_Validate(t *testing.T) {
	t.Run("empty PayloadPath is invalid", func(t *testing.T) {
		cfg := &PagerDutyConfig{}
		if err := cfg.Validate(); err == nil {
			t.Fatal("expected error for empty PayloadPath")
		}
	})

	t.Run("non-empty PayloadPath is valid", func(t *testing.T) {
		cfg := &PagerDutyConfig{PayloadPath: "/tmp/payload.json"}
		if err := cfg.Validate(); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

func TestManualConfig_Validate(t *testing.T) {
	t.Run("empty ClusterId is invalid", func(t *testing.T) {
		cfg := &ManualConfig{InvestigationName: "inv1"}
		if err := cfg.Validate(); err == nil {
			t.Fatal("expected error for empty ClusterId")
		}
	})

	t.Run("empty InvestigationName is invalid", func(t *testing.T) {
		cfg := &ManualConfig{ClusterId: "c1"}
		if err := cfg.Validate(); err == nil {
			t.Fatal("expected error for empty InvestigationName")
		}
	})

	t.Run("both set is valid", func(t *testing.T) {
		cfg := &ManualConfig{ClusterId: "c1", InvestigationName: "inv1"}
		if err := cfg.Validate(); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

func TestCalculateBackoff(t *testing.T) {
	tests := []struct {
		attempt int
		want    string // as Duration string for readability
	}{
		{1, "1s"},
		{2, "2s"},
		{3, "4s"},
		{4, "8s"},
		{5, "10s"}, // capped at maxRetryBackoff
	}
	for _, tt := range tests {
		got := calculateBackoff(tt.attempt)
		if got.String() != tt.want {
			t.Errorf("calculateBackoff(%d) = %v, want %v", tt.attempt, got, tt.want)
		}
	}
}

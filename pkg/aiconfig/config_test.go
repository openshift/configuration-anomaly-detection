package aiconfig

import (
	"os"
	"testing"
	"time"
)

func TestParseAIAgentConfig(t *testing.T) {
	tests := []struct {
		name       string
		envValue   string
		wantErr    bool
		wantConfig *AIAgentConfig
	}{
		{
			name:     "Empty env var returns disabled config",
			envValue: "",
			wantErr:  false,
			wantConfig: &AIAgentConfig{
				Enabled: false,
			},
		},
		{
			name:     "Invalid JSON returns error",
			envValue: `{invalid json}`,
			wantErr:  true,
		},
		{
			name: "Valid config with all fields",
			envValue: `{
				"runtime_arn": "arn:aws:bedrock:us-east-1:123456789012:agent-runtime/test",
				"user_id": "test-user",
				"region": "us-east-1",
				"version": "v1.0.0",
				"ops_sop_version": "v2.0.0",
				"rosa_plugins_version": "v3.0.0",
				"organizations": ["org1", "org2"],
				"clusters": ["cluster1", "cluster2"],
				"enabled": true,
				"timeout_seconds": 600
			}`,
			wantErr: false,
			wantConfig: &AIAgentConfig{
				RuntimeARN:         "arn:aws:bedrock:us-east-1:123456789012:agent-runtime/test",
				UserID:             "test-user",
				Region:             "us-east-1",
				Version:            "v1.0.0",
				OpsSopVersion:      "v2.0.0",
				RosaPluginsVersion: "v3.0.0",
				Organizations:      []string{"org1", "org2"},
				Clusters:           []string{"cluster1", "cluster2"},
				Enabled:            true,
				TimeoutSeconds:     600,
			},
		},
		{
			name: "Config without timeout uses default 300 seconds",
			envValue: `{
				"runtime_arn": "arn:aws:bedrock:us-east-1:123456789012:agent-runtime/test",
				"user_id": "test-user",
				"region": "us-east-1",
				"organizations": ["org1"],
				"clusters": [],
				"enabled": true
			}`,
			wantErr: false,
			wantConfig: &AIAgentConfig{
				RuntimeARN:     "arn:aws:bedrock:us-east-1:123456789012:agent-runtime/test",
				UserID:         "test-user",
				Region:         "us-east-1",
				Organizations:  []string{"org1"},
				Clusters:       []string{},
				Enabled:        true,
				TimeoutSeconds: 300,
			},
		},
		{
			name: "Config with empty allowlists",
			envValue: `{
				"runtime_arn": "arn:aws:bedrock:us-east-1:123456789012:agent-runtime/test",
				"user_id": "test-user",
				"region": "us-east-1",
				"organizations": [],
				"clusters": [],
				"enabled": false
			}`,
			wantErr: false,
			wantConfig: &AIAgentConfig{
				RuntimeARN:     "arn:aws:bedrock:us-east-1:123456789012:agent-runtime/test",
				UserID:         "test-user",
				Region:         "us-east-1",
				Organizations:  []string{},
				Clusters:       []string{},
				Enabled:        false,
				TimeoutSeconds: 300,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set env var for test
			if tt.envValue != "" {
				os.Setenv("CAD_AI_AGENT_CONFIG", tt.envValue)
			} else {
				os.Unsetenv("CAD_AI_AGENT_CONFIG")
			}
			defer os.Unsetenv("CAD_AI_AGENT_CONFIG")

			got, err := ParseAIAgentConfig()
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseAIAgentConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}

			// Compare relevant fields
			if got.RuntimeARN != tt.wantConfig.RuntimeARN {
				t.Errorf("RuntimeARN = %v, want %v", got.RuntimeARN, tt.wantConfig.RuntimeARN)
			}
			if got.UserID != tt.wantConfig.UserID {
				t.Errorf("UserID = %v, want %v", got.UserID, tt.wantConfig.UserID)
			}
			if got.Region != tt.wantConfig.Region {
				t.Errorf("Region = %v, want %v", got.Region, tt.wantConfig.Region)
			}
			if got.Version != tt.wantConfig.Version {
				t.Errorf("Version = %v, want %v", got.Version, tt.wantConfig.Version)
			}
			if got.OpsSopVersion != tt.wantConfig.OpsSopVersion {
				t.Errorf("OpsSopVersion = %v, want %v", got.OpsSopVersion, tt.wantConfig.OpsSopVersion)
			}
			if got.RosaPluginsVersion != tt.wantConfig.RosaPluginsVersion {
				t.Errorf("RosaPluginsVersion = %v, want %v", got.RosaPluginsVersion, tt.wantConfig.RosaPluginsVersion)
			}
			if got.Enabled != tt.wantConfig.Enabled {
				t.Errorf("Enabled = %v, want %v", got.Enabled, tt.wantConfig.Enabled)
			}
			if got.TimeoutSeconds != tt.wantConfig.TimeoutSeconds {
				t.Errorf("TimeoutSeconds = %v, want %v", got.TimeoutSeconds, tt.wantConfig.TimeoutSeconds)
			}
			if len(got.Organizations) != len(tt.wantConfig.Organizations) {
				t.Errorf("Organizations length = %v, want %v", len(got.Organizations), len(tt.wantConfig.Organizations))
			}
			if len(got.Clusters) != len(tt.wantConfig.Clusters) {
				t.Errorf("Clusters length = %v, want %v", len(got.Clusters), len(tt.wantConfig.Clusters))
			}
		})
	}
}

func TestAIAgentConfig_IsAllowedForAI(t *testing.T) {
	tests := []struct {
		name      string
		config    *AIAgentConfig
		clusterID string
		orgID     string
		want      bool
	}{
		{
			name: "Cluster in allowlist returns true",
			config: &AIAgentConfig{
				Clusters:      []string{"cluster1", "cluster2", "cluster3"},
				Organizations: []string{},
			},
			clusterID: "cluster2",
			orgID:     "",
			want:      true,
		},
		{
			name: "Organization in allowlist returns true",
			config: &AIAgentConfig{
				Clusters:      []string{},
				Organizations: []string{"org1", "org2", "org3"},
			},
			clusterID: "",
			orgID:     "org2",
			want:      true,
		},
		{
			name: "Neither cluster nor org in allowlist returns false",
			config: &AIAgentConfig{
				Clusters:      []string{"cluster1", "cluster2"},
				Organizations: []string{"org1", "org2"},
			},
			clusterID: "cluster3",
			orgID:     "org3",
			want:      false,
		},
		{
			name: "Both empty strings return false",
			config: &AIAgentConfig{
				Clusters:      []string{"cluster1", "cluster2"},
				Organizations: []string{"org1", "org2"},
			},
			clusterID: "",
			orgID:     "",
			want:      false,
		},
		{
			name: "Empty allowlists return false",
			config: &AIAgentConfig{
				Clusters:      []string{},
				Organizations: []string{},
			},
			clusterID: "cluster1",
			orgID:     "org1",
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.config.IsAllowedForAI(tt.clusterID, tt.orgID)
			if got != tt.want {
				t.Errorf("IsAllowedForAI(%q, %q) = %v, want %v", tt.clusterID, tt.orgID, got, tt.want)
			}
		})
	}
}

func TestAIAgentConfig_GetTimeout(t *testing.T) {
	c := &AIAgentConfig{
		TimeoutSeconds: 300,
	}
	got := c.GetTimeout()
	want := 5 * time.Minute
	if got != want {
		t.Errorf("GetTimeout() = %v, want %v", got, want)
	}
}

package config

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
	"gopkg.in/yaml.v2"
)

const (
	// ConfigEnvVar is the environment variable that holds the path to the investigation filter config file.
	ConfigEnvVar = "CAD_INVESTIGATION_CONFIG_PATH"

	// LegacyAIConfigEnvVar is the legacy environment variable that holds the AI agent config as JSON.
	//
	// Deprecated: use the ai_agent section in the config file instead.
	LegacyAIConfigEnvVar = "CAD_AI_AGENT_CONFIG"
)

// AIAgentConfig holds runtime configuration for AgentCore AI investigations.
type AIAgentConfig struct {
	RuntimeARN string `yaml:"runtime_arn"` // AWS ARN of the agent runtime to invoke
	UserID     string `yaml:"user_id"`     // Used for audit trail only
	Region     string `yaml:"region"`

	// Version Metadata (for audit trail in notes/reports)
	Version            string `yaml:"version,omitempty"`              // Agent runtime version to validate
	OpsSopVersion      string `yaml:"ops_sop_version,omitempty"`      // ops-sop repository version
	RosaPluginsVersion string `yaml:"rosa_plugins_version,omitempty"` // rosa-claude-plugins version

	TimeoutSeconds int `yaml:"timeout_seconds,omitempty"` // Timeout for agent API call (default: 900 seconds / 15 minutes)
}

// GetTimeout returns the timeout as a time.Duration for use with context.WithTimeout.
func (c *AIAgentConfig) GetTimeout() time.Duration {
	return time.Duration(c.TimeoutSeconds) * time.Second
}

// Config holds the complete investigation filter configuration.
type Config struct {
	AIAgent *AIAgentConfig        `yaml:"ai_agent,omitempty"`
	Filters []InvestigationFilter `yaml:"filters"`
}

// LoadConfig reads and parses the investigation filter configuration.
// If pathOverride is non-empty, it is used as the config file path.
// Otherwise, the path is read from the CAD_INVESTIGATION_CONFIG_PATH environment variable.
// If neither is set, falls back to the legacy CAD_AI_AGENT_CONFIG JSON env var for
// backwards compatibility.
// Returns nil (no config) if no source is available.
// The validInvestigations parameter is the list of known investigation names used to
// validate that each filter references a real investigation.
func LoadConfig(pathOverride string, validInvestigations []string) (*Config, error) {
	path := pathOverride
	if path == "" {
		path = os.Getenv(ConfigEnvVar)
	}
	if path != "" {
		data, err := os.ReadFile(path) //nolint:gosec // path is from a trusted env var, not user input
		if err != nil {
			return nil, fmt.Errorf("failed to read config file %q: %w", path, err)
		}
		return ParseConfig(data, validInvestigations)
	}

	// Fall back to legacy CAD_AI_AGENT_CONFIG env var.
	return loadLegacyAIConfig()
}

// legacyAIAgentConfig is the old JSON-based AI agent configuration from CAD_AI_AGENT_CONFIG.
type legacyAIAgentConfig struct {
	RuntimeARN         string   `json:"runtime_arn"`
	UserID             string   `json:"user_id"`
	Region             string   `json:"region"`
	Version            string   `json:"version,omitempty"`
	OpsSopVersion      string   `json:"ops_sop_version,omitempty"`
	RosaPluginsVersion string   `json:"rosa_plugins_version,omitempty"`
	Organizations      []string `json:"organizations"`
	Clusters           []string `json:"clusters"`
	Enabled            bool     `json:"enabled"`
	TimeoutSeconds     int      `json:"timeout_seconds,omitempty"`
}

// loadLegacyAIConfig parses the legacy CAD_AI_AGENT_CONFIG JSON env var and converts it
// into a Config with a synthesized aiassisted filter entry built from the old allowlists.
// Returns nil if the env var is not set or enabled is false.
func loadLegacyAIConfig() (*Config, error) {
	configJSON := os.Getenv(LegacyAIConfigEnvVar)
	if configJSON == "" {
		return nil, nil //nolint:nilnil // no config means "no filtering configured"
	}

	var legacy legacyAIAgentConfig
	if err := json.Unmarshal([]byte(configJSON), &legacy); err != nil {
		return nil, fmt.Errorf("failed to parse %s: %w", LegacyAIConfigEnvVar, err)
	}

	if !legacy.Enabled {
		return nil, nil //nolint:nilnil // disabled means no AI config
	}

	logging.Warnf("Using deprecated %s env var — migrate to a config file via %s", LegacyAIConfigEnvVar, ConfigEnvVar)

	timeout := legacy.TimeoutSeconds
	if timeout == 0 {
		timeout = 900
	}

	// Build an OR filter from the old cluster/org allowlists.
	filter := buildLegacyAllowlistFilter(legacy.Clusters, legacy.Organizations)
	if filter == nil {
		return nil, fmt.Errorf("%s: enabled but no clusters or organizations in allowlist", LegacyAIConfigEnvVar)
	}

	return &Config{
		AIAgent: &AIAgentConfig{
			RuntimeARN:         legacy.RuntimeARN,
			UserID:             legacy.UserID,
			Region:             legacy.Region,
			Version:            legacy.Version,
			OpsSopVersion:      legacy.OpsSopVersion,
			RosaPluginsVersion: legacy.RosaPluginsVersion,
			TimeoutSeconds:     timeout,
		},
		Filters: []InvestigationFilter{
			{
				Investigation: "aiassisted",
				Filter:        filter,
			},
		},
	}, nil
}

// buildLegacyAllowlistFilter converts the old clusters/organizations allowlists
// into a filter tree. Returns nil if both lists are empty.
func buildLegacyAllowlistFilter(clusters, organizations []string) *FilterNode {
	var children []FilterNode

	if len(clusters) > 0 {
		children = append(children, FilterNode{
			Field:    FieldClusterID,
			Operator: OperatorIn,
			Values:   clusters,
		})
	}

	if len(organizations) > 0 {
		children = append(children, FilterNode{
			Field:    FieldOrganizationID,
			Operator: OperatorIn,
			Values:   organizations,
		})
	}

	if len(children) == 0 {
		return nil
	}
	if len(children) == 1 {
		return &children[0]
	}
	return &FilterNode{Or: children}
}

// ParseConfig parses and validates a YAML config from raw bytes.
// The validInvestigations parameter is the list of known investigation names used to
// validate that each filter references a real investigation.
func ParseConfig(data []byte, validInvestigations []string) (*Config, error) {
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse investigation config: %w", err)
	}

	if err := cfg.Validate(validInvestigations); err != nil {
		return nil, fmt.Errorf("invalid investigation config: %w", err)
	}

	// Set default timeout for AI agent config
	if cfg.AIAgent != nil && cfg.AIAgent.TimeoutSeconds == 0 {
		cfg.AIAgent.TimeoutSeconds = 900
	}

	return &cfg, nil
}

// GetAIAgentConfig returns the AI agent runtime configuration, or nil if not set.
func (c *Config) GetAIAgentConfig() *AIAgentConfig {
	if c == nil {
		return nil
	}
	return c.AIAgent
}

// Validate checks that all investigation names are known and all filter expressions
// reference valid FilterContext fields.
func (c *Config) Validate(validInvestigations []string) error {
	if c.AIAgent != nil {
		if c.AIAgent.RuntimeARN == "" {
			return fmt.Errorf("ai_agent: runtime_arn must not be empty")
		}
		if c.AIAgent.Region == "" {
			return fmt.Errorf("ai_agent: region must not be empty")
		}
		if c.AIAgent.UserID == "" {
			return fmt.Errorf("ai_agent: user_id must not be empty")
		}
	}

	seen := make(map[string]bool)

	for i, f := range c.Filters {
		if f.Investigation == "" {
			return fmt.Errorf("filters[%d]: investigation name must not be empty", i)
		}

		if seen[f.Investigation] {
			return fmt.Errorf("filters[%d]: duplicate investigation %q", i, f.Investigation)
		}
		seen[f.Investigation] = true

		if !isValidInvestigation(f.Investigation, validInvestigations) {
			return fmt.Errorf("filters[%d]: unknown investigation %q; valid investigations: %v", i, f.Investigation, validInvestigations)
		}

		if f.Filter != nil {
			if err := f.Filter.validate(fmt.Sprintf("filters[%d].filter", i)); err != nil {
				return fmt.Errorf("filters[%d] (investigation %q): %w", i, f.Investigation, err)
			}
		}

		if f.Investigation == "aiassisted" {
			if c.AIAgent == nil {
				return fmt.Errorf("filters[%d]: investigation %q requires ai_agent configuration", i, f.Investigation)
			}
			if f.Filter == nil {
				return fmt.Errorf("filters[%d]: investigation %q requires filters for now", i, f.Investigation)
			}
		}
	}

	if _, ok := seen["aiassisted"]; !ok && c.AIAgent != nil {
		return fmt.Errorf("aiassisted investigation *must* specify valid filters for now: either add filtering or remove 'ai_agent' config")
	}

	return nil
}

// GetFilter returns the filter for the given investigation name, or nil if no filter
// is configured. A nil return means the investigation should always run.
func (c *Config) GetFilter(investigationName string) *InvestigationFilter {
	if c == nil {
		return nil
	}
	for i := range c.Filters {
		if c.Filters[i].Investigation == investigationName {
			return &c.Filters[i]
		}
	}
	return nil
}

func isValidInvestigation(name string, valid []string) bool {
	for _, v := range valid {
		if v == name {
			return true
		}
	}
	return false
}

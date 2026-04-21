package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v2"
)

const (
	// ConfigEnvVar is the environment variable that holds the path to the investigation filter config file.
	ConfigEnvVar = "CAD_INVESTIGATION_CONFIG_PATH"
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
// Returns nil (no config) if no path is available from either source.
// The validInvestigations parameter is the list of known investigation names used to
// validate that each filter references a real investigation.
func LoadConfig(pathOverride string, validInvestigations []string) (*Config, error) {
	path := pathOverride
	if path == "" {
		path = os.Getenv(ConfigEnvVar)
	}
	if path == "" {
		return nil, nil //nolint:nilnil // nil config means "no filtering configured", not an error
	}

	data, err := os.ReadFile(path) //nolint:gosec // path is from a trusted env var, not user input
	if err != nil {
		return nil, fmt.Errorf("failed to read config file %q: %w", path, err)
	}

	return ParseConfig(data, validInvestigations)
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

		if f.Investigation == "aiassisted" && c.AIAgent == nil {
			return fmt.Errorf("filters[%d]: investigation %q requires ai_agent configuration", i, f.Investigation)
		}
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

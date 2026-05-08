package config

import (
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
	"gopkg.in/yaml.v3"
)

const (
	// ConfigEnvVar is the environment variable that holds the path to the investigation filter config file.
	ConfigEnvVar = "CAD_INVESTIGATION_CONFIG_PATH"
)

// AIAgentConfig holds runtime configuration for AgentCore AI investigations.
type AIAgentConfig struct {
	RuntimeARN     string `yaml:"runtime_arn"`      // AWS ARN of the agent runtime to invoke
	UserID         string `yaml:"user_id"`          // Used for audit trail only
	Region         string `yaml:"region"`           // AWS region where AgentCore is deployed
	InvokerRoleArn string `yaml:"invoker_role_arn"` // IAM role ARN to assume for invoking AgentCore

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

// Config holds the complete investigation configuration.
type Config struct {
	AIAgent        *AIAgentConfig        `yaml:"ai_agent,omitempty"`
	Investigations []InvestigationConfig `yaml:"investigations"`
}

// InvestigationConfig defines which chain of investigations to run for a given alert.
type InvestigationConfig struct {
	AlertTitle   string       `yaml:"alert_title"`
	Experimental bool         `yaml:"experimental,omitempty"`
	When         *FilterNode  `yaml:"when,omitempty"`
	Chain        []ChainEntry `yaml:"chain"`
}

// ChainEntry is a single step in an investigation chain.
// In YAML it can be a bare string (investigation name) or an object with name + optional when filter.
type ChainEntry struct {
	Name string      `yaml:"name"`
	When *FilterNode `yaml:"when,omitempty"`
}

// UnmarshalYAML allows ChainEntry to be specified as either a bare string or a mapping.
func (e *ChainEntry) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind == yaml.ScalarNode {
		e.Name = value.Value
		return nil
	}
	type raw ChainEntry
	return value.Decode((*raw)(e))
}

// LoadConfig reads and parses the investigation configuration.
// If pathOverride is non-empty, it is used as the config file path.
// Otherwise, the path is read from the CAD_INVESTIGATION_CONFIG_PATH environment variable.
// Returns nil if no config file is found (optional ConfigMap mount).
// The validInvestigations parameter is the list of known investigation names used to
// validate that each chain entry references a real investigation.
func LoadConfig(pathOverride string, validInvestigations []string) (*Config, error) {
	path := pathOverride
	if path == "" {
		path = os.Getenv(ConfigEnvVar)
	}
	if path == "" {
		return nil, nil //nolint:nilnil // no config path means "no config"
	}

	data, err := os.ReadFile(path) //nolint:gosec // path is from a trusted env var, not user input
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// The config file is optional (e.g. mounted from an optional ConfigMap).
			// Treat a missing file the same as "no config".
			logging.Infof("Config file %q not found, continuing without config", path)
			return nil, nil //nolint:nilnil // no config means "no filtering configured"
		}
		return nil, fmt.Errorf("failed to read config file %q: %w", path, err)
	}
	return ParseConfig(data, validInvestigations)
}

// ParseConfig parses and validates a YAML config from raw bytes.
// The validInvestigations parameter is the list of known investigation names used to
// validate that each chain entry references a real investigation.
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

// GetChain returns the first InvestigationConfig whose AlertTitle is contained in the given alert title.
// Chains marked experimental are only returned when experimentalEnabled is true.
func (c *Config) GetChain(alertTitle string, experimentalEnabled bool) *InvestigationConfig {
	if c == nil {
		return nil
	}
	for i := range c.Investigations {
		if strings.Contains(alertTitle, c.Investigations[i].AlertTitle) {
			if c.Investigations[i].Experimental && !experimentalEnabled {
				continue
			}
			return &c.Investigations[i]
		}
	}
	return nil
}

// GetAIAgentConfig returns the AI agent runtime configuration, or nil if not set.
func (c *Config) GetAIAgentConfig() *AIAgentConfig {
	if c == nil {
		return nil
	}
	return c.AIAgent
}

// Validate checks that all investigation names are known, all filter expressions
// reference valid FilterContext fields, and chain-level/entry-level when clauses are valid.
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
		if c.AIAgent.InvokerRoleArn == "" {
			return fmt.Errorf("ai_agent: invoker_role_arn must not be empty")
		}
	}

	seen := make(map[string]bool)
	hasAIAssisted := false

	for i, ic := range c.Investigations {
		if ic.AlertTitle == "" {
			return fmt.Errorf("investigations[%d]: alert_title must not be empty", i)
		}

		if seen[ic.AlertTitle] {
			return fmt.Errorf("investigations[%d]: duplicate alert_title %q", i, ic.AlertTitle)
		}
		seen[ic.AlertTitle] = true

		if len(ic.Chain) == 0 {
			return fmt.Errorf("investigations[%d] (alert_title %q): chain must not be empty", i, ic.AlertTitle)
		}

		// Validate chain-level when clause
		if ic.When != nil {
			if err := ic.When.validate(fmt.Sprintf("investigations[%d].when", i)); err != nil {
				return fmt.Errorf("investigations[%d] (alert_title %q): %w", i, ic.AlertTitle, err)
			}
		}

		for j, entry := range ic.Chain {
			if entry.Name == "" {
				return fmt.Errorf("investigations[%d].chain[%d]: name must not be empty", i, j)
			}

			if !isValidInvestigation(entry.Name, validInvestigations) {
				return fmt.Errorf("investigations[%d].chain[%d]: unknown investigation %q; valid investigations: %v", i, j, entry.Name, validInvestigations)
			}

			if entry.Name == "aiassisted" {
				hasAIAssisted = true
				// aiassisted must always be gated by a filter to prevent uncontrolled
				// AI execution. Either a chain-level or entry-level when clause satisfies this.
				if ic.When == nil && entry.When == nil {
					return fmt.Errorf(
						"investigations[%d].chain[%d]: aiassisted requires a 'when' filter "+
							"(on the chain or entry level) to control execution", i, j)
				}
			}

			// Validate entry-level when clause
			if entry.When != nil {
				if err := entry.When.validate(fmt.Sprintf("investigations[%d].chain[%d].when", i, j)); err != nil {
					return fmt.Errorf("investigations[%d].chain[%d] (investigation %q): %w", i, j, entry.Name, err)
				}
			}
		}
	}

	if hasAIAssisted && c.AIAgent == nil {
		return fmt.Errorf("aiassisted investigation requires ai_agent configuration")
	}

	return nil
}

func isValidInvestigation(name string, valid []string) bool {
	return slices.Contains(valid, name)
}

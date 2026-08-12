package config

import (
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
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
	AIAgent *AIAgentConfig `yaml:"ai_agent,omitempty"`
	Alerts  []AlertConfig  `yaml:"alerts"`
}

// AlertConfig defines which investigations to run for a given alert.
type AlertConfig struct {
	AlertTitle     string               `yaml:"alert_title"`
	Name           string               `yaml:"name,omitempty"`
	Experimental   bool                 `yaml:"experimental,omitempty"`
	When           *FilterNode          `yaml:"when,omitempty"`
	Investigations []InvestigationEntry `yaml:"investigations"`
}

// GetName returns the alert's investigation name, falling back to AlertTitle
// when Name is not set. This preserves backward compatibility with configs
// that predate the name field.
func (ac *AlertConfig) GetName() string {
	if ac.Name != "" {
		return ac.Name
	}
	return ac.AlertTitle
}

// InvestigationEntry is a single investigation step within an alert's investigation list.
// In YAML it can be a bare string (investigation name) or an object with name + optional when filter.
type InvestigationEntry struct {
	Name string      `yaml:"name"`
	When *FilterNode `yaml:"when,omitempty"`
}

// UnmarshalYAML allows InvestigationEntry to be specified as either a bare string or a mapping.
func (e *InvestigationEntry) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind == yaml.ScalarNode {
		e.Name = value.Value
		return nil
	}
	type raw InvestigationEntry
	return value.Decode((*raw)(e))
}

// LoadConfig reads and parses the investigation configuration from the given path.
// Returns an error if the path is empty or the file cannot be read.
// The validInvestigations parameter is the list of known investigation names used to
// validate that each chain entry references a real investigation.
func LoadConfig(path string, validInvestigations []string) (*Config, error) {
	if path == "" {
		return nil, fmt.Errorf("investigation config path must not be empty")
	}

	data, err := os.ReadFile(path) //nolint:gosec // path is from a trusted source, not user input
	if err != nil {
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

// GetAlert returns the first AlertConfig whose AlertTitle is contained in the given alert title.
// The match is case-insensitive to prevent mismatches between config values and PagerDuty titles.
// Alerts marked experimental are only returned when experimentalEnabled is true.
func (c *Config) GetAlert(alertTitle string, experimentalEnabled bool) *AlertConfig {
	if c == nil {
		return nil
	}
	alertTitleLower := strings.ToLower(alertTitle)
	for i := range c.Alerts {
		if strings.Contains(alertTitleLower, strings.ToLower(c.Alerts[i].AlertTitle)) {
			if c.Alerts[i].Experimental && !experimentalEnabled {
				continue
			}
			return &c.Alerts[i]
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

	for i, ac := range c.Alerts {
		if strings.TrimSpace(ac.AlertTitle) == "" {
			return fmt.Errorf("alerts[%d]: alert_title must not be empty", i)
		}

		if seen[ac.AlertTitle] {
			return fmt.Errorf("alerts[%d]: duplicate alert_title %q", i, ac.AlertTitle)
		}
		seen[ac.AlertTitle] = true

		if len(ac.Investigations) == 0 {
			return fmt.Errorf("alerts[%d] (alert_title %q): investigations must not be empty", i, ac.AlertTitle)
		}

		// Validate alert-level when clause
		if ac.When != nil {
			if err := ac.When.validate(fmt.Sprintf("alerts[%d].when", i)); err != nil {
				return fmt.Errorf("alerts[%d] (alert_title %q): %w", i, ac.AlertTitle, err)
			}
		}

		for j, entry := range ac.Investigations {
			if entry.Name == "" {
				return fmt.Errorf("alerts[%d].investigations[%d]: name must not be empty", i, j)
			}

			if !isValidInvestigation(entry.Name, validInvestigations) {
				return fmt.Errorf("alerts[%d].investigations[%d]: unknown investigation %q; valid investigations: %v", i, j, entry.Name, validInvestigations)
			}

			if entry.Name == "aiassisted" {
				hasAIAssisted = true
			}

			// Validate entry-level when clause
			if entry.When != nil {
				if err := entry.When.validate(fmt.Sprintf("alerts[%d].investigations[%d].when", i, j)); err != nil {
					return fmt.Errorf("alerts[%d].investigations[%d] (investigation %q): %w", i, j, entry.Name, err)
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

package aiconfig

import (
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"time"
)

// AIAgentConfig holds configuration for AgentCore AI investigations
type AIAgentConfig struct {
	RuntimeARN string `json:"runtime_arn"` // AWS ARN of the agent runtime to invoke
	UserID     string `json:"user_id"`     // Used for audit trail only
	Region     string `json:"region"`

	// Version Metadata (for audit trail in notes/reports)
	// TODO: Add feature gating in production for different ENVs based on version
	Version            string `json:"version,omitempty"`              // Agent runtime version to validate
	OpsSopVersion      string `json:"ops_sop_version,omitempty"`      // ops-sop repository version
	RosaPluginsVersion string `json:"rosa_plugins_version,omitempty"` // rosa-claude-plugins version

	// Allowlist - at least one org or cluster must be specified for AI to run
	Organizations []string `json:"organizations"`
	Clusters      []string `json:"clusters"`

	Enabled        bool `json:"enabled"`                   // Global on/off switch for AI investigation
	TimeoutSeconds int  `json:"timeout_seconds,omitempty"` // Timeout for agent API call (default: 300 seconds / 5 minutes)
}

// ParseAIAgentConfig parses the AI agent configuration from the CAD_AI_AGENT_CONFIG environment variable
// Returns a config with Enabled=false if the environment variable is not set
func ParseAIAgentConfig() (*AIAgentConfig, error) {
	configJSON := os.Getenv("CAD_AI_AGENT_CONFIG")

	// If not set, return disabled config
	if configJSON == "" {
		return &AIAgentConfig{Enabled: false}, nil
	}

	var config AIAgentConfig
	if err := json.Unmarshal([]byte(configJSON), &config); err != nil {
		return nil, fmt.Errorf("failed to parse CAD_AI_AGENT_CONFIG: %w", err)
	}

	// Set default timeout
	if config.TimeoutSeconds == 0 {
		config.TimeoutSeconds = 300
	}

	return &config, nil
}

// GetTimeout returns the timeout as a time.Duration for use with context.WithTimeout
func (c *AIAgentConfig) GetTimeout() time.Duration {
	return time.Duration(c.TimeoutSeconds) * time.Second
}

// IsAllowedForAI checks if the given cluster ID or organization ID is in the allowlist
// Empty strings are never matched to prevent accidental authorization
func (c *AIAgentConfig) IsAllowedForAI(clusterID, orgID string) bool {
	// Check cluster allowlist (skip if clusterID is empty)
	if clusterID != "" && slices.Contains(c.Clusters, clusterID) {
		return true
	}

	// Check organization allowlist (skip if orgID is empty)
	if orgID != "" && slices.Contains(c.Organizations, orgID) {
		return true
	}

	return false
}

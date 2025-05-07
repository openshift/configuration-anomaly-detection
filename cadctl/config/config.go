/*
Copyright © 2025 Red Hat, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package config

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/openshift/configuration-anomaly-detection/pkg/ocm"
)

type Config struct {
	ConfigFile         string
	LogLevel           string
	CadOcmClientID     string
	CadOcmClientSecret string
	CadOcmURL          string
	Experimental       bool
}

func BuildConfig(cmd *cobra.Command) (Config, error) {
	// Get the config file path from command line flags or environment variables
	var c Config
	var err error
	var ocmConfigFile string

	_, err = c.getLogLevel(cmd)
	if err != nil {
		return c, fmt.Errorf("failed to get log level: %w", err)
	}

	if ocmConfigFile, err = c.getConfigFile(cmd); err != nil {
		return c, fmt.Errorf("failed to get config file: %w", err)
	}

	if ocmConfigFile == "" {
		// loads the configuration unless config file is present
		// config should be used only when developing
		if _, err = c.getCadOcmClientID(); err != nil {
			return c, fmt.Errorf("failed to get cadOcmClientID: %w", err)
		}
		if _, err = c.getCadOcmClientSecret(); err != nil {
			return c, fmt.Errorf("failed to get cadOcmClientSecret: %w", err)
		}
		if _, err = c.getCadOcmURL(); err != nil {
			return c, fmt.Errorf("failed to get cadOcmURL: %w", err)
		}
	}

	if _, err = c.getExperimental(); err != nil {
		return c, fmt.Errorf("failed to get experimental flag: %w", err)
	}

	return c, err
}

// getConfigFile retrieves the OCM config file path from the command line flags or environment variables.
// It checks the following in order:
// 1. Command line flag --ocmconfig
// 2. Environment variable OCM_CONFIG
// 3. Default OCM config locations
// If the file is not found at any of these locations, the config path remains empty.
// Missing config is a valid state, as the user may not have a config file.
func (c *Config) getConfigFile(cmd *cobra.Command) (string, error) {
	ocmConfigPath, err := cmd.Flags().GetString("ocmconfig")
	if err != nil {
		return "", fmt.Errorf("failed to get ocmconfig flag: %w", err)
	}

	if ocmConfigPath != "" {
		if _, err := os.Stat(ocmConfigPath); err != nil {
			return "", fmt.Errorf("ocmconfig file not found at %s: %w", ocmConfigPath, err)
		}

		c.ConfigFile = ocmConfigPath
		return ocmConfigPath, nil
	}

	ocmConfigPath, exists := os.LookupEnv("OCM_CONFIG")
	if exists {
		if _, err := os.Stat(ocmConfigPath); err != nil {
			return "", fmt.Errorf("ocmconfig file not found at %s: %w", ocmConfigPath, err)
		}

		c.ConfigFile = ocmConfigPath
		return ocmConfigPath, nil
	}

	ocmConfigPath, err = ocm.Location()
	if err != nil {
		// Location() checks for file existence
		return "", fmt.Errorf("failed to get ocmconfig file location: %w", err)
	}

	c.ConfigFile = ocmConfigPath
	return ocmConfigPath, nil
}

func (c *Config) getLogLevel(cmd *cobra.Command) (string, error) {
	logLevel, err := cmd.Flags().GetString("loglevel")
	if err != nil {
		return "", fmt.Errorf("failed to get loglevel flag: %w", err)
	}
	if logLevel != "" {
		c.LogLevel = logLevel
		return logLevel, nil
	}

	if envLogLevel, exists := os.LookupEnv("LOG_LEVEL"); exists {
		c.LogLevel = envLogLevel
		return logLevel, nil
	}

	c.LogLevel = "info"
	return logLevel, nil
}

// getExperimental retrieves the experimental flag passed as a command line argument.
// If not set, it checks the CAD_EXPERIMENTAL_ENABLED environment variable.
// Defaults to false if neither is set.
func (c *Config) getExperimental() (bool, error) {
	_, exist := os.LookupEnv("CAD_EXPERIMENTAL_ENABLED")
	if exist {
		c.Experimental = true
		return true, nil
	}

	c.Experimental = false
	return false, nil
}

// getCadOcmClientID retrieves the OCM cliend ID passed as
// an CAD_OCM_CLIENT_ID environment variable.
func (c *Config) getCadOcmClientID() (string, error) {
	cadOcmClientID, exist := os.LookupEnv("CAD_OCM_CLIENT_ID")
	if !exist {
		return "", fmt.Errorf("client-id flag or CAD_OCM_CLIENT_ID environment variable must be set")
	}

	c.CadOcmClientID = cadOcmClientID
	return cadOcmClientID, nil
}

// getCadOcmClientSecret retrieves the OCM client secret passed as
// an environment CAD_OCM_CLIENT_SECRET variable.
func (c *Config) getCadOcmClientSecret() (string, error) {
	cadOcmClientSecret, exist := os.LookupEnv("CAD_OCM_CLIENT_SECRET")
	if !exist {
		return "", fmt.Errorf("client-secret flag or CAD_OCM_CLIENT_SECRET environment variable must be set")
	}

	c.CadOcmClientSecret = cadOcmClientSecret
	return cadOcmClientSecret, nil
}

// getCadOcmURL retrieves the OCM URL passed as an environment
// CAD_OCM_URL variable.
func (c *Config) getCadOcmURL() (string, error) {
	cadOcmURL, exist := os.LookupEnv("CAD_OCM_URL")
	if !exist {
		return "", fmt.Errorf("ocm-url flag or CAD_OCM_URL environment variable must be set")
	}

	c.CadOcmURL = cadOcmURL
	return cadOcmURL, nil
}

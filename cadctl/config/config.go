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
)

type Config struct {
	ConfigFile string

	LogLevel string

	CadOcmClientID     string
	CadOcmClientSecret string
	CadOcmURL          string

	PipelineName string

	PrometheusPushGateway string

	PagerDutyToken        string
	PagerDutySilentPolicy string

	BackplaneURL        string
	BackplaneProxyURL   string
	BackplaneInitialARN string

	AWSProxy string

	Experimental bool
}

func BuildConfig(cmd *cobra.Command) (Config, error) {
	// Get the config file path from command line flags or environment variables
	var c Config
	var err error

	if c.LogLevel, err = getLogLevel(cmd); err != nil {
		return c, fmt.Errorf("failed to get log level: %w", err)
	}

	if c.CadOcmClientID, err = getCadOcmClientID(); err != nil {
		return c, fmt.Errorf("failed to get cadOcmClientID: %w", err)
	}
	if c.CadOcmClientSecret, err = getCadOcmClientSecret(); err != nil {
		return c, fmt.Errorf("failed to get cadOcmClientSecret: %w", err)
	}
	if c.CadOcmURL, err = getCadOcmURL(); err != nil {
		return c, fmt.Errorf("failed to get cadOcmURL: %w", err)
	}

	if c.Experimental, err = getExperimental(); err != nil {
		return c, fmt.Errorf("failed to get experimental flag: %w", err)
	}

	if c.PipelineName, err = getPipelineName(); err != nil {
		return c, fmt.Errorf("failed to get pipeline name: %w", err)
	}

	if c.PrometheusPushGateway, err = getPrometheusPushGateway(); err != nil {
		return c, fmt.Errorf("failed to get prometheus push gateway: %w", err)
	}

	if c.PagerDutyToken, err = getPagerDutyToken(); err != nil {
		return c, fmt.Errorf("failed to get pagerduty token: %w", err)
	}

	if c.PagerDutySilentPolicy, err = getPagerDutySilentPolicy(); err != nil {
		return c, fmt.Errorf("failed to get pagerduty silent policy: %w", err)
	}

	if c.BackplaneURL, err = getBackplaneURL(); err != nil {
		return c, fmt.Errorf("failed to get backplane URL: %w", err)
	}

	if c.BackplaneProxyURL, err = getBackplaneProxyURL(); err != nil {
		return c, fmt.Errorf("failed to get backplane proxy URL: %w", err)
	}

	if c.BackplaneInitialARN, err = getBackplaneInitialARN(); err != nil {
		return c, fmt.Errorf("failed to get backplane initial ARN: %w", err)
	}

	if c.AWSProxy, err = getAWSProxy(); err != nil {
		return c, fmt.Errorf("failed to get AWS proxy: %w", err)
	}

	return c, err
}

func getAWSProxy() (string, error) {
	if envAWSProxy, exists := os.LookupEnv("AWS_PROXY"); exists {
		return envAWSProxy, nil
	}

	return "", nil
}

func getBackplaneURL() (string, error) {
	if envBackplaneURL, exists := os.LookupEnv("BACKPLANE_URL"); exists {
		return envBackplaneURL, nil
	}

	return "", nil
}

func getBackplaneProxyURL() (string, error) {
	if envBackplaneProxyURL, exists := os.LookupEnv("BACKPLANE_PROXY"); exists {
		return envBackplaneProxyURL, nil
	}

	return "", nil
}

func getBackplaneInitialARN() (string, error) {
	if envBackplaneInitialARN, exists := os.LookupEnv("BACKPLANE_INITIAL_ARN"); exists {
		return envBackplaneInitialARN, nil
	}

	return "", nil
}

func getPipelineName() (string, error) {
	if envPipelineName, exists := os.LookupEnv("PIPELINE_NAME"); exists {
		return envPipelineName, nil
	}

	return "", nil
}

func getPagerDutyToken() (string, error) {
	if envPagerDutyToken, exists := os.LookupEnv("CAD_PD_TOKEN"); exists {
		return envPagerDutyToken, nil
	}
	return "", nil
}

func getPagerDutySilentPolicy() (string, error) {
	if envPagerDutySilentPolicy, exists := os.LookupEnv("CAD_SILENT_POLICY"); exists {
		return envPagerDutySilentPolicy, nil
	}
	return "", nil
}

func getPrometheusPushGateway() (string, error) {
	if envPrometheusPushGateway, exists := os.LookupEnv("CAD_PROMETHEUS_PUSHGATEWAY"); exists {
		return envPrometheusPushGateway, nil
	}

	return "", nil
}

func getLogLevel(cmd *cobra.Command) (string, error) {
	logLevel, err := cmd.Flags().GetString("loglevel")
	if err != nil {
		return "", fmt.Errorf("failed to get loglevel flag: %w", err)
	}
	if logLevel != "" {
		return logLevel, nil
	}

	if envLogLevel, exists := os.LookupEnv("LOG_LEVEL"); exists {
		return envLogLevel, nil
	}

	return "info", nil
}

// getExperimental retrieves the experimental flag passed as a command line argument.
// If not set, it checks the CAD_EXPERIMENTAL_ENABLED environment variable.
// Defaults to false if neither is set.
func getExperimental() (bool, error) {
	_, exist := os.LookupEnv("CAD_EXPERIMENTAL_ENABLED")
	if exist {
		return true, nil
	}

	return false, nil
}

// getCadOcmClientID retrieves the OCM cliend ID passed as
// an CAD_OCM_CLIENT_ID environment variable.
func getCadOcmClientID() (string, error) {
	cadOcmClientID, exist := os.LookupEnv("CAD_OCM_CLIENT_ID")
	if !exist {
		return "", fmt.Errorf("client-id flag or CAD_OCM_CLIENT_ID environment variable must be set")
	}

	return cadOcmClientID, nil
}

// getCadOcmClientSecret retrieves the OCM client secret passed as
// an environment CAD_OCM_CLIENT_SECRET variable.
func getCadOcmClientSecret() (string, error) {
	cadOcmClientSecret, exist := os.LookupEnv("CAD_OCM_CLIENT_SECRET")
	if !exist {
		return "", fmt.Errorf("client-secret flag or CAD_OCM_CLIENT_SECRET environment variable must be set")
	}

	return cadOcmClientSecret, nil
}

// getCadOcmURL retrieves the OCM URL passed as an environment
// CAD_OCM_URL variable.
func getCadOcmURL() (string, error) {
	cadOcmURL, exist := os.LookupEnv("CAD_OCM_URL")
	if !exist {
		return "", fmt.Errorf("ocm-url flag or CAD_OCM_URL environment variable must be set")
	}

	return cadOcmURL, nil
}

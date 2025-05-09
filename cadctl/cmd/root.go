// Package cmd holds the cadctl cobra data
/*
Copyright © 2022 Red Hat, Inc.

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
package cmd

import (
	"fmt"
	"os"

	investigate "github.com/openshift/configuration-anomaly-detection/cadctl/cmd/investigate"
	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
	"github.com/openshift/configuration-anomaly-detection/pkg/metrics"
	ocm "github.com/openshift/configuration-anomaly-detection/pkg/ocm"
	"github.com/spf13/cobra"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:               "cadctl",
	Short:             "A util of configuration-anomaly-detection (CAD) checks",
	PersistentPreRunE: loadCommon,
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	metrics.Push()
	if err != nil {
		logging.Fatal(err)
	}
}

func init() {
	rootCmd.AddCommand(investigate.InvestigateCmd)
	rootCmd.PersistentFlags().StringP("ocmconfig", "c", "", "Path to the OCM config file to use for CLI requests. When not set the OCM_CONFIG environment variable will be used. If that is not set, the default OCM config locations will be file will be used.")
}

func loadCommon(cmd *cobra.Command, args []string) error {

	ocmConfigPath, err := cmd.Flags().GetString("ocmconfig")
	if err != nil {
		return fmt.Errorf("failed to get ocmconfig flag: %w", err)
	}

	if ocmConfigPath != "" {
		if _, err := os.Stat(ocmConfigPath); err != nil {
			return fmt.Errorf("ocmconfig file not found at %s: %w", ocmConfigPath, err)
		}

		ocm.SetConfigFile(ocmConfigPath)

		return nil
	}

	ocmConfigPath, exists := os.LookupEnv("OCM_CONFIG")
	if exists {
		if _, err := os.Stat(ocmConfigPath); err != nil {
			return fmt.Errorf("ocmconfig file not found at %s: %w", ocmConfigPath, err)
		}

		ocm.SetConfigFile(ocmConfigPath)

		return nil
	}

	ocmConfigPath, err = ocm.Location()
	if err != nil {
		// Location() checks for file existence
		return fmt.Errorf("failed to get ocmconfig file location: %w", err)
	}

	ocm.SetConfigFile(ocmConfigPath)

	return nil
}

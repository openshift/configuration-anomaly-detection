// Package examine provides functionality for manual examining of anomalies.
// Compared to the investigate command, this command does not require an alert
// it needs an cluster id and investigation name.
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
package examine

import (
	"fmt"
	"strings"

	"github.com/openshift/configuration-anomaly-detection/pkg/investigations"
	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
	"github.com/spf13/cobra"
)

// ExamineCmd represents the entry point for manual anomaly examination
var ExamineCmd = &cobra.Command{
	Use:          "examine",
	SilenceUsage: true,
	Short:        "Manually examine anomalies for a specific cluster",
	Long:         `Manually examine anomalies for a specific cluster. This command requires a cluster ID and an investigation name. You can get list of available investigations using the 'list' subcommand.`,
	Example:      `cadctl examine <cluster-id> --investigation <investigation-name>`,
	RunE:         run,
}

var (
	logLevelFlag      = ""
	clusterID         = ""
	investigationName = ""
)

func init() {
	// Add flags for the examine command
	ExamineCmd.Flags().StringVarP(&investigationName, "investigation", "i", "", "the investigation name to run")
	ExamineCmd.Flags().StringVarP(&logging.LogLevelString, "log-level", "l", "info", "the log level [debug,info,warn,error,fatal], default = info")

	// Add the list subcommand
	ExamineCmd.AddCommand(listCmd)
}

func run(cmd *cobra.Command, args []string) error {
	// If no arguments are provided, show available subcommands
	if len(args) == 0 {
		return cmd.Help()
	}

	// Set the log level according to the flag
	flagValue, _ := cmd.Flags().GetString("log-level")
	logging.RawLogger = logging.InitConsoleLogger(flagValue)

	clusterID = args[0]
	if args[0] == "" {
		logging.Fatal("Cluster ID is required")
	}

	investigationName, _ = cmd.Flags().GetString("investigation")
	// Always use experimental flag, when running the examine command
	// the decision is up to the user
	investigationInstance := investigations.GetInvestigationByName(investigationName)

	logging.Info("Starting examine command")
	return nil
}

// listRegisteredInvestigations prints all registered investigations.
func listRegisteredInvestigations() {
	fmt.Printf("  %-10s %s\n", "NAME", "DESCRIPTION")
	fmt.Printf("  %-10s %s\n", strings.Repeat("-", 10), strings.Repeat("-", 40))
	for name, desc := range investigations.GetAllInvestigations() {
		fmt.Printf("  %-10s %s\n", name, desc)
	}
}

// listCmd represents the "list" subcommand
var listCmd = &cobra.Command{
	Use:     "list",
	Short:   "List all available investigations",
	Long:    `List all available investigations as a table`,
	Example: `cadctl examine list`,
	Run: func(_ *cobra.Command, _ []string) {
		listRegisteredInvestigations()
	},
}

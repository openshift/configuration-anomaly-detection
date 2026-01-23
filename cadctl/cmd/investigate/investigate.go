// Package investigate holds the investigate command
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
package investigate

import (
	"os"

	"github.com/openshift/configuration-anomaly-detection/pkg/controller"

	"github.com/spf13/cobra"
)

// InvestigateCmd represents the entry point for alert investigation
var InvestigateCmd = &cobra.Command{
	Use:          "investigate",
	SilenceUsage: true,
	Short:        "Filter for and investigate supported alerts",
	RunE:         run,
}

var (
	logLevelFlag    = ""
	payloadPath     = "./payload.json"
	pipelineNameEnv = ""
)

func init() {
	InvestigateCmd.Flags().StringVarP(&payloadPath, "payload-path", "p", payloadPath, "the path to the payload, defaults to './payload.json'")
	InvestigateCmd.Flags().StringVarP(&logLevelFlag, "log-level", "l", "", "the log level [debug,info,warn,error,fatal], default = info")

	if envLogLevel, exists := os.LookupEnv("LOG_LEVEL"); exists {
		logLevelFlag = envLogLevel
	}

	pipelineNameEnv = os.Getenv("PIPELINE_NAME")
}

var errAlertEscalated = fmt.Errorf("alert escalated to SRE")

// handleUnsupportedAlertWithAI checks if AI is enabled for unsupported alerts.
// If AI is enabled, returns an AI investigation. If disabled, escalates the alert.
// Returns errAlertEscalated if the alert was escalated.
func handleUnsupportedAlertWithAI(alertInvestigation investigation.Investigation, pdClient *pagerduty.SdkClient) (investigation.Investigation, error) {
	if alertInvestigation != nil {
		return alertInvestigation, nil
	}

	// Parse AI config
	aiConfig, err := aiconfig.ParseAIAgentConfig()
	if err != nil {
		aiConfig = &aiconfig.AIAgentConfig{Enabled: false}
		logging.Warnf("Failed to parse AI agent configuration, disabling AI investigation: %v", err)
	}

	// Escalate if AI is disabled
	if !aiConfig.Enabled {
		if err := pdClient.EscalateIncident(); err != nil {
			return nil, fmt.Errorf("could not escalate unsupported alert: %w", err)
		}
		return nil, errAlertEscalated
	}

	// Use AI investigation for unsupported alerts
	return &aiassisted.Investigation{}, nil
}

func run(_ *cobra.Command, _ []string) error {
	opts := controller.ControllerOptions{
		Common: controller.CommonConfig{
			LogLevel:   logLevelFlag,
			Identifier: pipelineNameEnv,
		},
		Pd: &controller.PagerDutyConfig{
			PayloadPath:  payloadPath,
			PipelineName: pipelineNameEnv,
		},
		Manual: nil,
	}
	return controller.Run(opts)
}

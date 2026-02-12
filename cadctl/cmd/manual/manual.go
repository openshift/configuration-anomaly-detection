package manual

import (
	"os"

	"github.com/openshift/configuration-anomaly-detection/pkg/controller"
	"github.com/spf13/cobra"
)

var (
	logLevelFlag      = ""
	investigationFlag = ""
	clusterIdFlag     = ""
	dryRunFlag        = false
	pipelineNameEnv   = ""
)

func NewManualCmd() (*cobra.Command, error) {
	cmd := &cobra.Command{
		Use:          "run",
		SilenceUsage: true,
		Short:        "Run a manual investigation",
		RunE:         run,
	}
	cmd.Flags().StringVarP(&clusterIdFlag, "cluster-id", "c", "", "the cluster to run an investigation againstk")
	cmd.Flags().StringVarP(&investigationFlag, "investigation", "i", "", "the investigation to run manually")
	cmd.Flags().BoolVarP(&dryRunFlag, "dry-run", "d", false, "run investigation without performing any external operations")
	err := cmd.MarkFlagRequired("cluster-id")
	if err != nil {
		return nil, err
	}
	err = cmd.MarkFlagRequired("investigation")
	if err != nil {
		return nil, err
	}

	logLevelFlag = os.Getenv("LOG_LEVEL")
	pipelineNameEnv = os.Getenv("PIPELINE_NAME")

	return cmd, nil
}

func run(_ *cobra.Command, _ []string) error {
	opts := controller.ControllerOptions{
		Common: controller.CommonConfig{
			LogLevel:   logLevelFlag,
			Identifier: pipelineNameEnv,
		},
		Pd: nil,
		Manual: &controller.ManualConfig{
			ClusterId:         clusterIdFlag,
			InvestigationName: investigationFlag,
			DryRun:            dryRunFlag,
		},
	}
	return controller.Run(opts)
}

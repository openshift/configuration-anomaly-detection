package manual

import (
	"fmt"
	"os"
	"strings"

	"github.com/openshift/configuration-anomaly-detection/pkg/controller"
	"github.com/spf13/cobra"
)

var (
	logLevelFlag      = ""
	investigationFlag = ""
	clusterIdFlag     = ""
	dryRunFlag        = false
	pipelineNameEnv   = ""
	paramsFlag        []string
)

func NewManualCmd() (*cobra.Command, error) {
	cmd := &cobra.Command{
		Use:          "run",
		SilenceUsage: true,
		Short:        "Run a manual investigation",
		RunE:         run,
	}
	cmd.Flags().StringVarP(&clusterIdFlag, "cluster-id", "c", "", "the cluster to run an investigation against")
	cmd.Flags().StringVarP(&investigationFlag, "investigation", "i", "", "the investigation to run manually")
	cmd.Flags().BoolVarP(&dryRunFlag, "dry-run", "d", false, "run investigation without performing any external operations")
	cmd.Flags().StringArrayVarP(&paramsFlag, "params", "p", nil, "investigation-specific parameters as KEY=VALUE (can be specified multiple times)")
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
	params, err := parseParams(paramsFlag)
	if err != nil {
		return err
	}

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
			Params:            params,
		},
	}
	return controller.Run(opts)
}

// parseParams converts a slice of "KEY=VALUE" strings into a map.
// Return an empty map when no params are provided.
func parseParams(raw []string) (map[string]string, error) {
	params := make(map[string]string, len(raw))
	for _, p := range raw {
		key, value, ok := strings.Cut(p, "=")
		if !ok || key == "" {
			return nil, fmt.Errorf("invalid parameter %q: must be KEY=VALUE", p)
		}
		params[key] = value
	}
	return params, nil
}

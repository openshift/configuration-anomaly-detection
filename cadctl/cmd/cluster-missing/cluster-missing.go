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
package clustermissing

import (
	"fmt"
	"os"

	"github.com/openshift/configuration-anomaly-detection/pkg/pagerduty"
	"github.com/spf13/cobra"
)

// ClusterMissingCmd represents the cluster-missing command
var ClusterMissingCmd = &cobra.Command{
	Use:   "cluster-missing",
	Short: "Will remediate the cluster-missing alert",
	RunE: func(cmd *cobra.Command, args []string) error {
		CAD_PD, ok := os.LookupEnv("CAD_PD")
		if !ok {
			return fmt.Errorf("could not load CAD_PD envvar")
		}

		_, err := pagerduty.NewWithToken(CAD_PD)
		if err != nil {
			return fmt.Errorf("could not start client: %w", err)
		}

		return nil
	},
}

var (
	incidentID string
)

func init() {
	ClusterMissingCmd.Flags().StringVarP(&incidentID, "incident", "i", "", "the incident ID to do the operation on")
}

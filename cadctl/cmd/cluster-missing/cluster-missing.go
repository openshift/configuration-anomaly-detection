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

	"github.com/openshift/configuration-anomaly-detection/pkg/aws"
	ocm "github.com/openshift/configuration-anomaly-detection/pkg/ocm"
	"github.com/openshift/configuration-anomaly-detection/pkg/pagerduty"
	"github.com/spf13/cobra"
)

// ClusterMissingCmd represents the cluster-missing command
var ClusterMissingCmd = &cobra.Command{
	Use:   "cluster-missing",
	Short: "Will remediate the cluster-missing alert",
	RunE: func(cmd *cobra.Command, args []string) error {
		AWS_ACCESS_KEY_ID, hasAWS_ACCESS_KEY_ID := os.LookupEnv("AWS_ACCESS_KEY_ID")
		AWS_SECRET_ACCESS_KEY, hasAWS_SECRET_ACCESS_KEY := os.LookupEnv("AWS_SECRET_ACCESS_KEY")
		AWS_SESSION_TOKEN, hasAWS_SESSION_TOKEN := os.LookupEnv("AWS_SESSION_TOKEN")
		AWS_DEFAULT_REGION, hasAWS_DEFAULT_REGION := os.LookupEnv("AWS_DEFAULT_REGION")
		if !hasAWS_ACCESS_KEY_ID || !hasAWS_SECRET_ACCESS_KEY || !hasAWS_SESSION_TOKEN || !hasAWS_DEFAULT_REGION {
			return fmt.Errorf("one of the required envvars in the list '(AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_DEFAULT_REGION)' is missing")
		}

		_, err := aws.NewClient(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN, AWS_DEFAULT_REGION)
		if err != nil {
			return fmt.Errorf("could not start awsClient: %w", err)
		}

		// in this case it's ok if the envvar is empty
		CAD_OCM_FILE_PATH := os.Getenv("CAD_OCM_FILE_PATH")
		_, err = ocm.New(CAD_OCM_FILE_PATH)
		if err != nil {
			return fmt.Errorf("could not create ocm client: %w", err)
		}

		CAD_PD, ok := os.LookupEnv("CAD_PD")
		if !ok {
			return fmt.Errorf("could not load CAD_PD envvar")
		}

		_, err = pagerduty.NewWithToken(CAD_PD)
		if err != nil {
			return fmt.Errorf("could not start pagerdutyClient: %w", err)
		}

		return nil
	},
}

var (
	incidentID string
)

func init() {
	ClusterMissingCmd.Flags().StringVarP(&incidentID, "payload", "p", "", "The incident payload as received from the PagerDuty WebHook")
}

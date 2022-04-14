// Package clustermissing holds the cluster-missing command
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
	"path/filepath"

	"github.com/openshift/configuration-anomaly-detection/pkg/aws"
	ocm "github.com/openshift/configuration-anomaly-detection/pkg/ocm"
	"github.com/openshift/configuration-anomaly-detection/pkg/pagerduty"
	"github.com/openshift/configuration-anomaly-detection/pkg/services/assumerole"
	"github.com/openshift/configuration-anomaly-detection/pkg/services/chgm"
	"github.com/spf13/cobra"
)

// ClusterMissingCmd represents the cluster-missing command
var ClusterMissingCmd = &cobra.Command{
	Use:   "cluster-missing",
	Short: "Will remediate the cluster-missing alert",
	RunE:  run,
}

func run(cmd *cobra.Command, args []string) error {

	awsClient, err := GetAWSClient()
	if err != nil {
		return fmt.Errorf("could not start awsClient: %w", err)
	}

	ocmClient, err := GetOCMClient()
	if err != nil {
		return fmt.Errorf("could not create ocm client: %w", err)
	}

	pdClient, err := GetPDClient()
	if err != nil {
		return fmt.Errorf("could not start pagerdutyClient: %w", err)
	}

	externalClusterID, err := pdClient.ExtractExternalIDFromPayload(payloadPath, pagerduty.RealFileReader{})
	if err != nil {
		return fmt.Errorf("GetExternalID failed on: %w", err)
	}

	incidentID, err := pdClient.ExtractIncidentIDFromPayload(payloadPath, pagerduty.RealFileReader{})
	if err != nil {
		return fmt.Errorf("GetIncidentID failed on: %w", err)
	}

	arClient := assumerole.Client{
		Service: chgm.Provider{
			AwsClient: awsClient,
			OcmClient: ocmClient,
			PdClient:  pdClient,
		},
	}
	cssJumprole, ok := os.LookupEnv("CSS_JUMPROLE")
	if !ok {
		return fmt.Errorf("CSS_JUMPROLE is missing")
	}

	supportRole, ok := os.LookupEnv("SUPPORT_JUMPROLE")
	if !ok {
		return fmt.Errorf("SUPPORT_JUMPROLE is missing")
	}

	customerAwsClient, err := arClient.AssumeSupportRoleChain(externalClusterID, cssJumprole, supportRole)
	if err != nil {
		return fmt.Errorf("could not AssumeSupportRoleChain: %w", err)
	}

	// building twice to override the awsClient
	chgmClient := chgm.Client{
		Service: chgm.Provider{
			AwsClient: customerAwsClient,
			OcmClient: ocmClient,
		},
	}

	res, err := chgmClient.InvestigateInstances(externalClusterID)
	if err != nil {
		return fmt.Errorf("InvestigateInstances failed on %s: %w", externalClusterID, err)
	}

	fmt.Printf("the returned struct is %#v\n", res)

	if res.UserAuthorized {
		fmt.Println("The node shutdown was not the customer. Should alert SRE")
		err = chgmClient.EscalateAlert(incidentID, res.String())
		if err != nil {
			return fmt.Errorf("could not escalate the alert %s: %w", incidentID, err)
		}
		return nil
	}

	err = chgmClient.SendServiceLog()
	if err != nil {
		return fmt.Errorf("failed sending service log during before silencing the alert: %w", err)
	}

	err = chgmClient.SilenceAlert(incidentID, res.String())
	if err != nil {
		return fmt.Errorf("assigning the incident to Silent Test did not work: %w", err)
	}
	// written this way so I can quickly detect if res is true of false
	fmt.Println("USER INITIATED SHUTDOWN")

	return nil
}

// GetOCMClient will retrieve the OcmClient from the 'ocm' package
func GetOCMClient() (ocm.Client, error) {
	cadOcmFilePath := os.Getenv("CAD_OCM_FILE_PATH")

	_, err := os.Stat(cadOcmFilePath)
	if os.IsNotExist(err) {
		configDir, err := os.UserConfigDir()
		if err != nil {
			return ocm.Client{}, err
		}
		cadOcmFilePath = filepath.Join(configDir, "/ocm/ocm.json")
	}

	return ocm.New(cadOcmFilePath)
}

// GetAWSClient will retrieve the AwsClient from the 'aws' package
func GetAWSClient() (aws.Client, error) {
	awsAccessKeyID, hasAwsAccessKeyID := os.LookupEnv("AWS_ACCESS_KEY_ID")
	awsSecretAccessKey, hasAwsSecretAccessKey := os.LookupEnv("AWS_SECRET_ACCESS_KEY")
	awsSessionToken, hasAwsSessionToken := os.LookupEnv("AWS_SESSION_TOKEN")
	awsDefaultRegion, hasAwsDefaultRegion := os.LookupEnv("AWS_DEFAULT_REGION")
	if !hasAwsAccessKeyID || !hasAwsSecretAccessKey {
		return aws.Client{}, fmt.Errorf("one of the required envvars in the list '(AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY)' is missing")
	}
	if !hasAwsSessionToken {
		fmt.Println("AWS_SESSION_TOKEN not provided, but is not required ")
	}
	if !hasAwsDefaultRegion {
		fmt.Println("setting AWS_DEFAULT_REGION to a default value")
		awsDefaultRegion = "us-east-1"
	}

	return aws.NewClient(awsAccessKeyID, awsSecretAccessKey, awsSessionToken, awsDefaultRegion)
}

// GetPDClient will retrieve the PagerDuty from the 'pagerduty' package
func GetPDClient() (pagerduty.Client, error) {
	cadPD, hasCadPD := os.LookupEnv("CAD_PD")
	cadEscalationPolicy, hasCadEscalationPolicy := os.LookupEnv("CAD_ESCALATION_POLICY")
	cadSilentPolicy, hasCadSilentPolicy := os.LookupEnv("CAD_SILENT_POLICY")

	if !hasCadEscalationPolicy || !hasCadSilentPolicy || hasCadPD {
		return pagerduty.Client{}, fmt.Errorf("one of the required envvars in the list '(CAD_ESCALATION_POLICY CAD_SILENT_POLICY CAP_PD)' is missing")
	}

	client, err := pagerduty.NewWithToken(cadPD, cadEscalationPolicy, cadSilentPolicy)
	if err != nil {
		return pagerduty.Client{}, fmt.Errorf("could not initialze the client: %w", err)
	}

	return client, nil
}

var (
	payloadPath = "./payload.json"
)

func init() {
	const payloadPathFlagName = "payload-path"
	ClusterMissingCmd.Flags().StringVarP(&payloadPath, payloadPathFlagName, "p", payloadPath, "the path to the payload")
}

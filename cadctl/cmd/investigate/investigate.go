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
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/openshift/configuration-anomaly-detection/pkg/aws"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigation"
	ocm "github.com/openshift/configuration-anomaly-detection/pkg/ocm"
	"github.com/openshift/configuration-anomaly-detection/pkg/pagerduty"
	"github.com/openshift/configuration-anomaly-detection/pkg/services/assumerole"
	"github.com/openshift/configuration-anomaly-detection/pkg/services/ccam"
	"github.com/openshift/configuration-anomaly-detection/pkg/services/chgm"
	"github.com/openshift/configuration-anomaly-detection/pkg/utils"

	"github.com/spf13/cobra"
)

// ClusterMissingCmd represents the cluster-missing command
var InvestigateCmd = &cobra.Command{
	Use:   "start-investigation",
	Short: "Will remediate the cluster-missing alert",
	RunE:  run,
}

var (
	payloadPath = "./payload.json"
)

func init() {
	const payloadPathFlagName = "payload-path"
	InvestigateCmd.Flags().StringVarP(&payloadPath, payloadPathFlagName, "p", payloadPath, "the path to the payload")
}

func run(cmd *cobra.Command, args []string) error {

	fmt.Println("Running CAD with webhook payload:")
	data, err := os.ReadFile(payloadPath)
	if err != nil {
		return fmt.Errorf("failed to read webhook payload: %w", err)
	}
	fmt.Printf("%s\n", string(data))

	pdClient, err := GetPDClient()
	if err != nil {
		return fmt.Errorf("could not start pagerdutyClient: %w", err)
	}

	title, err := pagerduty.ExtractTitleFromBytes(data)
	if err != nil {
		return err
	}

	// Will return a normalized alert name or an error if the alert is not supported
	alertType, err := GetAlertType(title)
	if err != nil {
		return err
	}

	// gather alert info and populate alert
	incidentID, err := pdClient.ExtractIncidentIDFromBytes(data)
	if err != nil {
		return fmt.Errorf("GetIncidentID failed on: %w", err)
	}
	fmt.Printf("Incident ID is: %s\n", incidentID)

	externalClusterID, err := pdClient.ExtractExternalIDFromBytes(data)
	if err != nil {
		return fmt.Errorf("GetExternalID failed on: %w", err)
	}

	eventType, err := pdClient.ExtractEventTypeFromBytes(data)
	if err != nil {
		return fmt.Errorf("could not determine event type: %w", err)
	}

	fmt.Printf("ClusterExternalID is: %s\n", externalClusterID)

	alert := utils.Alert{
		Payload:           data,
		ExternalClusterID: externalClusterID,
		IncidentID:        incidentID,
	}

	awsClient, err := GetAWSClient()
	if err != nil {
		return fmt.Errorf("could not start awsClient: %w", err)
	}

	ocmClient, err := GetOCMClient()
	if err != nil {
		return fmt.Errorf("could not create ocm client: %w", err)
	}

	// alert specific setup
	fmt.Printf("AlertType is '%s'", alertType)
	client := investigation.Client{}

	switch alertType {
	case "ClusterHasGoneMissing":
		_, err := checkCloudProvider(&ocmClient, externalClusterID, []string{"aws"})
		if err != nil {
			return fmt.Errorf("failed cloud provider check: %w", err)
		}

		// Try to jump into support role
		customerAwsClient, err := jumpRoles(awsClient, ocmClient, pdClient,
			externalClusterID, incidentID)
		if err != nil {
			fmt.Println("Assuming role failed, potential CCAM alert. Investigating... error: ", err.Error())
			// if assumeSupportRoleChain fails, we will evaluate if the credentials are missing
			ccamClient := ccam.Client{
				Service: ccam.Provider{
					OcmClient: ocmClient,
					PdClient:  pdClient,
				},
			}
			return ccamClient.Evaluate(err, externalClusterID, incidentID)
		}

		client = investigation.Client{
			Service: &chgm.Client{
				Service: chgm.Provider{
					AwsClient: customerAwsClient,
					OcmClient: ocmClient,
					PdClient:  pdClient,
				},
				Alert: alert,
			},
		}
	// case "ClusterProvisioningDelay":
	// client = investigation.Client{
	// 	Service: &cpd.Client{
	// 		Service: cpd.Provider{
	// 			AwsClient: customerAwsClient,
	// 			OcmClient: ocmClient,
	// 			PdClient:  pdClient,
	// 		},
	// 		Alert: alert,
	// 	},
	// }
	// this should never happen as GetAlertType should fail on unsupported alerts
	default:
		return fmt.Errorf("alert is not supported by CAD: %s", alertType)
	}

	// execute the investigation that corresponds to the event.type
	switch eventType {
	case pagerduty.PagerdutyIncidentTriggered:
		err = client.Triggered()
	case pagerduty.PagerdutyIncidentResolved:
		err = client.Resolved()
	}
	return err
}

// jumpRoles will return an aws client or an error after trying to jump into
// support role
func jumpRoles(awsClient aws.Client, ocmClient ocm.Client, pdClient pagerduty.Client,
	externalClusterID string, incidentID string) (aws.Client, error) {
	// Try to get cloud credentials
	arClient := assumerole.Client{
		Service: assumerole.Provider{
			AwsClient: awsClient,
			OcmClient: ocmClient,
		},
	}

	cssJumprole, ok := os.LookupEnv("CAD_AWS_CSS_JUMPROLE")
	if !ok {
		return aws.Client{}, fmt.Errorf("CAD_AWS_CSS_JUMPROLE is missing")
	}

	supportRole, ok := os.LookupEnv("CAD_AWS_SUPPORT_JUMPROLE")
	if !ok {
		return aws.Client{}, fmt.Errorf("CAD_AWS_SUPPORT_JUMPROLE is missing")
	}

	return arClient.AssumeSupportRoleChain(externalClusterID, cssJumprole, supportRole)
}

// GetAlertType will return a normalized form of the alertname as a string
// or an error if the alert is not supported by CAD
func GetAlertType(alertTitle string) (string, error) {
	// if strings.Contains(alertTitle, "ClusterProvisioningDelay") {
	// 	return "ClusterProvisioningDelay", nil
	// }
	if strings.Contains(alertTitle, "has gone missing") {
		return "ClusterHasGoneMissing", nil
	}
	return "", fmt.Errorf("alertType is not supported by CAD: %s", alertTitle)
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
		awsDefaultRegion = "us-east-1"
	}

	return aws.NewClient(awsAccessKeyID, awsSecretAccessKey, awsSessionToken, awsDefaultRegion)
}

// GetPDClient will retrieve the PagerDuty from the 'pagerduty' package
func GetPDClient() (pagerduty.Client, error) {
	cadPD, hasCadPD := os.LookupEnv("CAD_PD_TOKEN")
	cadEscalationPolicy, hasCadEscalationPolicy := os.LookupEnv("CAD_ESCALATION_POLICY")
	cadSilentPolicy, hasCadSilentPolicy := os.LookupEnv("CAD_SILENT_POLICY")

	if !hasCadEscalationPolicy || !hasCadSilentPolicy || !hasCadPD {
		return pagerduty.Client{}, fmt.Errorf("one of the required envvars in the list '(CAD_ESCALATION_POLICY CAD_SILENT_POLICY CAP_PD_TOKEN)' is missing")
	}

	client, err := pagerduty.NewWithToken(cadPD, cadEscalationPolicy, cadSilentPolicy)
	if err != nil {
		return pagerduty.Client{}, fmt.Errorf("could not initialize the client: %w", err)
	}

	return client, nil
}

// checkCloudProvider takes a list of supported providers
// and retrieves the clusters cloud provider. It will return the cloud provider
// if its on the list or an error if its not supported or the clusters cloud provider could
// not be gathered.
func checkCloudProvider(ocmClient *ocm.Client, externalClusterID string, supportedProviders []string) (string, error) {
	cloudProvider, err := ocmClient.GetCloudProviderID(externalClusterID)
	if err != nil {
		return "", err
	}
	for _, provider := range supportedProviders {
		if cloudProvider == provider {
			return cloudProvider, nil
		}
	}

	return "", fmt.Errorf("the clusters cloud provider is not supported")
}

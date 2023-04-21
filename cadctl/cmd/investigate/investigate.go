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

	v1 "github.com/openshift-online/ocm-sdk-go/clustersmgmt/v1"
	"github.com/openshift/configuration-anomaly-detection/pkg/aws"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigation"
	ocm "github.com/openshift/configuration-anomaly-detection/pkg/ocm"
	"github.com/openshift/configuration-anomaly-detection/pkg/pagerduty"
	"github.com/openshift/configuration-anomaly-detection/pkg/services/assumerole"
	"github.com/openshift/configuration-anomaly-detection/pkg/services/ccam"
	"github.com/openshift/configuration-anomaly-detection/pkg/services/chgm"

	"github.com/spf13/cobra"
)

// InvestigateCmd represents the entry point for alert investigation
var InvestigateCmd = &cobra.Command{
	Use:   "investigate",
	Short: "Filter for and investigate supported alerts",
	RunE:  run,
}

var (
	payloadPath = "./payload.json"
)

func init() {
	InvestigateCmd.Flags().StringVarP(&payloadPath, "payload-path", "p", payloadPath, "the path to the payload")
}

func run(_ *cobra.Command, _ []string) error {

	fmt.Println("Running CAD with webhook payload:")
	payload, err := os.ReadFile(payloadPath)
	if err != nil {
		return fmt.Errorf("failed to read webhook payload: %w", err)
	}
	fmt.Println(string(payload))

	pdClient, err := GetPDClient(payload)
	if err != nil {
		return fmt.Errorf("could not initialize pagerduty client: %w", err)
	}

	// After this point we know CAD will investigate the alert
	// so we can initialize the other clients
	alertType := isAlertSupported(pdClient.GetTitle(), pdClient.GetServiceName())
	if alertType == "" {
		fmt.Printf("Alert is not supported by CAD: %s", pdClient.GetTitle())
		err = pdClient.EscalateAlert()
		if err != nil {
			return err
		}

		return nil
	}

	fmt.Printf("AlertType is '%s'\n", alertType)
	fmt.Printf("Incident ID is: %s\n", pdClient.GetIncidentID())

	externalClusterID, err := pdClient.RetrieveExternalClusterID()
	if err != nil {
		return fmt.Errorf("GetExternalID failed on: %w", err)
	}

	ocmClient, err := GetOCMClient()
	if err != nil {
		return fmt.Errorf("could not initialize ocm client: %w", err)
	}

	cloudProviderSupported, err := checkCloudProviderSupported(&ocmClient, externalClusterID, []string{"aws"})
	if err != nil {
		return err
	}

	// We currently have no investigations supporting GCP. In the future, this check should be moved on
	// the investigation level, and we should be GCP or AWSClient based on this.
	if !cloudProviderSupported {
		err = pdClient.EscalateAlertWithNote("CAD Investigation skipped: cloud provider is not supported.")
		if err != nil {
			return err
		}

		return nil
	}

	awsClient, err := GetAWSClient()
	if err != nil {
		return fmt.Errorf("could not initialize aws client: %w", err)
	}

	cluster, err := ocmClient.GetClusterInfo(externalClusterID)
	if err != nil {
		return fmt.Errorf("could not retrieve cluster info for %s: %w", externalClusterID, err)
	}

	clusterDeployment, err := ocmClient.GetClusterDeployment(cluster.ID())
	if err != nil {
		return fmt.Errorf("could not retrieve Cluster Deployment for %s: %w", cluster.ID(), err)
	}

	// Try to jump into support role
	customerAwsClient, err := jumpRoles(awsClient, ocmClient, pdClient,
		externalClusterID, cluster)
	if err != nil {
		return err
	}
	// If jumpRoles does not return an aws.Client and there was no error
	// then cluster is in limited support for missing cloud credentials
	if customerAwsClient == (aws.Client{}) {
		return nil
	}

	investigationClient := investigation.Client{}

	// Alert specific setup of investigationClient
	switch alertType {
	case "ClusterHasGoneMissing":
		investigationClient = investigation.Client{
			Investigation: &chgm.Client{
				Service: chgm.Provider{
					AwsClient: &customerAwsClient,
					OcmClient: &ocmClient,
					PdClient:  &pdClient,
				},
				Cluster:           cluster,
				ClusterDeployment: clusterDeployment,
			},
		}
	// this comment highlights how the upcoming CPD integration could look like
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

	eventType := pdClient.GetEventType()
	fmt.Printf("Starting investigation for %s with event type %s\n", alertType, eventType)

	switch eventType {
	case pagerduty.IncidentTriggered:
		return investigationClient.Investigation.Triggered()
	case pagerduty.IncidentResolved:
		return investigationClient.Investigation.Resolved()
		// do we always want to alert primary if a resolve fails?
		// if we put a cluster in limited support and fail to remove it
		// the cluster owner can follow normal limited support flow to get it removed
	default:
		return fmt.Errorf("event type '%s' is not supported", eventType)
	}
}

// jumpRoles will return an aws client or an error after trying to jump into
// support role
func jumpRoles(awsClient aws.Client, ocmClient ocm.Client, pdClient pagerduty.Client,
	externalClusterID string, cluster *v1.Cluster) (aws.Client, error) {
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

	ccamClient := ccam.Client{
		Service: ccam.Provider{
			OcmClient: &ocmClient,
			PdClient:  &pdClient,
		},
		Cluster: cluster,
	}

	customerAwsClient, err := arClient.AssumeSupportRoleChain(externalClusterID, cssJumprole, supportRole)
	if err != nil {
		fmt.Println("Assuming role failed, potential CCAM alert. Investigating... error: ", err.Error())
		// if assumeSupportRoleChain fails, we will evaluate if the credentials are missing
		return aws.Client{}, ccamClient.Evaluate(err, pdClient.GetIncidentID())
	}
	fmt.Println("Got cloud credentials, removing 'Cloud Credentials Are Missing' limited Support reasons if any")
	return customerAwsClient, ccamClient.RemoveLimitedSupport()
}

// isAlertSupported will return a normalized form of the alertname as string or
// an empty string if the alert is not supported
func isAlertSupported(alertTitle string, service string) string {

	// TODO change to enum
	if service == "prod-deadmanssnitch" || service == "stage-deadmanssnitch" {
		if strings.Contains(alertTitle, "has gone missing") {
			return "ClusterHasGoneMissing"
		}
	}
	// this comment highlights how the upcoming CPD integration could look like
	// if strings.Contains(alertTitle, "ClusterProvisioningDelay") && service == "app-sre-alertmanager {
	// 	return "ClusterProvisioningDelay"
	// }
	return ""
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
func GetPDClient(webhookPayload []byte) (pagerduty.Client, error) {
	cadPD, hasCadPD := os.LookupEnv("CAD_PD_TOKEN")
	cadEscalationPolicy, hasCadEscalationPolicy := os.LookupEnv("CAD_ESCALATION_POLICY")
	cadSilentPolicy, hasCadSilentPolicy := os.LookupEnv("CAD_SILENT_POLICY")

	if !hasCadEscalationPolicy || !hasCadSilentPolicy || !hasCadPD {
		return pagerduty.Client{}, fmt.Errorf("one of the required envvars in the list '(CAD_ESCALATION_POLICY CAD_SILENT_POLICY CAP_PD_TOKEN)' is missing")
	}

	client, err := pagerduty.NewWithToken(cadEscalationPolicy, cadSilentPolicy, webhookPayload, cadPD)
	if err != nil {
		return pagerduty.Client{}, fmt.Errorf("could not initialize the client: %w", err)
	}

	return client, nil
}

// checkCloudProviderSupported takes a list of supported providers and checks if the
// cluster to investigate's provider is supported
func checkCloudProviderSupported(ocmClient *ocm.Client, externalClusterID string, supportedProviders []string) (bool, error) {
	cloudProvider, err := ocmClient.GetCloudProviderID(externalClusterID)
	if err != nil {
		return false, err
	}

	for _, provider := range supportedProviders {
		if cloudProvider == provider {
			return true, nil
		}
	}

	fmt.Printf("Unsupported cloud provider: %s", cloudProvider)
	return false, nil
}

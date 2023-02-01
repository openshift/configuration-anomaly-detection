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
	"time"

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

// InvestigateCmd represents the entry point for alert investigation
var InvestigateCmd = &cobra.Command{
	Use:   "investigate",
	Short: "Filter for and investigate supported alerts",
	RunE:  run,
}

var (
	payloadPath = "./payload.json"
	// CADPagerdutyService service id for cad alerts
	CADPagerdutyService = "TODO"
)

func init() {
	const payloadPathFlagName = "payload-path"
	InvestigateCmd.Flags().StringVarP(&payloadPath, payloadPathFlagName, "p", payloadPath, "the path to the payload")
}

func run(cmd *cobra.Command, args []string) error {

	fmt.Println("Running CAD with webhook payload:")
	payload, err := os.ReadFile(payloadPath)
	if err != nil {
		return fmt.Errorf("failed to read webhook payload: %w", err)
	}
	fmt.Printf("%s\n", string(payload))

	pdClient, err := GetPDClient(payload)
	if err != nil {
		return fmt.Errorf("could not start pagerdutyClient: %w", err)
	}

	// put intro struct in pd for simpler access
	title := pdClient.GetTitle()
	serviceName := pdClient.GetServiceName()
	incidentID := pdClient.GetIncidentID()
	eventType := pdClient.GetEventType()

	// currently cad fires its alerts on deadmanssnitch service
	// change this to the new cad service
	CADPagerdutyService = pdClient.GetServiceID()

	// After this point we know CAD will investigate the alert
	// so we can initialize the other clients
	alertType := isAlertSupported(title, serviceName)
	if alertType == "" {
		fmt.Printf("Alert is not supported by CAD: %s", title)
		return nil
	}

	// print parsed struct
	fmt.Printf("AlertType is '%s'", alertType)
	fmt.Printf("Incident ID is: %s\n", incidentID)

	externalClusterID, err := pdClient.RetrieveExternalClusterID()
	if err != nil {
		return fmt.Errorf("GetExternalID failed on: %w", err)
	}

	awsClient, err := GetAWSClient()
	if err != nil {
		return fmt.Errorf("could not start awsClient: %w", err)
	}

	ocmClient, err := GetOCMClient()
	if err != nil {
		return fmt.Errorf("could not create ocm client: %w", err)
	}

	// Try to jump into support role
	customerAwsClient, err := jumpRoles(awsClient, ocmClient, pdClient,
		externalClusterID, incidentID)
	if err != nil {
		return err
	}

	// Alert specific setup of investigation.Client
	client := investigation.Client{}

	cluster, err := ocmClient.GetClusterInfo(externalClusterID)
	if err != nil {
		return fmt.Errorf("could not retrieve cluster info for %s: %w", externalClusterID, err)
	}

	clusterdeployment, err := ocmClient.GetClusterDeployment(cluster.ID())
	if err != nil {
		return fmt.Errorf("could not retrieve Cluster Deployment for %s: %w", cluster.ID(), err)
	}

	switch alertType {
	case "ClusterHasGoneMissing":
		_, err = checkCloudProvider(&ocmClient, externalClusterID, []string{"aws"})
		if err != nil {
			return fmt.Errorf("failed cloud provider check: %w", err)
		}

		client = investigation.Client{
			Investigation: &chgm.Client{
				Service: chgm.Provider{
					AwsClient: customerAwsClient,
					OcmClient: ocmClient,
					PdClient:  pdClient,
				},
				Cluster:           cluster,
				ClusterDeployment: clusterdeployment,
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
	case pagerduty.IncidentTriggered:
		limitedSupport, notes := client.Investigation.Triggered()

		if limitedSupport == (ocm.LimitedSupportReason{}) {
			return utils.Retry(3, time.Second*2, func() error {
				return pdClient.UpdateAndEscalateAlert(string(notes))
			})
		}

		fmt.Printf("Sending limited support reason: %s", limitedSupport.Summary)
		return utils.Retry(3, time.Second*2, func() error {
			return client.PostLimitedSupport(notes)
		})

	case pagerduty.IncidentResolved:
		output, err := client.Investigation.Resolved()
		// do we always want to alert primary if a resolve fails?
		// if we put a cluster in limited support and fail to remove it
		// the cluster owner can follow normal limited support flow to get it removed
		if err != nil {
			return utils.Retry(3, time.Second*2, func() error {
				return pdClient.AddNote(fmt.Sprintf("Resolved investigation did not complete: %v", err.Error()))
			})

		} else if output.NewAlert != (pagerduty.NewAlert{}) {
			err = utils.Retry(3, time.Second*2, func() error {
				return pdClient.AddNote(output.Notes)
			})
			if err != nil {
				fmt.Printf("Failed to add notes to incident: %s", output.Notes)
			}
			return utils.Retry(3, time.Second*2, func() error {
				return pdClient.CreateNewAlert(output.NewAlert, CADPagerdutyService)
			})
		}

		err = utils.Retry(3, time.Second*2, func() error {
			return ocmClient.DeleteLimitedSupportReasons(output.LimitedSupportReason.Summary, cluster.ID())
		})
		if err != nil {
			fmt.Println("failed to remove limited support")
			err = utils.Retry(3, time.Second*2, func() error {
				return pdClient.CreateNewAlert(investigation.GetAlertForLimitedSupportRemovalFailure(err, cluster.ID()), CADPagerdutyService)
			})
			if err != nil {
				return fmt.Errorf("failed to create alert: %w", err)
			}
			fmt.Println("alert has been send")
			return nil
		}
		fmt.Println("limited support removed")
		return nil
	default:
		return fmt.Errorf("event type '%s' is not supported", eventType)
	}
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

	ccamClient, err := ccam.New(ocmClient, pdClient, externalClusterID)
	if err != nil {
		return aws.Client{}, err
	}

	customerAwsClient, err := arClient.AssumeSupportRoleChain(externalClusterID, cssJumprole, supportRole)
	if err != nil {
		fmt.Println("Assuming role failed, potential CCAM alert. Investigating... error: ", err.Error())
		// if assumeSupportRoleChain fails, we will evaluate if the credentials are missing
		return aws.Client{}, ccamClient.Evaluate(err, externalClusterID, incidentID)
	}
	fmt.Println("Got cloud credentials, removing 'Cloud Credentials Are Missing' Limited Support reasons if any")
	return customerAwsClient, ccamClient.RemoveLimitedSupport()
}

// isAlertSupported will return a normalized form of the alertname as string or
// an empty string if the alert is not supported
func isAlertSupported(alertTitle string, service string) string {

	// change to enum
	if service == "prod-deadmanssnitch" || service == "stage-deadmanssnitch" {
		if strings.Contains(alertTitle, "has gone missing") {
			return "ClusterHasGoneMissing"
		}
	}

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

	client, err := pagerduty.NewWithToken(cadPD, cadEscalationPolicy, cadSilentPolicy, webhookPayload)
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

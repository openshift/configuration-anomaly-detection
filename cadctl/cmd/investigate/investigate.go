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
	"github.com/openshift/configuration-anomaly-detection/pkg/services/logging"
	"github.com/spf13/cobra"
)

// InvestigateCmd represents the entry point for alert investigation
var InvestigateCmd = &cobra.Command{
	Use:   "investigate",
	Short: "Filter for and investigate supported alerts",
	RunE:  run,
}

var (
	logLevelString = "info"
	payloadPath    = "./payload.json"
)

func init() {
	InvestigateCmd.Flags().StringVarP(&payloadPath, "payload-path", "p", payloadPath, "the path to the payload")
	InvestigateCmd.Flags().StringVarP(&logLevelString, "log-level", "l", logLevelString, "the log level [debug,info,warn,error,fatal], default = info")
}

func run(_ *cobra.Command, _ []string) error {

	payload, err := os.ReadFile(payloadPath)
	if err != nil {
		return fmt.Errorf("failed to read webhook payload: %w", err)
	}
	logging.Info("Running CAD with webhook payload:", string(payload))

	pdClient, err := GetPDClient(payload)
	if err != nil {
		return fmt.Errorf("could not initialize pagerduty client: %w", err)
	}

	externalClusterID, err := pdClient.RetrieveExternalClusterID()
	if err != nil {
		return fmt.Errorf("GetExternalID failed on: %w", err)
	}

	// initialize logger for the cluster-id context
	logging.RawLogger = logging.InitLogger(logLevelString, externalClusterID)

	// After this point we know CAD will investigate the alert
	// so we can initialize the other clients
	alertType := isAlertSupported(pdClient.GetTitle(), pdClient.GetServiceName())
	if alertType == "" {
		logging.Infof("Alert is not supported by CAD: %s", pdClient.GetTitle())
		err = pdClient.EscalateAlert()
		if err != nil {
			return err
		}

		return nil
	}

	logging.Infof("AlertType is '%s'", alertType)
	logging.Infof("Incident ID is: %s", pdClient.GetIncidentID())

	ocmClient, err := GetOCMClient()
	if err != nil {
		return fmt.Errorf("could not initialize ocm client: %w", err)
	}

	cloudProviderSupported, err := checkCloudProviderSupported(ocmClient, externalClusterID, []string{"aws"})
	if err != nil {
		return err
	}

	// We currently have no investigations supporting GCP. In the future, this check should be moved on
	// the investigation level, and we should be GCP or AWSClient based on this.
	// For now, we can silence alerts for clusters that are already in limited support and not handled by CAD
	if !cloudProviderSupported {

		// We forward everything CAD doesn't support investigations for to primary, as long as the clusters
		// aren't in limited support.
		logging.Info("Cloud provider is not supported, checking for limited support...")
		ls, err := ocmClient.IsInLimitedSupport(externalClusterID)
		if err != nil {
			err = pdClient.EscalateAlertWithNote(fmt.Sprintf("could not determine if cluster is in limited support: %s", err.Error()))
			if err != nil {
				return err
			}
		}
		if ls {
			logging.Info("cluster is in limited support, silencing")
			return pdClient.SilenceAlertWithNote("cluster is in limited support, silencing alert.")
		}

		err = pdClient.EscalateAlertWithNote("CAD Investigation skipped: cloud provider is not supported.")
		if err != nil {
			return err
		}

		return nil
	}

	baseAwsClient, err := GetAWSClient()
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
	// This triggers a cloud-credentials-are-missing investigation in case the jumpRole fails.
	customerAwsClient, err := jumpRoles(cluster, baseAwsClient, ocmClient, pdClient)
	if err != nil {
		return err
	}
	// If jumpRoles does not return an aws.Client and there was no error
	// then cluster is in limited support for missing cloud credentials
	if customerAwsClient == (&aws.SdkClient{}) {
		return nil
	}

	investigationResources := &investigation.Resources{Cluster: cluster, ClusterDeployment: clusterDeployment, AwsClient: customerAwsClient, OcmClient: ocmClient, PdClient: pdClient}

	investigation := investigation.NewInvestigation()

	switch alertType {
	case "ClusterHasGoneMissing":
		investigation.Triggered = chgm.InvestigateTriggered
		investigation.Resolved = chgm.InvestigateResolved
	default:
		// Should never happen as GetAlertType should fail on unsupported alerts
		return fmt.Errorf("alert is not supported by CAD: %s", alertType)
	}

	eventType := pdClient.GetEventType()
	logging.Infof("Starting investigation for %s with event type %s", alertType, eventType)

	switch eventType {
	case pagerduty.IncidentTriggered:
		return investigation.Triggered(investigationResources)
	case pagerduty.IncidentResolved:
		return investigation.Resolved(investigationResources)
	case pagerduty.IncidentReopened:
		return investigation.Reopened(investigationResources)
	case pagerduty.IncidentEscalated:
		return investigation.Escalated(investigationResources)
	default:
		return fmt.Errorf("event type '%s' is not supported", eventType)
	}
}

// jumpRoles will return an aws client or an error after trying to jump into support role
func jumpRoles(cluster *v1.Cluster, baseAwsClient aws.Client, ocmClient ocm.Client, pdClient pagerduty.Client) (*aws.SdkClient, error) {

	cssJumprole, ok := os.LookupEnv("CAD_AWS_CSS_JUMPROLE")
	if !ok {
		return &aws.SdkClient{}, fmt.Errorf("CAD_AWS_CSS_JUMPROLE is missing")
	}

	supportRole, ok := os.LookupEnv("CAD_AWS_SUPPORT_JUMPROLE")
	if !ok {
		return &aws.SdkClient{}, fmt.Errorf("CAD_AWS_SUPPORT_JUMPROLE is missing")
	}

	customerAwsClient, err := assumerole.AssumeSupportRoleChain(baseAwsClient, ocmClient, cluster, cssJumprole, supportRole)
	if err != nil {
		logging.Info("Failed assumeRole chain: ", err.Error())

		// If assumeSupportRoleChain fails, we evaluate if the credentials are missing based on the error message,
		// it is also possible the assumeSupportRoleChain failed for another reason (e.g. API errors)
		return &aws.SdkClient{}, ccam.Evaluate(cluster, err, ocmClient, pdClient)
	}
	logging.Info("Successfully jumpRoled into the customer account. Removing existing 'Cloud Credentials Are Missing' limited support reasons.")
	return customerAwsClient, ccam.RemoveLimitedSupport(cluster, ocmClient, pdClient)
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
func GetOCMClient() (*ocm.SdkClient, error) {
	cadOcmFilePath := os.Getenv("CAD_OCM_FILE_PATH")

	_, err := os.Stat(cadOcmFilePath)
	if os.IsNotExist(err) {
		configDir, err := os.UserConfigDir()
		if err != nil {
			return &ocm.SdkClient{}, err
		}
		cadOcmFilePath = filepath.Join(configDir, "/ocm/ocm.json")
	}

	return ocm.New(cadOcmFilePath)
}

// GetAWSClient will retrieve the AwsClient from the 'aws' package
func GetAWSClient() (*aws.SdkClient, error) {
	awsAccessKeyID, hasAwsAccessKeyID := os.LookupEnv("AWS_ACCESS_KEY_ID")
	awsSecretAccessKey, hasAwsSecretAccessKey := os.LookupEnv("AWS_SECRET_ACCESS_KEY")
	awsSessionToken, _ := os.LookupEnv("AWS_SESSION_TOKEN") // AWS_SESSION_TOKEN is optional
	awsDefaultRegion, hasAwsDefaultRegion := os.LookupEnv("AWS_DEFAULT_REGION")
	if !hasAwsAccessKeyID || !hasAwsSecretAccessKey {
		return &aws.SdkClient{}, fmt.Errorf("one of the required envvars in the list '(AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY)' is missing")
	}
	if !hasAwsDefaultRegion {
		awsDefaultRegion = "us-east-1"
	}

	return aws.NewClient(awsAccessKeyID, awsSecretAccessKey, awsSessionToken, awsDefaultRegion)
}

// GetPDClient will retrieve the PagerDuty from the 'pagerduty' package
func GetPDClient(webhookPayload []byte) (*pagerduty.SdkClient, error) {
	cadPD, hasCadPD := os.LookupEnv("CAD_PD_TOKEN")
	cadEscalationPolicy, hasCadEscalationPolicy := os.LookupEnv("CAD_ESCALATION_POLICY")
	cadSilentPolicy, hasCadSilentPolicy := os.LookupEnv("CAD_SILENT_POLICY")

	if !hasCadEscalationPolicy || !hasCadSilentPolicy || !hasCadPD {
		return &pagerduty.SdkClient{}, fmt.Errorf("one of the required envvars in the list '(CAD_ESCALATION_POLICY CAD_SILENT_POLICY CAD_PD_TOKEN)' is missing")
	}

	client, err := pagerduty.NewWithToken(cadEscalationPolicy, cadSilentPolicy, webhookPayload, cadPD)
	if err != nil {
		return &pagerduty.SdkClient{}, fmt.Errorf("could not initialize the client: %w", err)
	}

	return client, nil
}

// checkCloudProviderSupported takes a list of supported providers and checks if the
// cluster to investigate's provider is supported
func checkCloudProviderSupported(ocmClient *ocm.SdkClient, externalClusterID string, supportedProviders []string) (bool, error) {
	cloudProvider, err := ocmClient.GetCloudProviderID(externalClusterID)
	if err != nil {
		return false, err
	}

	for _, provider := range supportedProviders {
		if cloudProvider == provider {
			return true, nil
		}
	}

	logging.Infof("Unsupported cloud provider: %s", cloudProvider)
	return false, nil
}

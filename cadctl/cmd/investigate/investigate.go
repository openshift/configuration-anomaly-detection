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
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	v1 "github.com/openshift-online/ocm-sdk-go/clustersmgmt/v1"
	"github.com/openshift/configuration-anomaly-detection/pkg/aws"
	"github.com/openshift/configuration-anomaly-detection/pkg/aws/assumerole"
	investigation "github.com/openshift/configuration-anomaly-detection/pkg/investigations"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/ccam"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/chgm"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/cpd"
	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
	ocm "github.com/openshift/configuration-anomaly-detection/pkg/ocm"
	"github.com/openshift/configuration-anomaly-detection/pkg/pagerduty"
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
	logLevelString = "info"
	payloadPath    = "./payload.json"
)

func init() {
	InvestigateCmd.Flags().StringVarP(&payloadPath, "payload-path", "p", payloadPath, "the path to the payload")
	InvestigateCmd.Flags().StringVarP(&logLevelString, "log-level", "l", logLevelString, "the log level [debug,info,warn,error,fatal], default = info")

	err := InvestigateCmd.MarkFlagRequired("payload-path")
	if err != nil {
		logging.Warn("Could not mark flag 'payload-path' as required")
	}
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

	ocmClient, err := GetOCMClient()
	if err != nil {
		return fmt.Errorf("could not initialize ocm client: %w", err)
	}

	// clusterID can end up being either be the internal or external ID.
	// We don't really care, as we only use this to initialize the cluster object,
	// which will contain both IDs.
	clusterID, err := parseClusterIDFromAlert(pdClient)
	if err != nil {
		return fmt.Errorf("parseClusterIdFromAlert failed on: %w", err)
	}

	logging.Infof("Incident link: %s", pdClient.GetIncidentRef())

	// After this point we know CAD will investigate the alert
	// so we can initialize the other clients
	alertType, err := isAlertSupported(pdClient.GetTitle())
	if err != nil {
		err = pdClient.EscalateAlert()
		if err != nil {
			return fmt.Errorf("Could not escalate unsupported alert: %w", err)
		}

		return nil
	}

	cluster, err := ocmClient.GetClusterInfo(clusterID)
	if err != nil {
		return fmt.Errorf("could not retrieve cluster info for %s: %w", clusterID, err)
	}
	// From this point on, we normalize to internal ID, as this ID always exists.
	// For installing clusters, externalID can be empty.
	internalClusterID := cluster.ID()

	// initialize logger for the internal-cluster-id context
	logging.RawLogger = logging.InitLogger(logLevelString, internalClusterID)

	alertName, err := alertType.String()
	if err != nil {
		return err
	}

	cloudProviderSupported, err := checkCloudProviderSupported(cluster, []string{"aws"})
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
		ls, err := ocmClient.IsInLimitedSupport(internalClusterID)
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

	clusterDeployment, err := ocmClient.GetClusterDeployment(internalClusterID)
	if err != nil {
		return fmt.Errorf("could not retrieve Cluster Deployment for %s: %w", internalClusterID, err)
	}

	// Try to jump into support role
	// This triggers a cloud-credentials-are-missing investigation in case the jumpRole fails.
	customerAwsClient, err := jumpRoles(cluster, baseAwsClient, ocmClient, pdClient)
	if err != nil {
		return err
	}
	// If jumpRoles does not return an *aws.Client and there was no error
	// then cluster is in limited support for missing cloud credentials
	if customerAwsClient == nil {
		return nil
	}

	investigationResources := &investigation.Resources{Cluster: cluster, ClusterDeployment: clusterDeployment, AwsClient: customerAwsClient, OcmClient: ocmClient, PdClient: pdClient}

	run := investigation.NewInvestigation()

	switch alertType {
	case investigation.ClusterHasGoneMissing:
		run.Triggered = chgm.InvestigateTriggered
		run.Resolved = chgm.InvestigateResolved
	case investigation.ClusterProvisioningDelay:
		run.Triggered = cpd.InvestigateTriggered
	default:
		// Should never happen as GetAlertType should fail on unsupported alerts
		return errors.New("alert is not supported by CAD")
	}

	eventType := pdClient.GetEventType()
	logging.Infof("Starting investigation for %s with event type %s", alertName, eventType)

	switch eventType {
	case pagerduty.IncidentTriggered:
		return run.Triggered(investigationResources)
	case pagerduty.IncidentResolved:
		return run.Resolved(investigationResources)
	case pagerduty.IncidentReopened:
		return run.Reopened(investigationResources)
	case pagerduty.IncidentEscalated:
		return run.Escalated(investigationResources)
	default:
		return fmt.Errorf("event type '%s' is not supported", eventType)
	}
}

// jumpRoles will return an aws client or an error after trying to jump into support role
func jumpRoles(cluster *v1.Cluster, baseAwsClient aws.Client, ocmClient ocm.Client, pdClient pagerduty.Client) (*aws.SdkClient, error) {
	cssJumprole, ok := os.LookupEnv("CAD_AWS_CSS_JUMPROLE")
	if !ok {
		return nil, fmt.Errorf("CAD_AWS_CSS_JUMPROLE is missing")
	}

	supportRole, ok := os.LookupEnv("CAD_AWS_SUPPORT_JUMPROLE")
	if !ok {
		return nil, fmt.Errorf("CAD_AWS_SUPPORT_JUMPROLE is missing")
	}

	customerAwsClient, err := assumerole.AssumeSupportRoleChain(baseAwsClient, ocmClient, cluster, cssJumprole, supportRole)
	if err != nil {
		logging.Info("Failed assumeRole chain: ", err.Error())

		// If assumeSupportRoleChain fails, we evaluate if the credentials are missing based on the error message,
		// it is also possible the assumeSupportRoleChain failed for another reason (e.g. API errors)
		return nil, ccam.Evaluate(cluster, err, ocmClient, pdClient)
	}
	logging.Info("Successfully jumpRoled into the customer account. Removing existing 'Cloud Credentials Are Missing' limited support reasons.")
	return customerAwsClient, ccam.RemoveLimitedSupport(cluster, ocmClient, pdClient)
}

// isAlertSupported will return the alertname as enum type of the alert if it is supported, otherwise an error
func isAlertSupported(alertTitle string) (investigation.AlertType, error) {
	// We currently map to the alert by using the title, we should use the name in the alert note in the future.
	// This currently isn't feasible yet, as CPD's alertmanager doesn't allow for the field to exist.

	if strings.Contains(alertTitle, "has gone missing") {
		return investigation.ClusterHasGoneMissing, nil
	} else if strings.Contains(alertTitle, "ClusterProvisioningDelay -") {
		return investigation.ClusterProvisioningDelay, nil
	}

	return investigation.Undefined, fmt.Errorf("Alert is not supported by CAD: %s", alertTitle)
}

// GetOCMClient will retrieve the OcmClient from the 'ocm' package
func GetOCMClient() (*ocm.SdkClient, error) {
	cadOcmFilePath := os.Getenv("CAD_OCM_FILE_PATH")

	_, err := os.Stat(cadOcmFilePath)
	if os.IsNotExist(err) {
		configDir, err := os.UserConfigDir()
		if err != nil {
			return nil, err
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
		return nil, fmt.Errorf("one of the required envvars in the list '(AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY)' is missing")
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
		return nil, fmt.Errorf("one of the required envvars in the list '(CAD_ESCALATION_POLICY CAD_SILENT_POLICY CAD_PD_TOKEN)' is missing")
	}

	client, err := pagerduty.NewWithToken(cadEscalationPolicy, cadSilentPolicy, webhookPayload, cadPD)
	if err != nil {
		return nil, fmt.Errorf("could not initialize the client: %w", err)
	}

	return client, nil
}

// checkCloudProviderSupported takes a list of supported providers and checks if the
// cluster to investigate's provider is supported
func checkCloudProviderSupported(cluster *v1.Cluster, supportedProviders []string) (bool, error) {
	cloudProvider, ok := cluster.GetCloudProvider()
	if !ok {
		return false, fmt.Errorf("Failed to get clusters cloud provider")
	}

	for _, provider := range supportedProviders {
		if cloudProvider.ID() == provider {
			return true, nil
		}
	}

	logging.Infof("Unsupported cloud provider: %s", cloudProvider)
	return false, nil
}

// Returns either the internal or external ID (differs per service)
// - app-sre-alertmanager contains an internal ID in the title in the format uhc-<env>-<internal-id>
// - everything else should adhere to being a separate field in the alert note.
func parseClusterIDFromAlert(pdClient *pagerduty.SdkClient) (string, error) {
	var clusterID string
	var err error

	switch pdClient.GetServiceName() {
	case "app-sre-alertmanager":
		clusterID, err = cpd.GetCPDAlertInternalID(pdClient.GetTitle())
		if err != nil {
			return "", fmt.Errorf("Failed to get CPD alert internal ID: %w", err)
		}
	default:
		clusterID, err = pdClient.RetrieveExternalClusterID()
		if err != nil {
			return "", fmt.Errorf("RetrieveExternalClusterID failed on: %w", err)
		}
	}
	return clusterID, nil
}

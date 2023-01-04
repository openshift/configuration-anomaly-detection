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
	"time"

	"github.com/openshift/configuration-anomaly-detection/pkg/services/ccam"

	"github.com/openshift/configuration-anomaly-detection/pkg/aws"
	ocm "github.com/openshift/configuration-anomaly-detection/pkg/ocm"
	"github.com/openshift/configuration-anomaly-detection/pkg/pagerduty"
	"github.com/openshift/configuration-anomaly-detection/pkg/services/assumerole"
	"github.com/openshift/configuration-anomaly-detection/pkg/services/chgm"
	"github.com/spf13/cobra"
)

const (
	pagerdutyIncidentResolved = "incident.resolved"
)

// ClusterMissingCmd represents the cluster-missing command
var ClusterMissingCmd = &cobra.Command{
	Use:   "cluster-missing",
	Short: "Will remediate the cluster-missing alert",
	RunE:  run,
}

func run(cmd *cobra.Command, args []string) error {

	fmt.Println("Running CAD with webhook payload:")
	data, err := os.ReadFile(payloadPath)
	if err != nil {
		return fmt.Errorf("failed to read webhook payload: %w", err)
	}
	fmt.Printf("%s\n", string(data))

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

	incidentID, err := pdClient.ExtractIncidentIDFromPayload(payloadPath, pagerduty.RealFileReader{})
	if err != nil {
		return fmt.Errorf("GetIncidentID failed on: %w", err)
	}
	fmt.Printf("Incident ID is: %s\n", incidentID)

	externalClusterID, err := pdClient.ExtractExternalIDFromPayload(payloadPath, pagerduty.RealFileReader{})
	if err != nil {
		return fmt.Errorf("GetExternalID failed on: %w", err)
	}

	eventType, err := pdClient.ExtractEventTypeFromPayload(payloadPath, pagerduty.RealFileReader{})
	if err != nil {
		return fmt.Errorf("could not determine event type: %w", err)
	}

	fmt.Printf("ClusterExternalID is: %s\n", externalClusterID)

	cloudProvider, err := ocmClient.GetCloudProviderID(externalClusterID)
	if err != nil {
		return err
	} else if cloudProvider != "aws" {
		return fmt.Errorf("cloudprovider is not supported: %s", cloudProvider)
	}

	arClient := assumerole.Client{
		Service: chgm.Provider{
			AwsClient: awsClient,
			OcmClient: ocmClient,
			PdClient:  pdClient,
		},
	}
	cssJumprole, ok := os.LookupEnv("CAD_AWS_CSS_JUMPROLE")
	if !ok {
		return fmt.Errorf("CAD_AWS_CSS_JUMPROLE is missing")
	}

	supportRole, ok := os.LookupEnv("CAD_AWS_SUPPORT_JUMPROLE")
	if !ok {
		return fmt.Errorf("CAD_AWS_SUPPORT_JUMPROLE is missing")
	}

	customerAwsClient, err := arClient.AssumeSupportRoleChain(externalClusterID, cssJumprole, supportRole)
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

	// building twice to override the awsClient
	chgmClient := chgm.Client{
		Service: chgm.Provider{
			AwsClient: customerAwsClient,
			OcmClient: ocmClient,
			PdClient:  pdClient,
		},
	}

	fmt.Println("Starting Cloud Provider investigation...")

	if eventType == pagerdutyIncidentResolved {
		return evaluateRestoredCluster(chgmClient, externalClusterID)
	}
	return evaluateMissingCluster(chgmClient, incidentID, externalClusterID)
}

// evaluateMissingCluster checks CHGM incident.triggered payload
// checks stopped instances and existing LS to determine if alert should be escalated
func evaluateMissingCluster(chgmClient chgm.Client, incidentID string, externalClusterID string) error {
	res, err := chgmClient.InvestigateStoppedInstances(externalClusterID)
	if err != nil {
		return fmt.Errorf("InvestigateInstances failed on %s: %w", externalClusterID, err)
	}
	fmt.Printf("the investigation returned %#v\n", res)

	lsExists, err := chgmClient.CHGMLimitedSupportExists(externalClusterID)
	if err != nil {
		return fmt.Errorf("failed to determine if limited support reason already exists: %w", err)
	}

	// if lsExists, silence alert and add investigation to notes
	if lsExists {
		err = chgmClient.SilenceAlert(incidentID, res.String())
		if err != nil {
			return fmt.Errorf("assigning the incident to Silent Test did not work: %w", err)
		}
		return nil
	}

	if res.UserAuthorized {
		fmt.Println("The node shutdown was not the customer. Should alert SRE")
		err := chgmClient.EscalateAlert(incidentID, res.String())
		if err != nil {
			return fmt.Errorf("could not escalate the alert %s: %w", incidentID, err)
		}
		return nil
	}

	fmt.Println("Sending CHGM limited support reason")
	reason, err := chgmClient.PostCHGMLimitedSupport(externalClusterID)
	if err != nil {
		return fmt.Errorf("failed posting limited support reason: %w", err)
	}
	res.LimitedSupportReason = reason

	err = chgmClient.SilenceAlert(incidentID, res.String())
	if err != nil {
		return fmt.Errorf("assigning the incident to Silent Test did not work: %w", err)
	}

	return nil
}

// evaluateRestoredCluster will take appropriate action against a cluster whose CHGM incident has resolved.
//
// Because CAD only runs a single time against a cluster when the alert resolves, robust retry logic is needed to
// ensure the cluster is in a supportable state afterwards
func evaluateRestoredCluster(chgmClient chgm.Client, externalClusterID string) error {
	serviceID := retryUntilServiceObtained(chgmClient)
	res, err := chgmClient.InvestigateStartedInstances(externalClusterID)
	// The investigation encountered an error & never completed - alert Primary and report the error, retrying as many times as necessary to escalate the issue
	if err != nil {
		fmt.Printf("Failure detected while investigating cluster '%s', attempting to notify Primary. Error: %v\n", externalClusterID, err)
		originalErr := err
		retries := 1

		err = chgmClient.CreateIncidentForInvestigationFailure(originalErr, externalClusterID, serviceID)
		for err != nil {
			fmt.Printf("Failed to escalate to Primary, retrying (attempt %d). Error encountered when escalating: %v\n", retries, err)

			// Sleep for a time, backing off based on the number of retries (up to 300 seconds)
			sleepBeforeRetrying(retries, 300)
			retries++

			err = chgmClient.CreateIncidentForInvestigationFailure(originalErr, externalClusterID, serviceID)
		}
		fmt.Println("Primary has been alerted")
		return fmt.Errorf("InvestigateStartedInstances failed for %s: %w", externalClusterID, originalErr)
	}

	// Investigation completed, but the state in OCM indicated the cluster didn't need investigation
	if res.ClusterNotEvaluated {
		fmt.Printf("Cluster has state '%s' in OCM, and so investigation is not need\n", res.ClusterState)
		return nil
	}

	// Investigation completed, but the cluster has not been restored properly - keep in limited support & alert Primary, retrying as many times as necessary to escalate the issue
	if res.Error != "" {
		fmt.Printf("Cluster failed post-restart check. Result: %#v\n", res)
		retries := 1
		err = chgmClient.CreateIncidentForRestoredCluster(res.Error, externalClusterID, serviceID)
		for err != nil {
			fmt.Printf("Failed to escalate to Primary to report investigation results, retrying (attempt %d). Error encountered when escalating: %v\n", retries, err)

			// Sleep for a time, backing off based on the number of retries (up to 300 seconds)
			sleepBeforeRetrying(retries, 300)
			retries++

			err = chgmClient.CreateIncidentForRestoredCluster(res.Error, externalClusterID, serviceID)
		}
		fmt.Println("Primary has been alerted")
		return nil
	}

	// Cluster has been restored - remove any limited support reasons that CAD may have added as the result of it's
	// missing instances investigation
	//
	// If we fail to remove either of the Limited Support reasons after several attempts, alert Primary

	// Start by removing any 'Cloud Credentials Are Missing' alerts added by CAD
	fmt.Println("Investigation complete. Cluster should be removed from Limited Support")
	fmt.Println("Removing 'Cloud Credentials Are Missing' Limited Support reasons")
	retries := 1
	var removedReasons bool
	removedReasons, err = chgmClient.RemoveCCAMLimitedSupport(externalClusterID)
	for err != nil && retries <= 3 {
		fmt.Printf("Failed to remove CCAM Limited Support reason from cluster %s: %v\n", externalClusterID, err)

		sleepBeforeRetrying(retries, 300)
		retries++

		removedReasons, err = chgmClient.RemoveCCAMLimitedSupport(externalClusterID)
	}
	// After 3 retries, if the LS reason hasn't been removed - alert Primary
	if err != nil {
		fmt.Println("Failed 3 times to remove CCAM Limited support reason from cluster. Attempting to alert Primary.")
		originalErr := err
		retries = 1

		err = chgmClient.CreateIncidentForLimitedSupportRemovalFailure(originalErr, externalClusterID, serviceID)
		for err != nil {
			fmt.Printf("Failed to alert Primary (attempt %d). Err: %v\n", retries, err)
			fmt.Println("Retrying")

			sleepBeforeRetrying(retries, 300)
			retries++

			err = chgmClient.CreateIncidentForLimitedSupportRemovalFailure(originalErr, externalClusterID, serviceID)
		}
		fmt.Println("Primary has been alerted")
		return fmt.Errorf("failed to remove CCAM Limited Support reason from cluster %s: %w", externalClusterID, originalErr)
	}

	if removedReasons {
		fmt.Println("Removed CCAM Limited Support reason from cluster")
	} else {
		fmt.Println("No CCAM Limited Support reasons needed to be removed")
	}

	// Remove 'Cluster Has Gone Missing' Limited Support reasons added by CAD
	fmt.Println("Removing 'Cluster Has Gone Missing' Limited Support reasons")
	retries = 1
	removedReasons, err = chgmClient.RemoveCHGMLimitedSupport(externalClusterID)
	for err != nil && retries <= 3 {
		fmt.Printf("Failed to remove CHGM Limited Support reason from cluster %s: %v\n", externalClusterID, err)

		// Sleep for a time, based on the number of retries (up to 300 seconds)
		sleepBeforeRetrying(retries, 300)
		retries++

		removedReasons, err = chgmClient.RemoveCHGMLimitedSupport(externalClusterID)
	}
	// After 3 retries, if the LS reason hasn't been removed - alert Primary
	if err != nil {
		fmt.Println("Failed 3 times to remove CHGM Limited Support reason from cluster. Attempting to alert Primary.")
		originalErr := err
		retries = 1

		err = chgmClient.CreateIncidentForLimitedSupportRemovalFailure(originalErr, externalClusterID, serviceID)
		for err != nil {
			fmt.Printf("Failed to alert Primary (attempt %d). Err: %v\n", retries, err)
			fmt.Println("Retrying")

			sleepBeforeRetrying(retries, 300)
			retries++

			err = chgmClient.CreateIncidentForLimitedSupportRemovalFailure(originalErr, externalClusterID, serviceID)

		}
		fmt.Println("Primary has been alerted")
		return fmt.Errorf("failed to remove CHGM Limited Support reason from cluster %s: %w", externalClusterID, originalErr)
	}
	if removedReasons {
		fmt.Println("Removed CHGM Limited Support reason from cluster")
	} else {
		fmt.Println("No CHGM Limited Support reasons needed to be removed")
	}
	return nil
}

// retryUntilServiceObtained attempts to retrieve the serviceID from the PD payload, retrying until successful
func retryUntilServiceObtained(chgmClient chgm.Client) string {
	// Retrieve the service to alert on, retrying until we succeed
	serviceID, err := chgmClient.ExtractServiceIDFromPayload(payloadPath, pagerduty.RealFileReader{})
	retries := 1
	for err != nil {
		fmt.Printf("Failed to retrieve service from PagerDuty, retrying (attempt %d). Error encountered: %v\n", retries, err)

		// Sleep for a time, based on the number of retries (up to 300 seconds)
		sleepBeforeRetrying(retries, 300)
		retries++

		serviceID, err = chgmClient.ExtractServiceIDFromPayload(payloadPath, pagerduty.RealFileReader{})
	}
	return serviceID
}

// sleepBeforeRetrying sleeps with an exponential backoff based on the current retry, up to the given maximum sleep time.
func sleepBeforeRetrying(currentRetry, maxSleepSeconds int) {
	duration := currentRetry * currentRetry
	sleepTime := time.Duration(duration) * time.Second
	if duration > maxSleepSeconds {
		sleepTime = time.Duration(maxSleepSeconds) * time.Second
	}

	fmt.Printf("Waiting %s seconds before trying again\n", sleepTime.String())
	time.Sleep(sleepTime)
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

var (
	payloadPath = "./payload.json"
)

func init() {
	const payloadPathFlagName = "payload-path"
	ClusterMissingCmd.Flags().StringVarP(&payloadPath, payloadPathFlagName, "p", payloadPath, "the path to the payload")
}

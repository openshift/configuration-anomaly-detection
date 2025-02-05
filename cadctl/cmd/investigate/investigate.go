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

	cmv1 "github.com/openshift-online/ocm-sdk-go/clustersmgmt/v1"
	investigation "github.com/openshift/configuration-anomaly-detection/pkg/investigations"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/ccam"
	investigation_mapping "github.com/openshift/configuration-anomaly-detection/pkg/investigations/mapping"
	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
	"github.com/openshift/configuration-anomaly-detection/pkg/managedcloud"
	"github.com/openshift/configuration-anomaly-detection/pkg/metrics"
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

	pdClient, err := pagerduty.GetPDClient(payload)
	if err != nil {
		return fmt.Errorf("could not initialize pagerduty client: %w", err)
	}

	logging.Infof("Incident link: %s", pdClient.GetIncidentRef())

	alertInvestigation := investigation_mapping.GetInvestigation(pdClient.GetTitle())

	// Escalate all unsupported alerts
	if alertInvestigation == nil {
		err = pdClient.EscalateIncident()
		if err != nil {
			return fmt.Errorf("could not escalate unsupported alert: %w", err)
		}
		return nil
	}

	metrics.Inc(metrics.Alerts, alertInvestigation.Name)

	// clusterID can end up being either be the internal or external ID.
	// We don't really care, as we only use this to initialize the cluster object,
	// which will contain both IDs.
	clusterID, err := pdClient.RetrieveClusterID()
	if err != nil {
		return err
	}

	ocmClient, err := GetOCMClient()
	if err != nil {
		return fmt.Errorf("could not initialize ocm client: %w", err)
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

	requiresInvestigation, err := clusterRequiresInvestigation(cluster, pdClient, ocmClient)
	if err != nil || !requiresInvestigation {
		return err
	}

	clusterDeployment, err := ocmClient.GetClusterDeployment(internalClusterID)
	if err != nil {
		return fmt.Errorf("could not retrieve Cluster Deployment for %s: %w", internalClusterID, err)
	}

	customerAwsClient, err := managedcloud.CreateCustomerAWSClient(cluster, ocmClient)
	if err != nil {
		ccamResources := &investigation.Resources{Cluster: cluster, ClusterDeployment: clusterDeployment, AwsClient: customerAwsClient, OcmClient: ocmClient, PdClient: pdClient, AdditionalResources: map[string]interface{}{"error": err}}
		result, err := ccam.Investigate(ccamResources)
		updateMetrics(alertInvestigation.Name, &result)
		return err
	}

	investigationResources := &investigation.Resources{Cluster: cluster, ClusterDeployment: clusterDeployment, AwsClient: customerAwsClient, OcmClient: ocmClient, PdClient: pdClient}

	logging.Infof("Starting investigation for %s", alertInvestigation.Name)
	result, err := alertInvestigation.Run(investigationResources)
	updateMetrics(alertInvestigation.Name, &result)
	return err
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

// Checks pre-requisites for a cluster investigation:
// - the cluster's state is supported by CAD for an investigation (= not uninstalling)
// - the cloud provider is supported by CAD (cluster is AWS)
// Performs according pagerduty actions and returns whether CAD needs to investigate the cluster
func clusterRequiresInvestigation(cluster *cmv1.Cluster, pdClient *pagerduty.SdkClient, ocmClient *ocm.SdkClient) (bool, error) {
	if cluster.State() == cmv1.ClusterStateUninstalling {
		logging.Info("Cluster is uninstalling and requires no investigation. Silencing alert.")
		return false, pdClient.SilenceIncidentWithNote("CAD: Cluster is already uninstalling, silencing alert.")
	}

	if cluster.AWS() == nil {
		logging.Info("Cloud provider unsupported, forwarding to primary.")
		return false, pdClient.EscalateIncidentWithNote("CAD could not run an automated investigation on this cluster: unsupported cloud provider.")
	}

	isAccessProtected, err := ocmClient.IsAccessProtected(cluster)
	if err != nil {
		logging.Warnf("failed to get access protection status for cluster. %w. Continuing...")
	}
	if isAccessProtected {
		logging.Info("Cluster is access protected. Escalating alert.")
		return false, pdClient.EscalateIncidentWithNote("CAD is unable to run against access protected clusters. Please investigate.")
	}
	return true, nil
}

func updateMetrics(investigationName string, result *investigation.InvestigationResult) {
	if result.ServiceLogSent.Performed {
		metrics.Inc(metrics.ServicelogSent, append([]string{investigationName}, result.ServiceLogSent.Labels...)...)
	}
	if result.ServiceLogPrepared.Performed {
		metrics.Inc(metrics.ServicelogPrepared, append([]string{investigationName}, result.ServiceLogPrepared.Labels...)...)
	}
	if result.LimitedSupportSet.Performed {
		metrics.Inc(metrics.LimitedSupportSet, append([]string{investigationName}, result.LimitedSupportSet.Labels...)...)
	}
}

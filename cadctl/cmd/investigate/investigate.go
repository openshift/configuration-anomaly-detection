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
	"strings"

	cmv1 "github.com/openshift-online/ocm-sdk-go/clustersmgmt/v1"
	"github.com/openshift/configuration-anomaly-detection/cadctl/config"
	investigations "github.com/openshift/configuration-anomaly-detection/pkg/investigations"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/ccam"
	investigation "github.com/openshift/configuration-anomaly-detection/pkg/investigations/investigation"
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
	PreRunE: func(cmd *cobra.Command, _ []string) error {
		var err error
		var c config.Config

		c, err = config.BuildConfig(cmd)
		if err != nil {
			return fmt.Errorf("failed to build config: %w", err)
		}

		// Initialize the logger here because it depends on user input
		logging.RawLogger = logging.InitLogger(c.LogLevel)
		logging.RawLogger = logging.WithPipelineName(logging.RawLogger, c.PipelineName)

		// configure the RunE command using a wrapper to
		// append the configuration into the command
		cmd.RunE = func(cmd *cobra.Command, args []string) error {
			if err := run(c, cmd, args); err != nil {
				logging.Error(err)
			}
			return err
		}

		return nil
	},
	RunE: func(_ *cobra.Command, _ []string) error {
		// DO NOT REMOVE
		// this ensures RunE work as expected
		// RunE is set in the PreRunE function
		// this works because the RunE is always called after PreRunE
		return nil
	},
}

var payloadPath = "./payload.json"

const pagerdutyTitlePrefix = "[CAD Investigated]"

func init() {
	InvestigateCmd.Flags().StringVarP(&payloadPath, "payload-path", "p", payloadPath, "the path to the payload")

	err := InvestigateCmd.MarkFlagRequired("payload-path")
	if err != nil {
		logging.Warn("Could not mark flag 'payload-path' as required")
	}
}

func run(c config.Config, _ *cobra.Command, _ []string) error {
	var err error

	if c.PrometheusPushGateway == "" {
		logging.Warn("metrics disabled, set env 'CAD_PROMETHEUS_PUSHGATEWAY' to push metrics")
	}

	err = metrics.Push(c.PrometheusPushGateway)
	if err != nil {
		logging.Warnf("failed to push metrics: %v", err)
	}

	// early init of logger for logs before clusterID is known
	payload, err := os.ReadFile(payloadPath)
	if err != nil {
		return fmt.Errorf("failed to read webhook payload: %w", err)
	}
	logging.Info("Running CAD with webhook payload:", string(payload))

	if c.PagerDutyToken == "" {
		return fmt.Errorf("missing PagerDuty token")
	}
	if c.PagerDutySilentPolicy == "" {
		return fmt.Errorf("missing PagerDuty silent policy")
	}

	pdClient, err := pagerduty.GetPDClient(payload, c.PagerDutyToken, c.PagerDutySilentPolicy)
	if err != nil {
		return fmt.Errorf("could not initialize pagerduty client: %w", err)
	}

	logging.Infof("Incident link: %s", pdClient.GetIncidentRef())

	var investigationResources *investigation.Resources

	defer func() {
		if err != nil {
			handleCADFailure(err, investigationResources, pdClient)
		}
	}()

	alertInvestigation := investigations.GetInvestigation(pdClient.GetTitle(), c.Experimental)

	// Escalate all unsupported alerts
	if alertInvestigation == nil {
		err = pdClient.EscalateIncident()
		if err != nil {
			return fmt.Errorf("could not escalate unsupported alert: %w", err)
		}
		return nil
	}

	metrics.Inc(metrics.Alerts, alertInvestigation.Name())

	// clusterID can end up being either be the internal or external ID.
	// We don't really care, as we only use this to initialize the cluster object,
	// which will contain both IDs.
	clusterID, err := pdClient.RetrieveClusterID()
	if err != nil {
		return err
	}

	var ocmClient *ocm.SdkClient
	var ocmErr error

	ocmClient, ocmErr = ocm.NewFromClientKeyPair(c.CadOcmURL, c.CadOcmClientID, c.CadOcmClientSecret)
	if ocmErr != nil {
		return fmt.Errorf("could not initialize ocm client: %w", err)
	}

	cluster, err := ocmClient.GetClusterInfo(clusterID)
	if err != nil {
		if strings.Contains(err.Error(), "no cluster found") {
			logging.Warnf("No cluster found with ID '%s'. Exiting.", clusterID)
			return pdClient.EscalateIncidentWithNote("CAD was unable to find the incident cluster in OCM. An alert for a non-existing cluster is unexpected. Please investigate manually.")
		}
		return fmt.Errorf("could not retrieve cluster info for %s: %w", clusterID, err)
	}

	// From this point on, we normalize to internal ID, as this ID always exists.
	// For installing clusters, externalID can be empty.
	internalClusterID := cluster.ID()

	// add the internal-cluster-id context to the logger
	logging.RawLogger = logging.WithClusterID(logging.RawLogger, internalClusterID)

	requiresInvestigation, err := clusterRequiresInvestigation(cluster, pdClient, ocmClient)
	if err != nil || !requiresInvestigation {
		return err
	}

	clusterDeployment, err := ocmClient.GetClusterDeployment(internalClusterID)
	if err != nil {
		return fmt.Errorf("could not retrieve Cluster Deployment for %s: %w", internalClusterID, err)
	}

	if c.BackplaneURL == "" {
		return fmt.Errorf("missing backplane URL")
	}
	if c.BackplaneProxyURL == "" {
		logging.Warn("missing backplane proxy URL, using default")
	}
	if c.BackplaneInitialARN == "" {
		return fmt.Errorf("missing backplane initial ARN")
	}
	customerAwsClient, err := managedcloud.CreateCustomerAWSClient(
		cluster,
		ocmClient,
		c.BackplaneURL,
		c.BackplaneProxyURL,
		c.BackplaneInitialARN,
		c.AWSProxy,
	)
	if err != nil {
		ccamResources := &investigation.Resources{Name: "ccam", Cluster: cluster, ClusterDeployment: clusterDeployment, AwsClient: customerAwsClient, OcmClient: ocmClient, PdClient: pdClient, Notes: nil, AdditionalResources: map[string]interface{}{"error": err}}
		inv := ccam.Investigation{}
		result, err := inv.Run(ccamResources)
		updateMetrics(alertInvestigation.Name(), &result)
		return err
	}

	investigationResources = &investigation.Resources{
		Name:              alertInvestigation.Name(),
		BackplaneURL:      c.BackplaneURL,
		Cluster:           cluster,
		ClusterDeployment: clusterDeployment,
		AwsClient:         customerAwsClient,
		OcmClient:         ocmClient,
		PdClient:          pdClient,
		Notes:             nil,
	}

	logging.Infof("Starting investigation for %s", alertInvestigation.Name())
	result, err := alertInvestigation.Run(investigationResources)
	updateMetrics(alertInvestigation.Name(), &result)
	if err != nil {
		return err
	}

	return updateIncidentTitle(pdClient)
}

func handleCADFailure(err error, resources *investigation.Resources, pdClient *pagerduty.SdkClient) {
	logging.Errorf("CAD investigation failed: %v", err)

	var notes string
	if resources != nil && resources.Notes != nil {
		resources.Notes.AppendWarning("🚨 CAD investigation failed, CAD team has been notified. Please investigate manually. 🚨")
		notes = resources.Notes.String()
	} else {
		notes = "🚨 CAD investigation failed prior to resource initilization, CAD team has been notified. Please investigate manually. 🚨"
	}

	if pdClient != nil {
		pdErr := pdClient.EscalateIncidentWithNote(notes)
		if pdErr != nil {
			logging.Errorf("Failed to escalate notes to PagerDuty: %v", pdErr)
		} else {
			logging.Info("CAD failure & incident notes added to PagerDuty")
		}
	} else {
		logging.Errorf("Failed to obtain PagerDuty client, unable to escalate CAD failure to PagerDuty notes.")
	}
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

func updateIncidentTitle(pdClient *pagerduty.SdkClient) error {
	currentTitle := pdClient.GetTitle()
	if strings.Contains(currentTitle, pagerdutyTitlePrefix) {
		return nil
	}
	newTitle := fmt.Sprintf("%s %s", pagerdutyTitlePrefix, currentTitle)
	err := pdClient.UpdateIncidentTitle(newTitle)
	if err != nil {
		return fmt.Errorf("failed to update PagerDuty incident title: %w", err)
	}
	return nil
}

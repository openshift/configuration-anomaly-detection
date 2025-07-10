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
	"strconv"
	"strings"

	cmv1 "github.com/openshift-online/ocm-sdk-go/clustersmgmt/v1"
	aws "github.com/openshift/configuration-anomaly-detection/pkg/aws"
	investigations "github.com/openshift/configuration-anomaly-detection/pkg/investigations"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/ccam"
	investigation "github.com/openshift/configuration-anomaly-detection/pkg/investigations/investigation"
	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
	"github.com/openshift/configuration-anomaly-detection/pkg/managedcloud"
	"github.com/openshift/configuration-anomaly-detection/pkg/metrics"
	ocm "github.com/openshift/configuration-anomaly-detection/pkg/ocm"
	"github.com/openshift/configuration-anomaly-detection/pkg/pagerduty"
	hivev1 "github.com/openshift/hive/apis/hive/v1"

	"github.com/spf13/cobra"
	"go.uber.org/dig"
)

// InvestigateCmd represents the entry point for alert investigation
var InvestigateCmd = &cobra.Command{
	Use:          "investigate",
	SilenceUsage: true,
	Short:        "Filter for and investigate supported alerts",
	RunE:         run,
}

var (
	logLevelFlag    = ""
	payloadPath     = "./payload.json"
	pipelineNameEnv = ""
)

const pagerdutyTitlePrefix = "[CAD Investigated]"

func init() {
	InvestigateCmd.Flags().StringVarP(&payloadPath, "payload-path", "p", payloadPath, "the path to the payload, defaults to './payload.json'")
	InvestigateCmd.Flags().StringVarP(&logLevelFlag, "log-level", "l", "", "the log level [debug,info,warn,error,fatal], default = info")

	if envLogLevel, exists := os.LookupEnv("LOG_LEVEL"); exists {
		logLevelFlag = envLogLevel
	}

	pipelineNameEnv = os.Getenv("PIPELINE_NAME")
}

func run(cmd *cobra.Command, _ []string) error {
	// Setup the dig container for DI
	container := dig.New()
	// early init of logger for logs before clusterID is known
	logging.RawLogger = logging.InitLogger(logLevelFlag, pipelineNameEnv, "")

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

	defer func() {
		if err != nil {
			handleCADFailure(err, pdClient)
		}
	}()

	err = container.Provide(func() pagerduty.Client { return pdClient })
	if err != nil {
		return err
	}

	experimentalEnabledVar := os.Getenv("CAD_EXPERIMENTAL_ENABLED")
	cadExperimentalEnabled, _ := strconv.ParseBool(experimentalEnabledVar)
	alertInvestigation := investigations.GetInvestigation(pdClient.GetTitle(), cadExperimentalEnabled)

	// Escalate all unsupported alerts
	if alertInvestigation == nil {
		err = pdClient.EscalateIncident()
		if err != nil {
			return fmt.Errorf("could not escalate unsupported alert: %w", err)
		}
		return nil
	}

	err = container.Provide(func() string { return alertInvestigation.Name() })
	if err != nil {
		return err
	}

	metrics.Inc(metrics.Alerts, alertInvestigation.Name())

	// clusterID can end up being either be the internal or external ID.
	// We don't really care, as we only use this to initialize the cluster object,
	// which will contain both IDs.
	clusterID, err := pdClient.RetrieveClusterID()
	if err != nil {
		return err
	}

	ocmClient, err := ocm.New()
	if err != nil {
		return fmt.Errorf("could not initialize ocm client: %w", err)
	}

	err = container.Provide(func() ocm.Client { return ocmClient })
	if err != nil {
		return err
	}

	err = container.Provide(func() (*cmv1.Cluster, error) {
		cluster, err := ocmClient.GetClusterInfo(clusterID)
		if err != nil {
			if strings.Contains(err.Error(), "no cluster found") {
				logging.Warnf("No cluster found with ID '%s'. Exiting.", clusterID)
				escalationErr := pdClient.EscalateIncidentWithNote("CAD was unable to find the incident cluster in OCM. An alert for a non-existing cluster is unexpected. Please investigate manually.")
				if escalationErr != nil {
					return nil, fmt.Errorf("failed to escalate 'cluster not found' to PagerDuty: %w", escalationErr)
				}
				// Return a recognizable error after successful escalation.
				return nil, fmt.Errorf("no cluster found with ID '%s'", clusterID)
			}
			return nil, fmt.Errorf("could not retrieve cluster info for %s: %w", clusterID, err)
		}
		return cluster, nil
	})

	var cluster *cmv1.Cluster
	err = container.Invoke(func(c *cmv1.Cluster) {
		cluster = c
	})
	if err != nil {
		// The provider returns a specific error for "no cluster found" after escalating.
		// We can check for this error and exit gracefully.
		if strings.HasPrefix(err.Error(), "no cluster found with ID") {
			return nil
		}
		return err
	}

	// From this point on, we normalize to internal ID, as this ID always exists.
	// For installing clusters, externalID can be empty.
	internalClusterID := cluster.ID()

	// re-initialize logger for the internal-cluster-id context
	logging.RawLogger = logging.InitLogger(logLevelFlag, pipelineNameEnv, internalClusterID)

	requiresInvestigation, err := clusterRequiresInvestigation(cluster, pdClient, ocmClient)
	if err != nil || !requiresInvestigation {
		return err
	}

	err = container.Provide(func() (*hivev1.ClusterDeployment, error) {
		return ocmClient.GetClusterDeployment(internalClusterID)
	})
	if err != nil {
		return err
	}

	customerAwsClient, awsErr := managedcloud.CreateCustomerAWSClient(cluster, ocmClient)
	if awsErr != nil {
		logging.Infof("Could not create AWS client (%s), running CCAM investigation as a fallback.", awsErr)
		// Manually construct resources for the CCAM investigation.
		// Note: This manual construction is an anti-pattern that can be improved in a future refactoring.
		var clusterDeployment *hivev1.ClusterDeployment
		invokeErr := container.Invoke(func(cd *hivev1.ClusterDeployment) {
			clusterDeployment = cd
		})
		if invokeErr != nil {
			return fmt.Errorf("failed to get clusterdeployment for ccam fallback: %w", invokeErr)
		}
		ccamResources := &investigation.Resources{Name: "ccam", Cluster: cluster, ClusterDeployment: clusterDeployment, OcmClient: ocmClient, PdClient: pdClient, AdditionalResources: map[string]interface{}{"error": awsErr}}
		inv := ccam.Investigation{}
		result, err := inv.Run(ccamResources)
		updateMetrics(alertInvestigation.Name(), &result)
		return err
	}

	err = container.Provide(func() aws.Client { return customerAwsClient })
	if err != nil {
		return err
	}

	err = container.Provide(investigation.NewResources)
	if err != nil {
		return err
	}

	logging.Infof("Starting investigation for %s", alertInvestigation.Name())

	var result investigation.InvestigationResult
	err = container.Invoke(func(r *investigation.Resources) error {
		res, err := alertInvestigation.Run(r)
		if err != nil {
			return err
		}
		result = res
		return nil
	})
	updateMetrics(alertInvestigation.Name(), &result)
	if err != nil {
		return err
	}

	return updateIncidentTitle(pdClient)
}

func handleCADFailure(err error, pdClient *pagerduty.SdkClient) {
	logging.Errorf("CAD investigation failed: %v", err)

	notes := "🚨 CAD investigation failed, CAD team has been notified. Please investigate manually. 🚨"

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

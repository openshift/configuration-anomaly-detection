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
	"strconv"
	"strings"

	investigations "github.com/openshift/configuration-anomaly-detection/pkg/investigations"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/ccam"
	investigation "github.com/openshift/configuration-anomaly-detection/pkg/investigations/investigation"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/precheck"
	k8sclient "github.com/openshift/configuration-anomaly-detection/pkg/k8s"
	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
	"github.com/openshift/configuration-anomaly-detection/pkg/managedcloud"
	"github.com/openshift/configuration-anomaly-detection/pkg/metrics"
	"github.com/openshift/configuration-anomaly-detection/pkg/ocm"
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
	// early init of logger for logs before clusterID is known
	logging.RawLogger = logging.InitLogger(logLevelFlag, pipelineNameEnv, "")

	// Load k8s environment variables
	backplaneURL := os.Getenv("BACKPLANE_URL")
	if backplaneURL == "" {
		return fmt.Errorf("missing required environment variable BACKPLANE_URL")
	}

	// Set k8s environment configuration for this session
	k8sclient.SetBackplaneURL(backplaneURL)

	// Load managedcloud environment variables
	backplaneInitialARN := os.Getenv("BACKPLANE_INITIAL_ARN")
	if backplaneInitialARN == "" {
		return fmt.Errorf("missing required environment variable BACKPLANE_INITIAL_ARN")
	}

	backplaneProxy := os.Getenv("BACKPLANE_PROXY")
	awsProxy := os.Getenv("AWS_PROXY")

	// Set managedcloud environment configuration for this session
	managedcloud.SetBackplaneURL(backplaneURL)
	managedcloud.SetBackplaneInitialARN(backplaneInitialARN)
	managedcloud.SetBackplaneProxy(backplaneProxy)
	managedcloud.SetAWSProxy(awsProxy)

	// Load OCM environment variables
	ocmClientID := os.Getenv("CAD_OCM_CLIENT_ID")
	if ocmClientID == "" {
		return fmt.Errorf("missing required environment variable CAD_OCM_CLIENT_ID")
	}

	ocmClientSecret := os.Getenv("CAD_OCM_CLIENT_SECRET")
	if ocmClientSecret == "" {
		return fmt.Errorf("missing required environment variable CAD_OCM_CLIENT_SECRET")
	}

	ocmURL := os.Getenv("CAD_OCM_URL")
	if ocmURL == "" {
		return fmt.Errorf("missing required environment variable CAD_OCM_URL")
	}

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

	metrics.Inc(metrics.Alerts, alertInvestigation.Name())

	// clusterID can end up being either be the internal or external ID.
	// We don't really care, as we only use this to initialize the cluster object,
	// which will contain both IDs.
	clusterID, err := pdClient.RetrieveClusterID()
	if err != nil {
		return err
	}
	ocmClient, err := ocm.New(ocmClientID, ocmClientSecret, ocmURL)
	if err != nil {
		return fmt.Errorf("could not initialize ocm client: %w", err)
	}

	builder, err := investigation.NewResourceBuilder(pdClient, ocmClient, clusterID, alertInvestigation.Name(), logLevelFlag, pipelineNameEnv)
	if err != nil {
		return fmt.Errorf("failed to create resource builder: %w", err)
	}

	defer func() {
		// The builder caches resources, so we can access them here even if a later step failed.
		// We ignore the error here because we just want to get any resources that were created.
		resources, _ := builder.Build()

		// Cleanup k8s client if it exists
		if resources != nil && resources.K8sClient != nil {
			// Failing the k8sclient cleanup call is not critical
			// There is garbage collection for the RBAC within MCC https://issues.redhat.com/browse/OSD-27692
			// We only log the error for now but could add it to the investigation notes or handle differently
			logging.Info("Cleaning kube-api access")
			deferErr := resources.K8sClient.Clean()
			if deferErr != nil {
				logging.Error(deferErr)
			}
		}
		if err != nil {
			handleCADFailure(err, builder, pdClient)
		}
	}()

	precheck := precheck.ClusterStatePrecheck{}
	result, err := precheck.Run(builder)
	if err != nil {
		clusterNotFound := &investigation.ClusterNotFoundError{}
		if errors.As(err, clusterNotFound) {
			logging.Warnf("No cluster found with ID '%s'. Escalating and exiting: %w", clusterID, clusterNotFound)
			return pdClient.EscalateIncidentWithNote("CAD was unable to find the incident cluster in OCM. An alert for a non-existing cluster is unexpected. Please investigate manually.")
		}
		return err
	}
	if result.StopInvestigations != nil {
		logging.Errorf("Stopping investigations due to: %w", result.StopInvestigations)
		return nil
	}

	ccamInvestigation := ccam.CloudCredentialsCheck{}
	result, err = ccamInvestigation.Run(builder)
	if err != nil {
		return err
	}
	updateMetrics(alertInvestigation.Name(), &result)

	logging.Infof("Starting investigation for %s", alertInvestigation.Name())
	result, err = alertInvestigation.Run(builder)
	if err != nil {
		return err
	}
	updateMetrics(alertInvestigation.Name(), &result)
	return updateIncidentTitle(pdClient)
}

func handleCADFailure(err error, rb investigation.ResourceBuilder, pdClient *pagerduty.SdkClient) {
	logging.Errorf("CAD investigation failed: %v", err)
	resources, err := rb.Build()
	if err != nil {
		logging.Errorf("resource builder failed with error: %v", err)
	}

	var docErr *ocm.DocumentationMismatchError
	if errors.As(err, &docErr) {
		escalateDocumentationMismatch(docErr, resources, pdClient)
		return
	}

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

func escalateDocumentationMismatch(docErr *ocm.DocumentationMismatchError, resources *investigation.Resources, pdClient *pagerduty.SdkClient) {
	message := docErr.EscalationMessage()

	if resources != nil && resources.Notes != nil {
		resources.Notes.AppendWarning("%s", message)
		message = resources.Notes.String()
	}

	if pdClient == nil {
		logging.Errorf("Failed to obtain PagerDuty client, unable to escalate documentation mismatch to PagerDuty notes.")
		return
	}

	if err := pdClient.EscalateIncidentWithNote(message); err != nil {
		logging.Errorf("Failed to escalate documentation mismatch notes to PagerDuty: %v", err)
		return
	}

	logging.Info("Escalated documentation mismatch to PagerDuty")
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

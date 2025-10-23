// Package clustermonitoringerrorbudgetburn contains remediation for https://issues.redhat.com/browse/OCPBUGS-33863
package clustermonitoringerrorbudgetburn

import (
	"context"
	"errors"
	"fmt"
	"strings"

	configv1 "github.com/openshift/api/config/v1"
	investigation "github.com/openshift/configuration-anomaly-detection/pkg/investigations/investigation"
	k8sclient "github.com/openshift/configuration-anomaly-detection/pkg/k8s"
	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
	"github.com/openshift/configuration-anomaly-detection/pkg/notewriter"
	"github.com/openshift/configuration-anomaly-detection/pkg/ocm"
	"k8s.io/apimachinery/pkg/fields"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func newUwmConfigMapMisconfiguredSL(docLink string) *ocm.ServiceLog {
	if docLink == "" {
		docLink = ocm.DocumentationLink(ocm.ProductROSA, ocm.DocumentationTopicMonitoringStack)
	}

	return &ocm.ServiceLog{
		Severity:     "Major",
		Summary:      "Action required: review user-workload-monitoring configuration",
		ServiceName:  "SREManualAction",
		Description:  fmt.Sprintf("Your cluster's user workload monitoring is misconfigured: please review the user-workload-monitoring-config ConfigMap in the openshift-user-workload-monitoring namespace. For more information, please refer to the product documentation: %s.", docLink),
		InternalOnly: false,
	}
}

func newUwmAMMisconfiguredSL(docLink string) *ocm.ServiceLog {
	if docLink == "" {
		docLink = ocm.DocumentationLink(ocm.ProductROSA, ocm.DocumentationTopicMonitoringStack)
	}

	return &ocm.ServiceLog{
		Severity:     "Major",
		Summary:      "Action required: review user-workload-monitoring configuration",
		ServiceName:  "SREManualAction",
		Description:  fmt.Sprintf("Your cluster's user workload monitoring is misconfigured: please review the Alert Manager configuration in the opennshift-user-workload-monitoring namespace. For more information, please refer to the product documentation: %s.", docLink),
		InternalOnly: false,
	}
}

func newUwmGenericMisconfiguredSL(docLink string) *ocm.ServiceLog {
	if docLink == "" {
		docLink = ocm.DocumentationLink(ocm.ProductROSA, ocm.DocumentationTopicMonitoringStack)
	}

	return &ocm.ServiceLog{
		Severity:     "Major",
		Summary:      "Action required: review user-workload-monitoring configuration",
		ServiceName:  "SREManualAction",
		Description:  fmt.Sprintf("Your cluster's user workload monitoring is misconfigured: please review the cluster operator status and correct the configuration in the opennshift-user-workload-monitoring namespace. For more information, please refer to the product documentation: %s.", docLink),
		InternalOnly: false,
	}
}

const available = "Available"

type Investigation struct{}

func (c *Investigation) Run(rb investigation.ResourceBuilder) (result investigation.InvestigationResult, err error) {
	r, err := rb.WithK8sClient().Build()
	if err != nil {
		if errors.Is(err, k8sclient.ErrAPIServerUnavailable) {
			return result, r.PdClient.EscalateIncidentWithNote("CAD was unable to access cluster's kube-api. Please investigate manually.")
		}
		if errors.Is(err, k8sclient.ErrCannotAccessInfra) {
			return result, r.PdClient.EscalateIncidentWithNote("CAD is not allowed to access hive, management or service cluster's kube-api. Please investigate manually.")
		}
		return result, err
	}

	// Initialize PagerDuty note writer
	notes := notewriter.New(r.Name, logging.RawLogger)
	defer func() { r.Notes = notes }()

	// List the monitoring cluster operator
	coList := &configv1.ClusterOperatorList{}
	listOptions := &client.ListOptions{FieldSelector: fields.SelectorFromSet(fields.Set{"metadata.name": "monitoring"})}
	err = r.K8sClient.List(context.TODO(), coList, listOptions)
	if err != nil {
		return result, fmt.Errorf("unable to list monitoring clusteroperator: %w", err)
	}

	// Make sure our list output only finds a single cluster operator for `metadata.name = monitoring`
	if len(coList.Items) != 1 {
		return result, fmt.Errorf("found %d clusteroperators, expected 1", len(coList.Items))
	}
	monitoringCo := coList.Items[0]

	product := ocm.GetClusterProduct(r.Cluster)
	monitoringDocLink := ocm.DocumentationLink(product, ocm.DocumentationTopicMonitoringStack)

	// Check if the UWM configmap is invalid
	// If it is, send a service log and silence the alert.
	if isUWMConfigInvalid(&monitoringCo) {
		notes.AppendAutomation("Customer misconfigured the UWM configmap, sending service log and silencing the alert")
		configMapSL := newUwmConfigMapMisconfiguredSL(monitoringDocLink)
		err = r.OcmClient.PostServiceLog(r.Cluster, configMapSL)
		if err != nil {
			return result, fmt.Errorf("failed posting servicelog: %w", err)
		}
		// XXX: No metric before
		result.ServiceLogSent = investigation.InvestigationStep{Performed: true, Labels: nil}

		return result, r.PdClient.SilenceIncidentWithNote(notes.String())
	}

	if isUWMAlertManagerBroken(&monitoringCo) {
		notes.AppendAutomation("Customer misconfigured the UWM (UpdatingUserWorkloadAlertmanager), sending service log and silencing the alert")
		alertManagerSL := newUwmAMMisconfiguredSL(monitoringDocLink)
		err = r.OcmClient.PostServiceLog(r.Cluster, alertManagerSL)
		if err != nil {
			return result, fmt.Errorf("failed posting servicelog: %w", err)
		}
		// XXX: No metric before
		result.ServiceLogSent = investigation.InvestigationStep{Performed: true, Labels: nil}

		return result, r.PdClient.SilenceIncidentWithNote(notes.String())
	}

	if isUWMPrometheusBroken(&monitoringCo) {
		notes.AppendAutomation("Customer misconfigured the UWM (UpdatingUserWorkloadPrometheus), sending service log and silencing the alert")
		genericSL := newUwmGenericMisconfiguredSL(monitoringDocLink)
		err = r.OcmClient.PostServiceLog(r.Cluster, genericSL)
		if err != nil {
			return result, fmt.Errorf("failed posting servicelog: %w", err)
		}
		// XXX: No metric before
		result.ServiceLogSent = investigation.InvestigationStep{Performed: true, Labels: nil}

		return result, r.PdClient.SilenceIncidentWithNote(notes.String())
	}

	// The UWM configmap is valid, an SRE will need to manually investigate this alert.
	// Escalate the alert with our findings.
	notes.AppendSuccess("Monitoring CO not degraded due to UWM misconfiguration")
	return result, r.PdClient.EscalateIncidentWithNote(notes.String())
}

func (c *Investigation) Name() string {
	return "clustermonitoringerrorbudgetburn"
}

func (c *Investigation) Description() string {
	return "Investigate the cluster monitoring error budget burn alert"
}

func (c *Investigation) ShouldInvestigateAlert(alert string) bool {
	return strings.Contains(alert, "ClusterMonitoringErrorBudgetBurnSRE")
}

func (c *Investigation) IsExperimental() bool {
	return false
}

// Check if the `Available` status condition reports a broken UWM config
func isUWMConfigInvalid(monitoringCo *configv1.ClusterOperator) bool {
	symptomStatusString := `the User Workload Configuration from "config.yaml" key in the "openshift-user-workload-monitoring/user-workload-monitoring-config" ConfigMap could not be parsed`

	for _, condition := range monitoringCo.Status.Conditions {
		if condition.Type == available {
			return strings.Contains(condition.Message, symptomStatusString)
		}
	}
	return false
}

func isUWMAlertManagerBroken(monitoringCo *configv1.ClusterOperator) bool {
	symptomStatusString := `UpdatingUserWorkloadAlertmanager: waiting for Alertmanager User Workload object changes failed: waiting for Alertmanager openshift-user-workload-monitoring/user-workload`

	for _, condition := range monitoringCo.Status.Conditions {
		if condition.Type == available {
			return strings.Contains(condition.Message, symptomStatusString)
		}
	}
	return false
}

func isUWMPrometheusBroken(monitoringCo *configv1.ClusterOperator) bool {
	symptomStatusString := `UpdatingUserWorkloadPrometheus: Prometheus "openshift-user-workload-monitoring/user-workload": NoPodReady`

	for _, condition := range monitoringCo.Status.Conditions {
		if condition.Type == available {
			return strings.Contains(condition.Message, symptomStatusString)
		}
	}
	return false
}

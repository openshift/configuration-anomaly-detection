// Package clustermonitoringerrorbudgetburn contains remediation for https://issues.redhat.com/browse/OCPBUGS-33863
package clustermonitoringerrorbudgetburn

import (
	"context"
	"errors"
	"fmt"
	"strings"

	configv1 "github.com/openshift/api/config/v1"
	"github.com/openshift/configuration-anomaly-detection/pkg/executor"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/investigation"
	k8sclient "github.com/openshift/configuration-anomaly-detection/pkg/k8s"
	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
	"github.com/openshift/configuration-anomaly-detection/pkg/notewriter"
	"github.com/openshift/configuration-anomaly-detection/pkg/ocm"
	"github.com/openshift/configuration-anomaly-detection/pkg/types"
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
		k8sErr := &investigation.K8SClientError{}
		if errors.As(err, k8sErr) {
			if errors.Is(k8sErr.Err, k8sclient.ErrAPIServerUnavailable) {
				result.Actions = []types.Action{
					executor.Escalate("CAD was unable to access cluster's kube-api. Please investigate manually."),
				}
				return result, nil
			}
			if errors.Is(k8sErr.Err, k8sclient.ErrCannotAccessInfra) {
				result.Actions = []types.Action{
					executor.Escalate("CAD is not allowed to access hive, management or service cluster's kube-api. Please investigate manually."),
				}
				return result, nil
			}
			return result, err
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

		result.Actions = []types.Action{
			executor.NewServiceLogAction(configMapSL.Severity, configMapSL.Summary).
				WithDescription(configMapSL.Description).
				WithServiceName(configMapSL.ServiceName).
				Build(),
			executor.NoteFrom(notes),
			executor.Silence("Customer misconfigured UWM configmap"),
		}
		return result, nil
	}

	if isUWMAlertManagerBroken(&monitoringCo) {
		notes.AppendAutomation("Customer misconfigured the UWM (UpdatingUserWorkloadAlertmanager), sending service log and silencing the alert")
		alertManagerSL := newUwmAMMisconfiguredSL(monitoringDocLink)

		result.Actions = []types.Action{
			executor.NewServiceLogAction(alertManagerSL.Severity, alertManagerSL.Summary).
				WithDescription(alertManagerSL.Description).
				WithServiceName(alertManagerSL.ServiceName).
				Build(),
			executor.NoteFrom(notes),
			executor.Silence("Customer misconfigured UWM AlertManager"),
		}
		return result, nil
	}

	if isUWMPrometheusBroken(&monitoringCo) {
		notes.AppendAutomation("Customer misconfigured the UWM (UpdatingUserWorkloadPrometheus), sending service log and silencing the alert")
		genericSL := newUwmGenericMisconfiguredSL(monitoringDocLink)

		result.Actions = []types.Action{
			executor.NewServiceLogAction(genericSL.Severity, genericSL.Summary).
				WithDescription(genericSL.Description).
				WithServiceName(genericSL.ServiceName).
				Build(),
			executor.NoteFrom(notes),
			executor.Silence("Customer misconfigured UWM Prometheus"),
		}
		return result, nil
	}

	// The UWM configmap is valid, an SRE will need to manually investigate this alert.
	// Escalate the alert with our findings.
	notes.AppendSuccess("Monitoring CO not degraded due to UWM misconfiguration")
	result.Actions = []types.Action{
		executor.NoteFrom(notes),
		executor.Escalate("Monitoring CO not degraded due to UWM misconfiguration - manual investigation required"),
	}
	return result, nil
}

func (c *Investigation) Name() string {
	return "clustermonitoringerrorbudgetburn"
}

func (c *Investigation) AlertTitle() string {
	return "ClusterMonitoringErrorBudgetBurnSRE"
}

func (c *Investigation) Description() string {
	return "Investigation to analyze a ClusterMonitoringErrorBudgetBurnSRE alert"
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

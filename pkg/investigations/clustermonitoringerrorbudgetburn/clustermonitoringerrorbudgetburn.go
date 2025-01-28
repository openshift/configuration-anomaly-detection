// Package clustermonitoringerrorbudgetburn contains remediation for https://issues.redhat.com/browse/OCPBUGS-33863
package clustermonitoringerrorbudgetburn

import (
	"context"
	"fmt"
	"strings"

	configv1 "github.com/openshift/api/config/v1"
	investigation "github.com/openshift/configuration-anomaly-detection/pkg/investigations"
	k8sclient "github.com/openshift/configuration-anomaly-detection/pkg/k8s"
	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
	"github.com/openshift/configuration-anomaly-detection/pkg/notewriter"
	"github.com/openshift/configuration-anomaly-detection/pkg/ocm"
	"k8s.io/apimachinery/pkg/fields"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var uwmMisconfiguredSL = ocm.ServiceLog{
	Severity:     "Major",
	Summary:      "Action required: review user-workload-monitoring configuration",
	ServiceName:  "SREManualAction",
	Description:  "Your cluster's user workload monitoring is misconfigured: please review the user-workload-monitoring-config ConfigMap in the openshift-user-workload-monitoring namespace. For more information, please refer to the product documentation: https://access.redhat.com/documentation/en-us/red_hat_openshift_service_on_aws/4/html/monitoring/configuring-the-monitoring-stack#.",
	InternalOnly: false,
}

func Investigate(r *investigation.Resources) error {
	// Initialize k8s client
	k8scli, err := k8sclient.New(r.Cluster.ID(), r.OcmClient)
	if err != nil {
		return fmt.Errorf("unable to initialize k8s cli: %w", err)
	}

	// Initialize PagerDuty note writer
	notes := notewriter.New("ClusterMonitoringErrorBudgetBurn", logging.RawLogger)

	// List the monitoring cluster operator
	coList := &configv1.ClusterOperatorList{}
	listOptions := &client.ListOptions{FieldSelector: fields.SelectorFromSet(fields.Set{"metadata.name": "monitoring"})}
	err = k8scli.List(context.TODO(), coList, listOptions)
	if err != nil {
		return fmt.Errorf("unable to list monitoring clusteroperator: %w", err)
	}

	// Make sure our list output only finds a single cluster operator for `metadata.name = monitoring`
	if len(coList.Items) != 1 {
		return fmt.Errorf("found %d clusteroperators, expected 1", len(coList.Items))
	}
	monitoringCo := coList.Items[0]

	// Check if the UWM configmap is invalid
	// If it is, send a service log and silence the alert.
	if isUWMConfigInvalid(&monitoringCo) {
		notes.AppendAutomation("Customer misconfigured the UWM configmap, sending service log and silencing the alert")
		err = r.OcmClient.PostServiceLog(r.Cluster.ID(), &uwmMisconfiguredSL)
		if err != nil {
			return fmt.Errorf("failed posting servicelog: %w", err)
		}

		return r.PdClient.SilenceIncidentWithNote(notes.String())
	}

	// The UWM configmap is valid, an SRE will need to manually investigate this alert.
	// Escalate the alert with our findings.
	notes.AppendSuccess("Monitoring CO not degraded due to a broken UWM configmap")
	return r.PdClient.EscalateIncidentWithNote(notes.String())
}

// Check if the `Available` status condition reports a broken UWM config
func isUWMConfigInvalid(monitoringCo *configv1.ClusterOperator) bool {
	symptomStatusString := `the User Workload Configuration from "config.yaml" key in the "openshift-user-workload-monitoring/user-workload-monitoring-config" ConfigMap could not be parsed`

	for _, condition := range monitoringCo.Status.Conditions {
		if condition.Type == "Available" {
			return strings.Contains(condition.Message, symptomStatusString)
		}
	}
	return false
}

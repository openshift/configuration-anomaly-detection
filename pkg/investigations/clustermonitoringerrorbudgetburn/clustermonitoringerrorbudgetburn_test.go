package clustermonitoringerrorbudgetburn

import (
	"testing"

	configv1 "github.com/openshift/api/config/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var (
	statusConditionAvailable                         = configv1.ClusterOperatorStatusCondition{Type: "Available", Status: "True"}
	statusConditionUpgradeable                       = configv1.ClusterOperatorStatusCondition{Type: "Upgradeable", Status: "True"}
	statusConditionUnavailableConfigMapSymptomsMatch = configv1.ClusterOperatorStatusCondition{Type: "Available", Status: "False", Message: `the User Workload Configuration from "config.yaml" key in the "openshift-user-workload-monitoring/user-workload-monitoring-config" ConfigMap could not be parsed`}
	statusConditionUnavailableAMSymptomsMatch        = configv1.ClusterOperatorStatusCondition{Type: "Available", Status: "False", Message: `UpdatingUserWorkloadAlertmanager: waiting for Alertmanager User Workload object changes failed: waiting for Alertmanager openshift-user-workload-monitoring/user-workload: context deadline exceeded: condition Reconciled: status False: reason ReconciliationFailed: provision alertmanager configuration: failed to initialize from secret: address ${SMTP_HOST:-smtp.gmail.com:587}: too many colons in address`}
	statusConditionUnavailablePMSymptomsMatch        = configv1.ClusterOperatorStatusCondition{Type: "Available", Status: "False", Message: `UpdatingUserWorkloadPrometheus: Prometheus "openshift-user-workload-monitoring/user-workload": NoPodReady: shard 0: pod prometheus-user-workload-0: containers with unready status: [prometheus] shard 0: pod prometheus-user-workload-1: containers with unready status: [prometheus]`}
)

func TestSymptomMatchesConfigMap(t *testing.T) {
	monitoringCo := configv1.ClusterOperator{
		ObjectMeta: v1.ObjectMeta{Name: "monitoring"},
		Status: configv1.ClusterOperatorStatus{
			Conditions: []configv1.ClusterOperatorStatusCondition{statusConditionUnavailableConfigMapSymptomsMatch, statusConditionUpgradeable},
		},
	}
	if !isUWMConfigInvalid(&monitoringCo) {
		t.Fatal("expected symptoms to match")
	}
}

func TestSymptomMatchesAM(t *testing.T) {
	monitoringCo := configv1.ClusterOperator{
		ObjectMeta: v1.ObjectMeta{Name: "monitoring"},
		Status: configv1.ClusterOperatorStatus{
			Conditions: []configv1.ClusterOperatorStatusCondition{statusConditionUnavailableAMSymptomsMatch, statusConditionUpgradeable},
		},
	}
	if !isUWMAlertManagerBroken(&monitoringCo) {
		t.Fatal("expected symptoms to match")
	}
}

func TestSymptomMatchesPrometheus(t *testing.T) {
	monitoringCo := configv1.ClusterOperator{
		ObjectMeta: v1.ObjectMeta{Name: "monitoring"},
		Status: configv1.ClusterOperatorStatus{
			Conditions: []configv1.ClusterOperatorStatusCondition{statusConditionUnavailablePMSymptomsMatch, statusConditionUpgradeable},
		},
	}
	if !isUWMPrometheusBroken(&monitoringCo) {
		t.Fatal("expected symptoms to match")
	}
}

func TestSymptomNoMatch(t *testing.T) {
	monitoringCo := configv1.ClusterOperator{
		ObjectMeta: v1.ObjectMeta{Name: "monitoring"},
		Status: configv1.ClusterOperatorStatus{
			Conditions: []configv1.ClusterOperatorStatusCondition{statusConditionAvailable, statusConditionUpgradeable},
		},
	}
	if isUWMConfigInvalid(&monitoringCo) ||
		isUWMAlertManagerBroken(&monitoringCo) ||
		isUWMPrometheusBroken(&monitoringCo) {
		t.Fatal("expected symptoms to not match")
	}
}

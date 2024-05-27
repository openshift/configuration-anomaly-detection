package clustermonitoringerrorbudgetburn

import (
	"testing"

	configv1 "github.com/openshift/api/config/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var (
	statusConditionAvailable                = configv1.ClusterOperatorStatusCondition{Type: "Available", Status: "True"}
	statusConditionUpgradeable              = configv1.ClusterOperatorStatusCondition{Type: "Upgradeable", Status: "True"}
	statusConditionUnavailableSymptomsMatch = configv1.ClusterOperatorStatusCondition{Type: "Available", Status: "False", Message: `the User Workload Configuration from "config.yaml" key in the "openshift-user-workload-monitoring/user-workload-monitoring-config" ConfigMap could not be parsed`}
)

func TestSymptomMatches(t *testing.T) {
	monitoringCo := configv1.ClusterOperator{
		ObjectMeta: v1.ObjectMeta{Name: "monitoring"},
		Status: configv1.ClusterOperatorStatus{
			Conditions: []configv1.ClusterOperatorStatusCondition{statusConditionUnavailableSymptomsMatch, statusConditionUpgradeable},
		},
	}
	if !isUWMConfigInvalid(&monitoringCo) {
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
	if isUWMConfigInvalid(&monitoringCo) {
		t.Fatal("expected symptoms to not match")
	}
}

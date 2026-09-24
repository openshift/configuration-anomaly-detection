package clustermonitoringerrorbudgetburn

import (
	"strings"
	"testing"

	servicelogsv1 "github.com/openshift-online/ocm-sdk-go/servicelogs/v1"
	configv1 "github.com/openshift/api/config/v1"
	"github.com/openshift/configuration-anomaly-detection/pkg/ocm"
	"gotest.tools/v3/assert"
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

func TestNewUwmServiceLogs(t *testing.T) {
	docLink := "https://docs.example.com"

	tests := []struct {
		name     string
		buildSL  func(string) *ocm.ServiceLog
		wantDesc string
	}{
		{
			name:     "ConfigMap misconfigured",
			buildSL:  newUwmConfigMapMisconfiguredSL,
			wantDesc: "please review the user-workload-monitoring-config ConfigMap",
		},
		{
			name:     "AlertManager misconfigured",
			buildSL:  newUwmAMMisconfiguredSL,
			wantDesc: "please review the Alert Manager configuration",
		},
		{
			name:     "Generic misconfigured",
			buildSL:  newUwmGenericMisconfiguredSL,
			wantDesc: "please review the cluster operator status",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sl := tt.buildSL(docLink)
			assert.Equal(t, servicelogsv1.SeverityImportant, sl.Severity)
			assert.Equal(t, "SREManualAction", sl.ServiceName)
			assert.Equal(t, "Action required: review user-workload-monitoring configuration", sl.Summary)
			assert.Assert(t, !sl.InternalOnly)
			assert.Assert(t, strings.Contains(sl.Description, tt.wantDesc))
			assert.Assert(t, strings.Contains(sl.Description, docLink))
		})
	}
}

func TestNewUwmServiceLogs_DefaultDocLink(t *testing.T) {
	sl := newUwmConfigMapMisconfiguredSL("")
	assert.Assert(t, strings.Contains(sl.Description, "docs."))
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

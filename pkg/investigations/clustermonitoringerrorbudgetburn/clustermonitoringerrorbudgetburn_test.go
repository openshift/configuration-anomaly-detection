package clustermonitoringerrorbudgetburn

import (
	"strings"
	"testing"

	cmv1 "github.com/openshift-online/ocm-sdk-go/clustersmgmt/v1"
	servicelogsv1 "github.com/openshift-online/ocm-sdk-go/servicelogs/v1"
	configv1 "github.com/openshift/api/config/v1"
	"github.com/openshift/configuration-anomaly-detection/pkg/executor"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/investigation"
	"github.com/openshift/configuration-anomaly-detection/pkg/ocm"
	"github.com/openshift/configuration-anomaly-detection/pkg/types"
	"gotest.tools/v3/assert"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
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
			assert.Assert(t, !strings.Contains(sl.Description, "opennshift"))
			if strings.Contains(sl.Description, "namespace") {
				assert.Assert(t, strings.Contains(sl.Description, "openshift-user-workload-monitoring"))
			}
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

func TestRun_UWMMisconfigurationSilences(t *testing.T) {
	cases := []configv1.ClusterOperatorStatusCondition{
		statusConditionUnavailableConfigMapSymptomsMatch,
		statusConditionUnavailableAMSymptomsMatch,
		statusConditionUnavailablePMSymptomsMatch,
	}
	for _, condition := range cases {
		t.Run(condition.Message[:40], func(t *testing.T) {
			result, err := runWithMonitoringOperator(t, condition)
			assert.NilError(t, err)
			assert.Assert(t, hasAction(result.Actions, "service_log"))
			assert.Assert(t, hasAction(result.Actions, "silence_incident"))
			assert.Assert(t, !hasAction(result.Actions, "escalate_incident"))
			for _, action := range result.Actions {
				sl, ok := action.(*executor.ServiceLogAction)
				if !ok || sl.ServiceLog == nil {
					continue
				}
				assert.Assert(t, !strings.Contains(sl.ServiceLog.Description, "opennshift"))
				assert.Assert(t, strings.Contains(sl.ServiceLog.Description, "openshift-user-workload-monitoring"))
			}
		})
	}
}

func TestRun_OtherMonitoringStateEscalates(t *testing.T) {
	result, err := runWithMonitoringOperator(t, statusConditionAvailable)
	assert.NilError(t, err)
	assert.Assert(t, hasAction(result.Actions, "escalate_incident"))
	assert.Assert(t, !hasAction(result.Actions, "silence_incident"))
}

func TestRun_UnexpectedOperatorCountEscalates(t *testing.T) {
	result, err := (&Investigation{}).Run(monitoringBuilder(t))
	assert.NilError(t, err)
	assert.Assert(t, hasAction(result.Actions, "escalate_incident"))
}

func monitoringBuilder(t *testing.T, objects ...client.Object) *investigation.ResourceBuilderMock {
	t.Helper()
	scheme := runtime.NewScheme()
	assert.NilError(t, configv1.AddToScheme(scheme))
	cluster, err := cmv1.NewCluster().ID("cluster-id").Build()
	assert.NilError(t, err)
	return &investigation.ResourceBuilderMock{
		Resources: &investigation.Resources{
			Name:    "clustermonitoringerrorbudgetburn",
			Cluster: cluster,
			K8sClient: fake.NewClientBuilder().WithScheme(scheme).WithIndex(&configv1.ClusterOperator{}, "metadata.name", func(obj client.Object) []string {
				return []string{obj.GetName()}
			}).WithObjects(objects...).Build(),
		},
	}
}

func runWithMonitoringOperator(t *testing.T, available configv1.ClusterOperatorStatusCondition) (investigation.InvestigationResult, error) {
	t.Helper()
	co := &configv1.ClusterOperator{
		ObjectMeta: v1.ObjectMeta{Name: "monitoring"},
		Status:     configv1.ClusterOperatorStatus{Conditions: []configv1.ClusterOperatorStatusCondition{available}},
	}
	return (&Investigation{}).Run(monitoringBuilder(t, co))
}

func hasAction(actions []types.Action, actionType string) bool {
	for _, action := range actions {
		if action.Type() == actionType {
			return true
		}
	}
	return false
}

package insightsoperatordown

import (
	"context"
	"errors"
	"fmt"
	"strings"

	configv1 "github.com/openshift/api/config/v1"
	"github.com/openshift/configuration-anomaly-detection/pkg/executor"
	investigation "github.com/openshift/configuration-anomaly-detection/pkg/investigations/investigation"
	k8sclient "github.com/openshift/configuration-anomaly-detection/pkg/k8s"
	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
	"github.com/openshift/configuration-anomaly-detection/pkg/networkverifier"
	"github.com/openshift/configuration-anomaly-detection/pkg/notewriter"
	"github.com/openshift/configuration-anomaly-detection/pkg/ocm"
	"github.com/openshift/configuration-anomaly-detection/pkg/types"
	"k8s.io/apimachinery/pkg/fields"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type Investigation struct{}

func (c *Investigation) Run(rb investigation.ResourceBuilder) (investigation.InvestigationResult, error) {
	result := investigation.InvestigationResult{}
	r, err := rb.WithAwsClient().Build()
	if err != nil {
		return result, err
	}
	notes := notewriter.New(r.Name, logging.RawLogger)

	user, err := ocm.GetCreatorFromCluster(r.OcmClient.GetConnection(), r.Cluster)
	if err != nil {
		notes.AppendWarning("encountered an issue when checking if the cluster owner is banned: %s", err)
		result.Actions = []types.Action{
			executor.NoteFrom(notes),
			executor.Escalate("Failed to check user ban status - manual investigation required"),
		}
		return result, nil
	}

	if user.Banned() {
		notes.AppendWarning("User is banned: %s\nBan description: %s\nPlease open a proactive case, so that MCS can resolve the ban or organize a ownership transfer.", user.BanCode(), user.BanDescription())
		result.Actions = []types.Action{
			executor.NoteFrom(notes),
			executor.Escalate("User is banned - proactive case required"),
		}
		return result, nil
	} else {
		notes.AppendSuccess("User is not banned.")
	}

	r, err = rb.WithK8sClient().Build()
	if err != nil {
		k8sErr := &investigation.K8SClientError{}
		if errors.As(err, k8sErr) {
			if errors.Is(k8sErr.Err, k8sclient.ErrAPIServerUnavailable) {
				notes.AppendWarning("CAD was unable to access cluster's kube-api. Please investigate manually.")
				result.Actions = []types.Action{
					executor.NoteFrom(notes),
					executor.Escalate("Kube-api unavailable - manual investigation required"),
				}
				return result, nil
			}
			if errors.Is(k8sErr.Err, k8sclient.ErrCannotAccessInfra) {
				notes.AppendWarning("CAD is not allowed to access hive, management or service cluster's kube-api. Please investigate manually.")
				result.Actions = []types.Action{
					executor.NoteFrom(notes),
					executor.Escalate("Cannot access infra cluster - manual investigation required"),
				}
				return result, nil
			}
			return result, err
		}
		return result, err
	}

	coList := &configv1.ClusterOperatorList{}
	listOptions := &client.ListOptions{FieldSelector: fields.SelectorFromSet(fields.Set{"metadata.name": "insights"})}
	err = r.K8sClient.List(context.TODO(), coList, listOptions)
	if err != nil {
		return result, investigation.WrapInfrastructure(
			fmt.Errorf("unable to list insights clusteroperator: %w", err),
			"K8s API failure listing clusteroperators")
	}

	if len(coList.Items) != 1 {
		notes.AppendWarning("Found %d insights clusteroperators, expected 1", len(coList.Items))
		result.Actions = []types.Action{
			executor.NoteFrom(notes),
			executor.Escalate("Unexpected insights clusteroperator count - manual investigation required"),
		}
		return result, nil
	}
	co := coList.Items[0]

	if isOCPBUG22226(&co) {
		notes.AppendWarning("Found symptom of OCPBUGS-22226. Try deleting the insights operator pod to remediate.\n$ oc -n openshift-insights delete pods -l app=insights-operator --wait=false")
		result.Actions = []types.Action{
			executor.NoteFrom(notes),
			executor.Escalate("OCPBUGS-22226 detected - manual remediation required"),
		}
		return result, nil
	} else {
		notes.AppendSuccess("Ruled out OCPBUGS-22226")
	}

	verifierResult, failureReason, err := networkverifier.Run(r.Cluster, r.ClusterDeployment, r.AwsClient)
	if err != nil {
		logging.Error("Network verifier ran into an error: %s", err.Error())
		notes.AppendWarning("NetworkVerifier failed to run:\n\t %s", err.Error())
	}

	switch verifierResult {
	case networkverifier.Failure:
		logging.Infof("Network verifier reported failure: %s", failureReason)
		result.ServiceLogPrepared = investigation.InvestigationStep{Performed: true, Labels: nil}
		notes.AppendWarning("NetworkVerifier found unreachable targets. \n \n Verify and send service log if necessary: \n osdctl servicelog post --cluster-id %s -t https://raw.githubusercontent.com/openshift/managed-notifications/master/osd/required_network_egresses_are_blocked.json -p URLS=%s", r.Cluster.ID(), failureReason)
	case networkverifier.Success:
		notes.AppendSuccess("Network verifier passed")
	}

	result.Actions = []types.Action{
		executor.NoteFrom(notes),
		executor.Escalate("InsightsOperatorDown investigation completed - manual review required"),
	}
	return result, nil
}

func isOCPBUG22226(co *configv1.ClusterOperator) bool {
	symptomStatusString := "Failed to pull SCA certs"

	for _, condition := range co.Status.Conditions {
		if condition.Type == "SCAAvailable" && strings.Contains(condition.Message, symptomStatusString) {
			return true
		}
	}
	return false
}

func (c *Investigation) Name() string {
	return "insightsoperatordown"
}

func (c *Investigation) AlertTitle() string {
	return "InsightsOperatorDown"
}

func (c *Investigation) Description() string {
	return "Investigate insights operator down alert"
}

func (c *Investigation) IsExperimental() bool {
	return false
}

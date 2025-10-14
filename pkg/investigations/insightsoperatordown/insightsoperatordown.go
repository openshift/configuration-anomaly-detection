package insightsoperatordown

import (
	"context"
	"errors"
	"fmt"
	"strings"

	configv1 "github.com/openshift/api/config/v1"
	investigation "github.com/openshift/configuration-anomaly-detection/pkg/investigations/investigation"
	k8sclient "github.com/openshift/configuration-anomaly-detection/pkg/k8s"
	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
	"github.com/openshift/configuration-anomaly-detection/pkg/networkverifier"
	"github.com/openshift/configuration-anomaly-detection/pkg/notewriter"
	"github.com/openshift/configuration-anomaly-detection/pkg/ocm"
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
		return result, r.PdClient.EscalateIncidentWithNote(notes.String())
	}

	if user.Banned() {
		notes.AppendWarning("User is banned: %s\nBan description: %s\nPlease open a proactive case, so that MCS can resolve the ban or organize a ownership transfer.", user.BanCode(), user.BanDescription())
		return result, r.PdClient.EscalateIncidentWithNote(notes.String())
	} else {
		notes.AppendSuccess("User is not banned.")
	}

	r, err = rb.WithK8sClient().Build()
	if err != nil {
		if errors.Is(err, k8sclient.ErrAPIServerUnavailable) {
			return result, r.PdClient.EscalateIncidentWithNote("CAD was unable to access cluster's kube-api. Please investigate manually.")
		}
		if errors.Is(err, k8sclient.ErrCannotAccessInfra) {
			return result, r.PdClient.EscalateIncidentWithNote("CAD is not allowed to access hive, management or service cluster's kube-api. Please investigate manually.")
		}
		return result, err
	}

	coList := &configv1.ClusterOperatorList{}
	listOptions := &client.ListOptions{FieldSelector: fields.SelectorFromSet(fields.Set{"metadata.name": "insights"})}
	err = r.K8sClient.List(context.TODO(), coList, listOptions)
	if err != nil {
		return result, fmt.Errorf("unable to list insights clusteroperator: %w", err)
	}

	if len(coList.Items) != 1 {
		return result, fmt.Errorf("found %d clusteroperators, expected 1", len(coList.Items))
	}
	co := coList.Items[0]

	if isOCPBUG22226(&co) {
		notes.AppendWarning("Found symptom of OCPBUGS-22226. Try deleting the insights operator pod to remediate.\n$ oc -n openshift-insights delete pods -l app=insights-operator --wait=false")
		return result, r.PdClient.EscalateIncidentWithNote(notes.String())
	} else {
		notes.AppendSuccess("Ruled out OCPBUGS-22226")
	}

	verifierResult, failureReason, err := networkverifier.Run(r.Cluster, r.ClusterDeployment, r.AwsClient)
	if err != nil {
		logging.Error("Network verifier ran into an error: %s", err.Error())
		notes.AppendWarning("NetworkVerifier failed to run:\n\t %s", err.Error())

		err = r.PdClient.AddNote(notes.String())
		if err != nil {
			// We do not return as we want the alert to be escalated either no matter what.
			logging.Error("could not add failure reason incident notes")
		}
	}

	switch verifierResult {
	case networkverifier.Failure:
		logging.Infof("Network verifier reported failure: %s", failureReason)
		// XXX: metrics.Inc(metrics.ServicelogPrepared, investigationName)
		result.ServiceLogPrepared = investigation.InvestigationStep{Performed: true, Labels: nil}
		notes.AppendWarning("NetworkVerifier found unreachable targets. \n \n Verify and send service log if necessary: \n osdctl servicelog post --cluster-id %s -t https://raw.githubusercontent.com/openshift/managed-notifications/master/osd/required_network_egresses_are_blocked.json -p URLS=%s", r.Cluster.ID(), failureReason)

		// In the future, we want to send a service log in this case
		err = r.PdClient.AddNote(notes.String())
		if err != nil {
			logging.Error("could not add issues to incident notes")
		}
	case networkverifier.Success:
		notes.AppendSuccess("Network verifier passed")
		err = r.PdClient.AddNote(notes.String())
		if err != nil {
			logging.Error("could not add passed message to incident notes")
		}
	}
	return result, r.PdClient.EscalateIncidentWithNote(notes.String())
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

func (c *Investigation) Description() string {
	return "Investigate insights operator down alert"
}

func (c *Investigation) ShouldInvestigateAlert(alert string) bool {
	return strings.Contains(alert, "InsightsOperatorDown")
}

func (c *Investigation) IsExperimental() bool {
	return false
}

func (c *Investigation) RequiresAwsClient() bool {
	return false
}

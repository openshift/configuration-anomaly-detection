// insightsoperatordown remediates InsightOperatorDownSRE alerts
// SOP https://github.com/openshift/ops-sop/blob/master/v4/troubleshoot/clusteroperators/insights.md

// Step: Check for banned user

// Step: Check for https://issues.redhat.com/browse/OCPBUGS-22226
// Steps to imitate the bug for a cluster:  block console.redhat.com via rule group in aws account
package insightsoperatordown

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

func Investigate(r *investigation.Resources) (investigation.InvestigationResult, error) {
	result := investigation.InvestigationResult{}
	notes := notewriter.New(r.Name, logging.RawLogger)

	user, err := ocm.GetCreatorFromCluster(r.OcmClient.GetConnection(), r.Cluster)
	if err != nil {
		notes.AppendWarning("encountered an issue when checking if the cluster owner is banned. Please investigate.")
		return result, r.PdClient.EscalateIncidentWithNote(notes.String())
	}

	if user.Banned() {
		// Lets make a nice copyable snippet here.
		notes.AppendWarning("User is banned: %s", user.BanCode())
		notes.AppendWarning("Ban description: %s", user.BanDescription())
		notes.AppendWarning("Please open a proactive case, so that MCS can resolve the ban or organize a ownership transfer.")
	} else {
		notes.AppendSuccess("User is not banned.")
	}

	// We continue with the next step OCPBUG22226 even if the user is banned.

	// Initialize k8s client with the investigations name
	k8scli, err := k8sclient.New(r.Cluster.ID(), r.OcmClient, r.Name)
	if err != nil {
		return result, fmt.Errorf("unable to initialize k8s cli: %w", err)
	}

	coList := &configv1.ClusterOperatorList{}
	listOptions := &client.ListOptions{FieldSelector: fields.SelectorFromSet(fields.Set{"metadata.name": "insights"})}
	err = k8scli.List(context.TODO(), coList, listOptions)
	if err != nil {
		return result, fmt.Errorf("unable to list insights clusteroperator: %w", err)
	}

	if len(coList.Items) != 1 {
		return result, fmt.Errorf("found %d clusteroperators, expected 1", len(coList.Items))
	}
	co := coList.Items[0]

	if isOCPBUG22226(&co) {
		notes.AppendWarning("Found symptom of OCPBUG22226. Try deleting the insights operator pod to remediate.")
		notes.AppendWarning("$ oc -n openshift-insights delete pods -l app=insights-operator --wait=false")
		return result, r.PdClient.EscalateIncidentWithNote(notes.String())
	}

	notes.AppendSuccess("User is not banned and its not OCPBUG22226. Please investigate.")
	return result, r.PdClient.EscalateIncidentWithNote(notes.String())
}

func isOCPBUG22226(co *configv1.ClusterOperator) bool {
	symptomStatusString := `Failed to pull SCA certs`

	for _, condition := range co.Status.Conditions {
		if condition.Type == "SCAAvailable" && strings.Contains(condition.Message, symptomStatusString) {
			return true
		}
	}
	return false
}

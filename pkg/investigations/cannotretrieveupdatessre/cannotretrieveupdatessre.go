package cannotretrieveupdatessre

import (
	"context"
	"errors"
	"fmt"
	"strings"

	configv1 "github.com/openshift/api/config/v1"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/investigation"
	k8sclient "github.com/openshift/configuration-anomaly-detection/pkg/k8s"
	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
	"github.com/openshift/configuration-anomaly-detection/pkg/networkverifier"
	"github.com/openshift/configuration-anomaly-detection/pkg/notewriter"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	alertname       = "CannotRetrieveUpdatesSRE"
	remediationName = "CannotRetrieveUpdatesSRE"
)

type Investigation struct{}

// Run executes the investigation for the CannotRetrieveUpdatesSRE alert
func (c *Investigation) Run(r *investigation.Resources) (investigation.InvestigationResult, error) {
	result := investigation.InvestigationResult{}
	notes := notewriter.New("CannotRetrieveUpdatesSRE", logging.RawLogger)
	k8scli, err := k8sclient.New(r.Cluster.ID(), r.OcmClient, remediationName)
	if err != nil {
		return result, fmt.Errorf("unable to initialize k8s cli: %w", err)
	}
	defer func() {
		deferErr := k8scli.Clean()
		if deferErr != nil {
			logging.Error(deferErr)
			err = errors.Join(err, deferErr)
		}
	}()

	// Run network verifier
	verifierResult, failureReason, err := networkverifier.Run(r.Cluster, r.ClusterDeployment, r.AwsClient)
	if err != nil {
		notes.AppendWarning("NetworkVerifier failed to run:\n\t %s", err.Error())
	} else {
		switch verifierResult {
		case networkverifier.Failure:
			result.ServiceLogPrepared = investigation.InvestigationStep{Performed: true, Labels: nil}
			notes.AppendWarning("NetworkVerifier found unreachable targets. \n \n Verify and send service log if necessary: \n osdctl servicelog post %s -t https://raw.githubusercontent.com/openshift/managed-notifications/master/osd/required_network_egresses_are_blocked.json -p URLS=%s", r.Cluster.ID(), failureReason)
		case networkverifier.Success:
			notes.AppendSuccess("Network verifier passed")
		}
	}

	// Check ClusterVersion
	clusterVersion, err := getClusterVersion(k8scli)
	if err != nil {
		notes.AppendWarning("Failed to get ClusterVersion: %s", err.Error())
	} else {
		notes.AppendSuccess("ClusterVersion found: %s", clusterVersion.Status.Desired.Version)

		failureReason := getUpdateRetrievalFailures(clusterVersion)
		if failureReason != "" {
			logging.Warnf("Detected ClusterVersion issue: %s", failureReason)
			notes.AppendWarning("ClusterVersion related issue detected: %s. Current version %s not found in channel %s",
				failureReason, clusterVersion.Status.Desired.Version, clusterVersion.Spec.Channel)
		}
	}
	notes.AppendWarning("Alert escalated to on-call primary for review and please check the ClusterVersion.")
	return result, r.PdClient.EscalateIncidentWithNote(notes.String())
}

func getClusterVersion(k8scli client.Client) (*configv1.ClusterVersion, error) {
	clusterVersion := &configv1.ClusterVersion{}
	err := k8scli.Get(context.TODO(), client.ObjectKey{Name: "version"}, clusterVersion)
	if err != nil {
		return nil, fmt.Errorf("failed to get ClusterVersion: %w", err)
	}
	return clusterVersion, nil
}

// getUpdateRetrievalFailures checks for update retrieval failures in the ClusterVersion
func getUpdateRetrievalFailures(clusterVersion *configv1.ClusterVersion) string {
	for _, condition := range clusterVersion.Status.Conditions {
		msg, found := checkCondition(condition)
		if found {
			return msg
		}
	}
	return ""
}

func checkCondition(condition configv1.ClusterOperatorStatusCondition) (string, bool) {
	if condition.Type != "RetrievedUpdates" {
		return "", false
	}
	if condition.Status == configv1.ConditionFalse {
		return fmt.Sprintf("(Reason: %s). %s", condition.Reason, condition.Message), true
	}
	return "", false
}

func (i *Investigation) Name() string {
	return alertname
}

func (i *Investigation) Description() string {
	return fmt.Sprintf("Investigates '%s' alerts by running network verifier and checking ClusterVersion", alertname)
}

func (i *Investigation) ShouldInvestigateAlert(alert string) bool {
	return strings.Contains(alert, alertname)
}

func (i *Investigation) IsExperimental() bool {
	return true
}

func (i *Investigation) InformingMode() bool {
	return false
}

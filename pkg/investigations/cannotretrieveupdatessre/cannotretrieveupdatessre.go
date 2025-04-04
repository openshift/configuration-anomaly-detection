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
		deferErr := k8sclient.Cleanup(r.Cluster.ID(), r.OcmClient, remediationName)
		if deferErr != nil {
			logging.Error(deferErr)
			err = errors.Join(err, deferErr)
		}
	}()

	defer func(r *investigation.Resources) {
		logging.Infof("Cleaning up investigation resources for cluster %s", r.Cluster.ID())
		if cleanupErr := k8sclient.Cleanup(r.Cluster.ID(), r.OcmClient, remediationName); cleanupErr != nil {
			logging.Errorf("Failed to cleanup Kubernetes client: %v", cleanupErr)
		} else {
			logging.Infof("Cleanup completed successfully for cluster %s", r.Cluster.ID())
		}
	}(r)

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
		notes.AppendWarning("NetworkVerifier found unreachable targets. \n \n Verify and send service log if necessary: \n osdctl servicelog post %s -t https://raw.githubusercontent.com/openshift/managed-notifications/master/osd/required_network_egresses_are_blocked.json -p URLS=%s", r.Cluster.ID(), failureReason)

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

	// Check ClusterVersion
	clusterVersion, note, err := checkClusterVersion(k8scli, r.Cluster.ID())
	if err != nil {
		notes.AppendWarning("Failure checking ClusterVersion: %s", err.Error())
		notes.AppendWarning("Alert escalated to on-call primary for review.")
		logging.Infof("Escalating incident with notes for cluster %s", r.Cluster.ID())
		err = r.PdClient.EscalateIncidentWithNote(notes.String())
		if err != nil {
			logging.Errorf("Failed to escalate incident to PagerDuty: %v", err)
			return result, fmt.Errorf("failed to escalate incident: %w", err)
		}
		return result, err
	}
	if note != "" {
		notes.AppendWarning(note)
		err = r.PdClient.AddNote(notes.String())
		if err != nil {
			logging.Error("could not add notes to the incident")
		}
	}
	if clusterVersion != "" {
		notes.AppendSuccess("ClusterVersion found: %s", clusterVersion)
		err = r.PdClient.AddNote(notes.String())
		if err != nil {
			logging.Error("could not add passed message to incident notes")
		}
	}

	notes.AppendWarning("Alert escalated to on-call primary for review.")
	logging.Infof("Escalating incident with notes for cluster %s", r.Cluster.ID())
	err = r.PdClient.EscalateIncidentWithNote(notes.String())
	if err != nil {
		logging.Errorf("Failed to escalate incident to PagerDuty: %v", err)
		return result, fmt.Errorf("failed to escalate incident: %w", err)
	}
	logging.Infof("Investigation completed and escalated successfully for cluster %s", r.Cluster.ID())

	return result, nil
}

// checkClusterVersion retrieves the cluster version
func checkClusterVersion(k8scli client.Client, clusterID string) (version string, note string, err error) {
	logging.Infof("Checking ClusterVersion for cluster %s", clusterID)
	clusterVersion := &configv1.ClusterVersion{}
	err = k8scli.Get(context.TODO(), client.ObjectKey{Name: "version"}, clusterVersion)
	if err != nil {
		return "", "Failed to get ClusterVersion: cluster access issues detected", fmt.Errorf("failed to get ClusterVersion: %w", err)
	}
	logging.Infof("ClusterVersion channel: %s", clusterVersion.Spec.Channel)
	logging.Infof("ClusterVersion found: %s", clusterVersion.Status.Desired.Version)
	logging.Debugf("ClusterVersion conditions: %+v", clusterVersion.Status.Conditions)

	for _, condition := range clusterVersion.Status.Conditions {
		logging.Debugf("Checking ClusterVersion condition: Type=%s, Status=%s, Reason=%s, Message=%q",
			condition.Type, condition.Status, condition.Reason, condition.Message)
		if condition.Type == "RetrievedUpdates" && condition.Status == "False" {
			if (condition.Reason == "VersionNotFound" || condition.Reason == "RemoteFailed") &&
				strings.Contains(strings.TrimSpace(condition.Message), "Unable to retrieve available updates") {
				logging.Warnf("Detected ClusterVersion error: Reason=%s, Message=%s", condition.Reason, condition.Message)
				return "", fmt.Sprintf("ClusterVersion error detected: %s. Current version %s not found in channel %s",
						condition.Message, clusterVersion.Status.Desired.Version, clusterVersion.Spec.Channel),
					fmt.Errorf("clusterversion validation failed: %s", condition.Reason)
			}
		}
	}
	return clusterVersion.Status.Desired.Version, "", nil
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

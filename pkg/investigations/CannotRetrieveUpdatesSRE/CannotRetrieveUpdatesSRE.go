package CannotRetrieveUpdatesSRE

import (
	"context"
	"fmt"
	"strings"

	configv1 "github.com/openshift/api/config/v1"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/investigation"
	k8sclient "github.com/openshift/configuration-anomaly-detection/pkg/k8s"
	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
	"github.com/openshift/configuration-anomaly-detection/pkg/networkverifier"
	"github.com/openshift/configuration-anomaly-detection/pkg/notewriter"
	"k8s.io/apimachinery/pkg/fields"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	alertname       = "CannotRetrieveUpdatesSRE"
	remediationName = "CannotRetrieveUpdatesSRE"
)

type Investigation struct {
	kclient client.Client
	notes   *notewriter.NoteWriter
}

// setup initializes the investigation resources
func (i *Investigation) setup(r *investigation.Resources) error {
	logging.Infof("Setting up investigation '%s' for cluster %s with remediation name %s",
		i.Name(), r.Cluster.ID(), r.Name)

	k, err := k8sclient.New(r.Cluster.ID(), r.OcmClient, remediationName)
	if err != nil {
		logging.Errorf("Failed to initialize Kubernetes client: %v", err)
		return fmt.Errorf("failed to initialize kubernetes client: %w", err)
	}
	i.kclient = k
	i.notes = notewriter.New(r.Name, logging.RawLogger)

	logging.Infof("Successfully set up Kubernetes client and notewriter for remediation %s", r.Name)
	return nil
}

// cleanup handles resource cleanup after investigation
func (i *Investigation) cleanup(r *investigation.Resources) error {
	logging.Infof("Cleaning up investigation resources for cluster %s", r.Cluster.ID())
	err := k8sclient.Cleanup(r.Cluster.ID(), r.OcmClient, remediationName)
	if err != nil {
		logging.Errorf("Failed to cleanup Kubernetes client: %v", err)
		return fmt.Errorf("failed to cleanup kubernetes client: %w", err)
	}
	logging.Infof("Cleanup completed successfully for cluster %s", r.Cluster.ID())
	return nil
}

// Run executes the investigation for the CannotRetrieveUpdatesSRE alert
func (i *Investigation) Run(r *investigation.Resources) (investigation.InvestigationResult, error) {
	result := investigation.InvestigationResult{}

	// Setup & teardown
	err := i.setup(r)
	if err != nil {
		return result, fmt.Errorf("failed to setup investigation: %w", err)
	}
	defer func(r *investigation.Resources) {
		if err := i.cleanup(r); err != nil {
			logging.Errorf("Failed to cleanup investigation: %v", err)
		}
	}(r)

	if r.Cluster == nil || r.Cluster.ID() == "" {
		errMsg := "Invalid cluster configuration: cluster or cluster ID is missing"
		logging.Errorf(errMsg)
		i.notes.AppendWarning(errMsg)
		return result, r.PdClient.EscalateIncidentWithNote(i.notes.String())
	}

	// Run network verification
	logging.Infof("Running network verification for cluster %s", r.Cluster.ID())
	verifierResult, failureReason, err := networkverifier.Run(r.Cluster, r.ClusterDeployment, r.AwsClient)
	if err != nil {
		logging.Errorf("Network verifier failed: %v", err)
		i.notes.AppendWarning("Network verifier encountered an error: %v", err)
	} else {
		logging.Infof("Network verification completed with result: %v", verifierResult)
		switch verifierResult {
		case networkverifier.Success:
			i.notes.AppendSuccess("Network verifier passed")
		case networkverifier.Failure:
			logging.Infof("Network verifier reported failure: %s", failureReason)
			result.ServiceLogPrepared = investigation.InvestigationStep{Performed: true, Labels: nil}
			i.notes.AppendWarning("NetworkVerifier found unreachable targets. \n \n Verify and send service log if necessary: \n osdctl servicelog post %s -t https://raw.githubusercontent.com/openshift/managed-notifications/master/osd/required_network_egresses_are_blocked.json -p URLS=%s",
				r.Cluster.ID(), failureReason)
		}
	}

	// Check ClusterVersion
	logging.Infof("Checking ClusterVersion for cluster %s", r.Cluster.ID())
	cvList := &configv1.ClusterVersionList{}
	listOptions := &client.ListOptions{FieldSelector: fields.SelectorFromSet(fields.Set{"metadata.name": "version"})}
	err = i.kclient.List(context.TODO(), cvList, listOptions)
	if err != nil {
		logging.Errorf("Failed to list ClusterVersion: %v", err)
		i.notes.AppendWarning("Failed to list ClusterVersion: %v\nThis may indicate cluster access issues", err)
	} else if len(cvList.Items) != 1 {
		logging.Warnf("Found %d ClusterVersions, expected 1", len(cvList.Items))
		i.notes.AppendWarning("Found %d ClusterVersions, expected 1", len(cvList.Items))
	} else {
		versionCv := cvList.Items[0]
		logging.Infof("ClusterVersion found: %s", versionCv.Status.Desired.Version)
		for _, condition := range versionCv.Status.Conditions {
			logging.Debugf("Checking ClusterVersion condition: Type=%s, Status=%s, Reason=%s, Message=%s",
				condition.Type, condition.Status, condition.Reason, condition.Message)
			if condition.Type == "RetrievedUpdates" &&
				condition.Status == "False" &&
				condition.Reason == "VersionNotFound" &&
				strings.Contains(condition.Message, "Unable to retrieve available updates") {
				i.notes.AppendWarning("ClusterVersion error detected: %s\nThis indicates the current version %s is not found in the specified channel %s",
					condition.Message, versionCv.Status.Desired.Version, versionCv.Spec.Channel)
			}
		}
		fmt.Printf("Cluster version: %s\n", versionCv.Status.Desired.Version)
	}

	i.notes.AppendWarning("Alert escalated to on-call primary for review.")
	logging.Infof("Escalating incident with notes for cluster %s", r.Cluster.ID())
	err = r.PdClient.EscalateIncidentWithNote(i.notes.String())
	if err != nil {
		logging.Errorf("Failed to escalate incident to PagerDuty: %v", err)
		return result, fmt.Errorf("failed to escalate incident: %w", err)
	}
	logging.Infof("Investigation completed and escalated successfully for cluster %s", r.Cluster.ID())

	return result, nil
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

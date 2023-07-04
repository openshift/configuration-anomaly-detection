// Package cpd contains functionality for the ClusterProvisioningDelay investigation
package cpd

import (
	"errors"
	"fmt"
	"regexp"

	"github.com/openshift/configuration-anomaly-detection/pkg/investigation"
	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
	"github.com/openshift/configuration-anomaly-detection/pkg/services/networkverifier"
)

// GetCPDAlertInternalID gets the internal ID from a CPD pagerduty alert's title
// We need this function as CPD's alert formatting is an edge case to our other alerts.
func GetCPDAlertInternalID(alertTitle string) (string, error) {
	re := regexp.MustCompile(`uhc-[^\s-]+-([^\s-]+)`)
	fmt.Println(alertTitle)
	match := re.FindStringSubmatch(alertTitle)

	// It should have one match and one capturing group:
	// [uhc-production-1234k6tnqp7306a6sefn4m41sdp7qsh6 1234k6tnqp7306a6sefn4m41sdp7qsh6]
	if len(match) != 2 {
		return "", errors.New("getCPDAlertInternalID wasn't able to find the internal ID in the alert title")
	}

	return match[1], nil // [1] is the capture group.
}

// InvestigateTriggered runs the investigation for a triggered CPD pagerduty event
// Currently what this investigation does is:
// - run network verifier and add the output as pagerduty note
// - always escalate the alert to primary
// The reasoning for this is that we don't fully trust network verifier yet.
// In the future, we want to automate service logs based on the network verifier output.
func InvestigateTriggered(r *investigation.Resources) error {
	verifierResult, failureReason, err := networkverifier.Run(r.Cluster, r.ClusterDeployment, r.AwsClient)
	if err != nil {
		logging.Error("Network verifier ran into an error: %s", err.Error())
		err = r.PdClient.AddNote(fmt.Sprintf("NetworkVerifier failed to run:\n\t %s", err))
		if err != nil {
			// We do not return as we want the alert to be escalated either no matter what.
			logging.Error("could not add failure reason incident notes")
		}
	}

	switch verifierResult {
	case networkverifier.Failure:
		logging.Info("Network verifier reported failure: %s", failureReason)
		// In the future, we want to send a service log in this case
		err = r.PdClient.AddNote(fmt.Sprintf("Network verifier found issues:\n %s \n\n Verify and send service log if necessary: \n osdctl servicelog post %s -t https://raw.githubusercontent.com/openshift/managed-notifications/master/osd/required_network_egresses_are_blocked.json -p URLS=%s", failureReason, r.Cluster.ID(), failureReason))
		if err != nil {
			logging.Error("could not add issues to incident notes")
		}
	case networkverifier.Success:
		logging.Info("Network verifier passed.")
		err = r.PdClient.AddNote("Network verifier passed.")
		if err != nil {
			logging.Error("could not add passed message to incident notes")
		}
	}

	// We currently always escalate, in the future, when network verifier is reliable,
	// we would silence the alert when we had a service log in the case of network verifier detecting failures.
	return r.PdClient.EscalateAlert()
}

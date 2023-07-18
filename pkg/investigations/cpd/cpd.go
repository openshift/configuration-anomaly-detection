// Package cpd contains functionality for the ClusterProvisioningDelay investigation
package cpd

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/openshift/configuration-anomaly-detection/pkg/aws"
	investigation "github.com/openshift/configuration-anomaly-detection/pkg/investigations"
	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
	"github.com/openshift/configuration-anomaly-detection/pkg/networkverifier"
)

const unknownProvisionCode = "OCM3999"

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
// - check cluster state
// - check DNS
// - check OcmErrorCode
// - check subnet routes
// - run network verifier and add the output as pagerduty note
// - always escalate the alert to primary
// The reasoning for this is that we don't fully trust network verifier yet.
// In the future, we want to automate service logs based on the network verifier output.
func InvestigateTriggered(r *investigation.Resources) error {
	var notesSb strings.Builder

	notesSb.WriteString("🤖 Automated CPD pre-investigation 🤖\n")
	notesSb.WriteString("===========================\n")

	if r.Cluster.Status().State() == "ready" {
		notesSb.WriteString("⚠️ This cluster is in a ready state, thus provisioning succeeded\n.")
		err := r.PdClient.AddNote(notesSb.String())
		if err != nil {
			logging.Error("could not add clusters ready state to incident notes")
		}
	}
	notesSb.WriteString("✅ Cluster installation did not yet finish\n")

	// Check if DNS is ready, exit out if not
	if !r.Cluster.Status().DNSReady() {
		notesSb.WriteString(fmt.Sprintf("⚠️ DNS not ready.\nInvestigate reasons using the dnszones CR in the cluster namespace:\noc get dnszones -n uhc-production-%s -o yaml --as backplane-cluster-admin\n", r.Cluster.ID()))
		return r.PdClient.EscalateAlertWithNote(notesSb.String())
	}
	notesSb.WriteString("✅ Cluster DNS is ready\n")

	// Check if the OCM Error code is a known error
	if len(r.Cluster.Status().ProvisionErrorCode()) > 0 && r.Cluster.Status().ProvisionErrorCode() != unknownProvisionCode {
		notesSb.WriteString(fmt.Sprintf("⚠️ Error code '%s' is known, customer already received Service Log\n", r.Cluster.Status().ProvisionErrorCode()))
		return r.PdClient.EscalateAlertWithNote(notesSb.String())
	}
	notesSb.WriteString("✅ OCM Error code is unknown, customer did not receive automated SL from OCM yet.\n")

	if r.Cluster.AWS().SubnetIDs() != nil && len(r.Cluster.AWS().SubnetIDs()) > 0 {
		logging.Info("Checking BYOVPC to ensure subnets have valid routing...")
		for _, subnet := range r.Cluster.AWS().SubnetIDs() {
			isValid, err := isSubnetRouteValid(r.AwsClient, subnet)
			if err != nil {
				logging.Error(err)
			}
			if !isValid {
				notesSb.WriteString(fmt.Sprintf("⚠️ subnet %s does not have a default route to 0.0.0.0/0\nRun the following to send the according ServiceLog:\nosdctl servicelog post %s -t https://raw.githubusercontent.com/openshift/managed-notifications/master/osd/aws/InstallFailed_NoRouteToInternet.json\n", subnet, r.Cluster.ID()))
				err = r.PdClient.AddNote(notesSb.String())
				if err != nil {
					logging.Error(err)
				}
				return r.PdClient.EscalateAlert()
			}
		}
	}
	notesSb.WriteString("✅ BYOVPC has valid routing\n")

	verifierResult, failureReason, err := networkverifier.Run(r.Cluster, r.ClusterDeployment, r.AwsClient)
	if err != nil {
		logging.Error("Network verifier ran into an error: %s", err.Error())
		notesSb.WriteString(fmt.Sprintf("⚠️ NetworkVerifier failed to run:\n\t %s", err))

		err = r.PdClient.AddNote(notesSb.String())
		if err != nil {
			// We do not return as we want the alert to be escalated either no matter what.
			logging.Error("could not add failure reason incident notes")
		}
	}

	switch verifierResult {
	case networkverifier.Failure:
		logging.Infof("Network verifier reported failure: %s", failureReason)
		notesSb.WriteString(fmt.Sprintf("⚠️ Network verifier found issues:\n %s \n\n Verify and send service log if necessary: \n osdctl servicelog post %s -t https://raw.githubusercontent.com/openshift/managed-notifications/master/osd/required_network_egresses_are_blocked.json -p URLS=%s\n", failureReason, r.Cluster.ID(), failureReason))

		// In the future, we want to send a service log in this case
		err = r.PdClient.AddNote(notesSb.String())
		if err != nil {
			logging.Error("could not add issues to incident notes")
		}
	case networkverifier.Success:
		notesSb.WriteString("✅ Network verifier passed\n")
		err = r.PdClient.AddNote(notesSb.String())
		if err != nil {
			logging.Error("could not add passed message to incident notes")
		}
	}

	// We currently always escalate, in the future, when network verifier is reliable,
	// we would silence the alert when we had a service log in the case of network verifier detecting failures.
	return r.PdClient.EscalateAlert()
}

func isSubnetRouteValid(awsClient aws.Client, subnetID string) (bool, error) {
	routeTable, err := awsClient.GetRouteTableForSubnet(subnetID)
	if err != nil {
		return false, err
	}

	for _, route := range routeTable.Routes {
		// Some routes don't use CIDR blocks as targets, so this needs to be checked
		if route.DestinationCidrBlock != nil && *route.DestinationCidrBlock == "0.0.0.0/0" {
			return true, nil
		}
	}

	// We haven't found a default route to the internet, so this subnet has an invalid route table
	return false, nil
}

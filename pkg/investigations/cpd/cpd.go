// Package cpd contains functionality for the ClusterProvisioningDelay investigation
package cpd

import (
	"github.com/openshift/configuration-anomaly-detection/pkg/aws"
	investigation "github.com/openshift/configuration-anomaly-detection/pkg/investigations"
	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
	"github.com/openshift/configuration-anomaly-detection/pkg/metrics"
	"github.com/openshift/configuration-anomaly-detection/pkg/networkverifier"
	"github.com/openshift/configuration-anomaly-detection/pkg/notewriter"
	"github.com/openshift/configuration-anomaly-detection/pkg/ocm"
)

var (
	investigationName = "ClusterProvisioningDelay"
	// https://raw.githubusercontent.com/openshift/managed-notifications/master/osd/aws/InstallFailed_NoRouteToInternet.json
	byovpcRoutingSL = &ocm.ServiceLog{Severity: "Major", Summary: "Installation blocked: Missing route to internet", Description: "Your cluster's installation is blocked because of the missing route to internet in the route table(s) associated with the supplied subnet(s) for cluster installation. Please review and validate the routes by following documentation and re-install the cluster: https://docs.openshift.com/container-platform/latest/installing/installing_aws/installing-aws-vpc.html#installation-custom-aws-vpc-requirements_installing-aws-vpc.", InternalOnly: false, ServiceName: "SREManualAction"}
)

// Investigate runs the investigation for a triggered CPD pagerduty event
// Currently what this investigation does is:
// - check cluster state
// - check clusterDeployment state
// - check DNS
// - check subnet routes
// - run network verifier and add the output as pagerduty note
// - always escalate the alert to primary
// The reasoning for this is that we don't fully trust network verifier yet.
// In the future, we want to automate service logs based on the network verifier output.
func Investigate(r *investigation.Resources) error {
	notes := notewriter.New("CPD", logging.RawLogger)

	if r.Cluster.Status().State() == "ready" {
		// We are unsure when this happens, in theory, if the cluster is ready, the alert shouldn't fire or should autoresolve.
		// We currently believe this never happens, but want to be made aware if it does.
		notes.AppendWarning("This cluster is in a ready state, thus provisioning succeeded. Please contact CAD team to investigate if we can just silence this case in the future")

		return r.PdClient.EscalateIncidentWithNote(notes.String())
	}
	notes.AppendSuccess("Cluster installation did not yet finish")

	if r.ClusterDeployment.Spec.ClusterMetadata == nil {
		// This sometimes happens on staging when QE tests new unstable versions
		// In case this happens on production, we want to raise this to OCM/CS.
		notes.AppendWarning("This cluster has an empty ClusterDeployment.Spec.ClusterMetadata, meaning that the provisioning failed before the installation started. This is usually the case when the install configuration is faulty. Please investigate manually.")

		return r.PdClient.EscalateIncidentWithNote(notes.String())
	}
	notes.AppendSuccess("Installation hive job started")

	// Check if DNS is ready, exit out if not
	if !r.Cluster.Status().DNSReady() {
		notes.AppendWarning("DNS not ready.\nInvestigate reasons using the dnszones CR in the cluster namespace:\noc get dnszones -n uhc-production-%s -o yaml --as backplane-cluster-admin", r.Cluster.ID())
		return r.PdClient.EscalateIncidentWithNote(notes.String())
	}
	notes.AppendSuccess("Cluster DNS is ready")

	if r.Cluster.AWS().SubnetIDs() != nil && len(r.Cluster.AWS().SubnetIDs()) > 0 {
		logging.Info("Checking BYOVPC to ensure subnets have valid routing...")
		for _, subnet := range r.Cluster.AWS().SubnetIDs() {
			isValid, err := isSubnetRouteValid(r.AwsClient, subnet)
			if err != nil {
				logging.Error(err)
			}
			if !isValid {
				if err := r.OcmClient.PostServiceLog(r.Cluster.ID(), byovpcRoutingSL); err != nil {
					return err
				}
				metrics.Inc(metrics.ServicelogSent, investigationName)

				notes.AppendWarning("subnet %s does not have a default route to 0.0.0.0/0", subnet)
				notes.AppendAutomation("Sent SL: '%s'", byovpcRoutingSL.Summary)
				if err := r.PdClient.AddNote(notes.String()); err != nil {
					logging.Error(err)
				}

				return r.PdClient.SilenceIncident()
			}
		}
	}
	notes.AppendSuccess("BYOVPC has valid routing")

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
		metrics.Inc(metrics.ServicelogPrepared, investigationName)
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

	// We currently always escalate, in the future, when network verifier is reliable,
	// we would silence the alert when we had a service log in the case of network verifier detecting failures.
	return r.PdClient.EscalateIncident()
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

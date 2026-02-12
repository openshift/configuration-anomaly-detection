// Package cpd contains functionality for the ClusterProvisioningDelay investigation package cpd
package cpd

import (
	"fmt"

	"github.com/openshift/configuration-anomaly-detection/pkg/aws"
	"github.com/openshift/configuration-anomaly-detection/pkg/executor"
	investigation "github.com/openshift/configuration-anomaly-detection/pkg/investigations/investigation"
	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
	"github.com/openshift/configuration-anomaly-detection/pkg/networkverifier"
	"github.com/openshift/configuration-anomaly-detection/pkg/notewriter"
	"github.com/openshift/configuration-anomaly-detection/pkg/ocm"
)

type Investigation struct{}

// https://raw.githubusercontent.com/openshift/managed-notifications/master/osd/aws/InstallFailed_NoRouteToInternet.json
func newBYOVPCRoutingSL(docLink string) *ocm.ServiceLog {
	if docLink == "" {
		docLink = ocm.DocumentationLink(ocm.ProductROSA, ocm.DocumentationTopicAwsCustomVPC)
	}

	return &ocm.ServiceLog{
		Severity:     "Major",
		Summary:      "Installation blocked: Missing route to internet",
		Description:  fmt.Sprintf("Your cluster's installation is blocked because of the missing route to internet in the route table(s) associated with the supplied subnet(s) for cluster installation. Please review and validate the routes by following documentation and re-install the cluster: %s.", docLink),
		InternalOnly: false,
		ServiceName:  "SREManualAction",
	}
}

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
func (c *Investigation) Run(rb investigation.ResourceBuilder) (investigation.InvestigationResult, error) {
	result := investigation.InvestigationResult{}
	r, err := rb.WithClusterDeployment().WithAwsClient().Build()
	if err != nil {
		return result, err
	}
	notes := notewriter.New("CPD", logging.RawLogger)
	defer func() { r.Notes = notes }()

	if r.Cluster.Status().State() == "ready" {
		// We are unsure when this happens, in theory, if the cluster is ready, the alert shouldn't fire or should autoresolve.
		// We currently believe this never happens, but want to be made aware if it does.
		notes.AppendWarning("This cluster is in a ready state, thus provisioning succeeded. Please contact CAD team to investigate if we can just silence this case in the future")

		result.Actions = append(
			executor.NoteAndReportFrom(notes, r.Cluster.ID(), c.Name()),
			executor.Escalate("Cluster ready but alert fired - CAD team investigation required"),
		)
		return result, nil
	}
	notes.AppendSuccess("Cluster installation did not yet finish")

	if r.ClusterDeployment.Spec.ClusterMetadata == nil {
		// This sometimes happens on staging when QE tests new unstable versions
		// In case this happens on production, we want to raise this to OCM/CS.
		notes.AppendWarning("This cluster has an empty ClusterDeployment.Spec.ClusterMetadata, meaning that the provisioning failed before the installation started. This is usually the case when the install configuration is faulty. Please investigate manually.")

		result.Actions = append(
			executor.NoteAndReportFrom(notes, r.Cluster.ID(), c.Name()),
			executor.Escalate("ClusterDeployment.Spec.ClusterMetadata empty - faulty install configuration"),
		)
		return result, nil
	}
	notes.AppendSuccess("Installation hive job started")

	// Check if DNS is ready, exit out if not
	if !r.Cluster.Status().DNSReady() {
		notes.AppendWarning("DNS not ready.\nInvestigate reasons using the dnszones CR in the cluster namespace:\noc get dnszones -n uhc-production-%s -o yaml --as backplane-cluster-admin", r.Cluster.ID())
		result.Actions = append(
			executor.NoteAndReportFrom(notes, r.Cluster.ID(), c.Name()),
			executor.Escalate("Cluster DNS not ready"),
		)
		return result, nil
	}
	notes.AppendSuccess("Cluster DNS is ready")

	product := ocm.GetClusterProduct(r.Cluster)
	docLink := ocm.DocumentationLink(product, ocm.DocumentationTopicAwsCustomVPC)

	if r.Cluster.AWS().SubnetIDs() != nil && len(r.Cluster.AWS().SubnetIDs()) > 0 {
		logging.Info("Checking BYOVPC to ensure subnets have valid routing...")
		for _, subnet := range r.Cluster.AWS().SubnetIDs() {
			isValid, err := isSubnetRouteValid(r.AwsClient, subnet)
			if err != nil {
				return result, investigation.WrapInfrastructure(err, "AWS API failure checking subnet route tables")
			}
			if !isValid {
				notes.AppendWarning("subnet %s does not have a default route to 0.0.0.0/0", subnet)
				byovpcRoutingSL := newBYOVPCRoutingSL(docLink)

				// XXX: metrics.Inc(metrics.ServicelogSent, investigationName)
				result.ServiceLogSent = investigation.InvestigationStep{Performed: true, Labels: nil}

				notes.AppendAutomation("Sent SL: '%s'", byovpcRoutingSL.Summary)

				result.Actions = append(
					executor.NoteAndReportFrom(notes, r.Cluster.ID(), c.Name()),
					executor.NewServiceLogAction(byovpcRoutingSL.Severity, byovpcRoutingSL.Summary).
						WithDescription(byovpcRoutingSL.Description).
						WithServiceName(byovpcRoutingSL.ServiceName).
						Build(),
					executor.Silence("Missing route to internet in subnet route table"),
				)
				return result, nil
			}
		}
	}
	notes.AppendSuccess("BYOVPC has valid routing")

	verifierResult, failureReason, err := networkverifier.Run(r.Cluster, r.ClusterDeployment, r.AwsClient)
	if err != nil {
		logging.Error("Network verifier ran into an error: %s", err.Error())
		notes.AppendWarning("NetworkVerifier failed to run:\n\t %s", err.Error())
		// We do not return as we want the alert to be escalated either no matter what.
	}

	switch verifierResult {
	case networkverifier.Failure:
		logging.Infof("Network verifier reported failure: %s", failureReason)
		// XXX: metrics.Inc(metrics.ServicelogPrepared, investigationName)
		result.ServiceLogPrepared = investigation.InvestigationStep{Performed: true, Labels: nil}
		notes.AppendWarning("NetworkVerifier found unreachable targets. \n \n Verify and send service log if necessary: \n osdctl servicelog post --cluster-id %s -t https://raw.githubusercontent.com/openshift/managed-notifications/master/osd/required_network_egresses_are_blocked.json -p URLS=\"%s\"", r.Cluster.ID(), failureReason)
	case networkverifier.Success:
		notes.AppendSuccess("Network verifier passed")
	}

	// We currently always escalate, in the future, when network verifier is reliable,
	// we would silence the alert when we had a service log in the case of network verifier detecting failures.
	result.Actions = append(
		executor.NoteAndReportFrom(notes, r.Cluster.ID(), c.Name()),
		executor.Escalate("ClusterProvisioningDelay - manual investigation required"),
	)
	return result, nil
}

func (c *Investigation) Name() string {
	return "ClusterProvisioningDelay"
}

func (c *Investigation) AlertTitle() string {
	return "ClusterProvisioningDelay -"
}

func (c *Investigation) Description() string {
	return "Investigates the ClusterProvisioningDelay alert"
}

func (c *Investigation) IsExperimental() bool {
	return false
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

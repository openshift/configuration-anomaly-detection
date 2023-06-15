// Package ccam Cluster Credentials Are Missing (CCAM) provides a service for detecting missing cluster credentials
package ccam

import (
	"fmt"
	"regexp"

	v1 "github.com/openshift-online/ocm-sdk-go/clustersmgmt/v1"
	"github.com/openshift/configuration-anomaly-detection/pkg/ocm"
	"github.com/openshift/configuration-anomaly-detection/pkg/pagerduty"
	"github.com/openshift/configuration-anomaly-detection/pkg/utils"
)

// NOTE: USE CAUTION WHEN CHANGING THESE TEMPLATES!!
// Changing the templates' summaries will likely prevent CAD from removing clusters with these Limited Support reasons in the future, since it identifies which reasons to delete via their summaries.
// If the summaries *must* be modified, it's imperative that existing clusters w/ these LS reasons have the new summary applied to them (currently, the only way to do this is to delete the current
// reason & apply the new one). Failure to do so will result in orphan clusters that are not managed by CAD.

var ccamLimitedSupport = ocm.LimitedSupportReason{
	Summary: "Restore missing cloud credentials",
	Details: "Your cluster requires you to take action because Red Hat is not able to access the infrastructure with the provided credentials. Please restore the credentials and permissions provided during install",
}

// CAUTION!!

var accessDeniedRegex = regexp.MustCompile(`failed to assume into support-role: AccessDenied`)

// OcmClient is a wrapper around the ocm client, and is used to import the received functions into the Provider
type OcmClient = ocm.Client

// PdClient is a wrapper around the pagerduty client, and is used to import the received functions into the Provider
type PdClient = pagerduty.Client

// Provider should have all the functions that ChgmService is implementing
type Provider struct {
	// having awsClient and ocmClient this way
	// allows for all the method receivers defined on them to be passed into the parent struct,
	// thus making it more composable than just having each func redefined here
	//
	// a different solution is to have the structs have unique names to begin with, which makes the code
	// aws.AwsClient feel a bit redundant
	*OcmClient
	*PdClient
}

// Service will wrap all the required commands the client needs to run its operations
type Service interface {
	// OCM
	GetClusterInfo(identifier string) (*v1.Cluster, error)
	LimitedSupportExists(limitedSupportReason ocm.LimitedSupportReason, clusterID string) (bool, error)
	PostLimitedSupportReason(limitedSupportReason ocm.LimitedSupportReason, clusterID string) error
	DeleteLimitedSupportReasons(ls ocm.LimitedSupportReason, clusterID string) error
	// PD
	AddNote(noteContent string) error
	CreateNewAlert(newAlert pagerduty.NewAlert, serviceID string) error
	SilenceAlertWithNote(notes string) error
	MoveToEscalationPolicy(escalationPolicyID string) error
	GetOnCallEscalationPolicy() string
	GetServiceID() string
}

// Client refers to the CCAM client
type Client struct {
	Service
	Cluster *v1.Cluster
}

// New creates a new CCAM client and gets the cluster object from ocm for the internal id
func New(ocmClient *OcmClient, pdClient *PdClient, cluster *v1.Cluster) (Client, error) {
	client := Client{
		Service: Provider{
			OcmClient: ocmClient,
			PdClient:  pdClient,
		},
		Cluster: cluster,
	}
	return client, nil
}

// checkMissing checks for missing credentials that are required for assuming
// into the support-role. If these credentials are missing we can silence the
// alert and post limited support reason.
func (c Client) checkMissing(err error) bool {
	return accessDeniedRegex.MatchString(err.Error())
}

// Evaluate estimates if the awsError is a cluster credentials are missing error. If it determines that it is,
// the cluster is placed into limited support, otherwise an error is returned. If the cluster already has a CCAM
// LS reason, no additional reasons are added and incident is sent to SilentTest.
func (c Client) Evaluate(awsError error, _ string) error {
	if !c.checkMissing(awsError) {
		return fmt.Errorf("credentials are there, error is different: %w", awsError)
	}

	lsExists, err := c.LimitedSupportExists(ccamLimitedSupport, c.Cluster.ID())
	if err != nil {
		return fmt.Errorf("couldn't determine if limited support reason already exists: %w", err)
	}

	note := fmt.Sprintf("Cluster already has limited support for '%s'. Silencing alert.\n", ccamLimitedSupport.Summary)

	if !lsExists {
		err = c.PostLimitedSupportReason(ccamLimitedSupport, c.Cluster.ID())
		if err != nil {
			return fmt.Errorf("could not post limited support reason for %s: %w", c.Cluster.Name(), err)
		}
		note = fmt.Sprintf("Added the following Limited Support reason to cluster: %#v. Silencing alert.\n", ccamLimitedSupport)
	}
	return c.SilenceAlertWithNote(note)
}

// RemoveLimitedSupport will remove any CCAM limited support reason from the cluster,
// if it fails to do so, it will try to alert primary
// Run this after cloud credentials are confirmed
func (c Client) RemoveLimitedSupport() error {
	err := utils.WithRetries(func() error {
		return c.DeleteLimitedSupportReasons(ccamLimitedSupport, c.Cluster.ID())
	})
	if err != nil {
		fmt.Println("Failed to remove CCAM Limited support reason from cluster. Attempting to alert Primary.")
		originalErr := err
		err := utils.WithRetries(func() error {
			return c.CreateNewAlert(c.buildAlertForCCAM(originalErr), c.GetServiceID())
		})
		if err != nil {
			fmt.Println("Failed to alert Primary")
			return err
		}
		fmt.Println("Primary has been alerted")
		return nil
	}
	return nil
}

// buildAlertForCCAM will return a NewAlert populated with cluster id and the specific error
func (c Client) buildAlertForCCAM(lsError error) pagerduty.NewAlert {
	return pagerduty.NewAlert{
		Description: fmt.Sprintf("CAD is unable to remove a Limited Support reason from cluster %s", c.Cluster.ID()),
		Details: pagerduty.NewAlertDetails{
			ClusterID:  c.Cluster.ID(),
			Error:      lsError.Error(),
			Resolution: "CAD has been unable to remove a Limited Support reason from this cluster. The cluster needs to be manually reviewed and have any appropriate Limited Support reasons removed. After corrective actions have been taken, this alert must be manually resolved.",
			SOP:        "https://github.com/openshift/ops-sop/blob/master/v4/alerts/CAD_ErrorRemovingLSReason.md",
		},
	}
}

// Package ccam Cluster Credentials Are Missing (CCAM) provides a service for detecting missing cluster credentials
package ccam

import (
	"fmt"
	"regexp"
	"time"

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
	OcmClient
	PdClient
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
	SilenceAlert(notes string) error
	MoveToEscalationPolicy(escalationPolicyID string) error
	GetEscalationPolicy() string
	GetSilentPolicy() string
	GetServiceID() string
}

// Client refers to the CCAM client
type Client struct {
	Service
	cluster *v1.Cluster
	v1.LimitedSupportReason
}

// New creates a new CCAM client and gets the cluster object from ocm for the internal id
func New(ocmClient OcmClient, pdClient PdClient, externalClusterID string) (Client, error) {
	client := Client{
		Service: Provider{
			OcmClient: ocmClient,
			PdClient:  pdClient,
		},
	}
	err := client.populateStructWith(externalClusterID)
	if err != nil {
		return Client{}, err
	}
	return client, nil
}

// populateStructWith will populate the client with v1.Cluster object from ocm
func (c *Client) populateStructWith(externalID string) error {
	if c.cluster == nil {
		cluster, err := c.GetClusterInfo(externalID)
		if err != nil {
			return fmt.Errorf("could not retrieve cluster info for %s in CCAM step: %w", externalID, err)
		}
		// fmt.Printf("cluster ::: %v\n", cluster)
		c.cluster = cluster
	}
	return nil
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
func (c Client) Evaluate(awsError error, externalClusterID string, incidentID string) error {
	err := c.populateStructWith(externalClusterID)
	if err != nil {
		return fmt.Errorf("failed to populate struct in Evaluate in CCAM step: %w", err)
	}
	if !c.checkMissing(awsError) {
		return fmt.Errorf("credentials are there, error is different: %w", awsError)
	}

	lsExists, err := c.LimitedSupportExists(ccamLimitedSupport, c.cluster.ID())
	if err != nil {
		return fmt.Errorf("couldn't determine if limited support reason already exists: %w", err)
	}
	if !lsExists {
		err = c.PostLimitedSupportReason(ccamLimitedSupport, c.cluster.ID())
		if err != nil {
			return fmt.Errorf("could not post limited support reason for %s: %w", c.cluster.Name(), err)
		}

	}
	return c.SilenceAlert(fmt.Sprintf("Added the following Limited Support reason to cluster: %#v\n", ccamLimitedSupport))
}

// RemoveLimitedSupport will remove any CCAM limited support reason from the cluster,
// if it fails to do so, it will try to alert primary until it succeeds
// Run this after cloud credentials are confirmed
func (c Client) RemoveLimitedSupport() error {
	err := utils.Retry(3, time.Second*2, func() error {
		return c.DeleteLimitedSupportReasons(ccamLimitedSupport, c.cluster.ID())
	})
	if err != nil {
		fmt.Println("Failed 3 times to remove CCAM Limited support reason from cluster. Attempting to alert Primary.")
		originalErr := err
		err := utils.Retry(3, time.Second*2, func() error {
			return c.CreateNewAlert(c.getCCAMAlert(originalErr), c.GetServiceID())
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

// GetCCAMAlert will return a NewAlert populated with cluster id and the specific error
func (c Client) getCCAMAlert(lsError error) pagerduty.NewAlert {
	return pagerduty.NewAlert{
		Description: fmt.Sprintf("CAD is unable to remove a Limited Support reason from cluster %s", c.cluster.ID()),
		Details: pagerduty.NewAlertDetails{
			ClusterID:  c.cluster.ID(),
			Error:      lsError.Error(),
			Resolution: "CAD has been unable to remove a Limited Support reason from this cluster. The cluster needs to be manually reviewed and have any appropriate Limited Support reasons removed. After corrective actions have been taken, this alert must be manually resolved.",
			SOP:        "https://github.com/openshift/ops-sop/blob/master/v4/alerts/CAD_ErrorRemovingLSReason.md",
		},
	}
}

// Package ccam Cluster Credentials Are Missing (CCAM) provides a service for detecting missing cluster credentials
package ccam

import (
	"fmt"
	"regexp"

	v1 "github.com/openshift-online/ocm-sdk-go/clustersmgmt/v1"
	"github.com/openshift/configuration-anomaly-detection/pkg/ocm"
	"github.com/openshift/configuration-anomaly-detection/pkg/pagerduty"
)

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
	CCAMLimitedSupportExists(clusterID string) (bool, error)
	PostCCAMLimitedSupportReason(clusterID string) (*v1.LimitedSupportReason, error)
	// PD
	AddNote(incidentID string, noteContent string) error
	MoveToEscalationPolicy(incidentID string, escalationPolicyID string) error
	GetEscalationPolicy() string
	GetSilentPolicy() string
}

// Client refers to the CCAM client
type Client struct {
	Service
	cluster *v1.Cluster
}

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

	lsExists, err := c.CCAMLimitedSupportExists(c.cluster.ID())
	if err != nil {
		return fmt.Errorf("couldn't determine if limited support reason already exists: %w", err)
	}
	if !lsExists {
		ls, err := c.PostCCAMLimitedSupportReason(c.cluster.ID())
		if err != nil {
			return err
		}
		fmt.Printf("Added the following Limited Support reason to cluster: %#v\n", *ls)
	} else {
		fmt.Println("Avoided reposting duplicate CCAM limited support reason")
	}

	return c.silenceAlert(incidentID, fmt.Sprintf("Cluster %s incident silenced", externalClusterID))
}

// PostLimitedSupport adds a limited support reason to corresponding cluster
func (c Client) PostLimitedSupport() (*v1.LimitedSupportReason, error) {
	id := c.cluster.ID()
	reason, err := c.PostCCAMLimitedSupportReason(id)
	if err != nil {
		return nil, fmt.Errorf("could not post limited support reason for %s: %w", c.cluster.Name(), err)
	}

	return reason, nil
}

// silenceAlert annotates the PagerDuty alert with the given notes and silences it via
// assigning the "Silent Test" escalation policy
func (c Client) silenceAlert(incidentID, notes string) error {
	escalationPolicy := c.GetSilentPolicy()
	if notes != "" {
		fmt.Printf("Attaching Note %s\n", notes)
		err := c.AddNote(incidentID, notes)
		if err != nil {
			return fmt.Errorf("failed to attach notes to CCAM incident: %w", err)
		}
	}
	fmt.Printf("Moving Alert to Escalation Policy %s\n", escalationPolicy)
	err := c.MoveToEscalationPolicy(incidentID, escalationPolicy)
	if err != nil {
		return fmt.Errorf("failed to change incident escalation policy in CCAM step: %w", err)
	}
	return nil
}

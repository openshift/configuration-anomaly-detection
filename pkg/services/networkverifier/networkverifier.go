// Package networkverifier contains functionality for running the network verifier
package networkverifier

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go/aws/credentials"
	v1 "github.com/openshift-online/ocm-sdk-go/clustersmgmt/v1"
	hivev1 "github.com/openshift/hive/apis/hive/v1"

	"github.com/openshift/configuration-anomaly-detection/pkg/aws"
	"github.com/openshift/configuration-anomaly-detection/pkg/ocm"

	"github.com/openshift/osd-network-verifier/pkg/proxy"
	"github.com/openshift/osd-network-verifier/pkg/verifier"
	awsverifier "github.com/openshift/osd-network-verifier/pkg/verifier/aws"
)

// AwsClient is a wrapper around the aws client, and is used to import the received functions into the Provider
type AwsClient = aws.Client

// OcmClient is a wrapper around the ocm client, and is used to import the received functions into the Provider
type OcmClient = ocm.Client

// Provider should have all the functions that ChgmService is implementing
type Provider struct {
	// having awsClient and ocmClient this way
	// allows for all the method receivers defined on them to be passed into the parent struct,
	// thus making it more composable than just having each func redefined here
	//
	// a different solution is to have the structs have unique names to begin with, which makes the code
	// aws.AwsClient feel a bit redundant\
	*AwsClient
	*OcmClient
}

// Service will wrap all the required commands the client needs to run its operations
type Service interface {
	// OCM
	GetClusterInfo(identifier string) (*v1.Cluster, error)
	GetClusterDeployment(clusterID string) (*hivev1.ClusterDeployment, error)
	// AWS
	GetSubnetID(infraID string) ([]string, error)
	GetSecurityGroupID(infraID string) (string, error)
	GetAWSCredentials() credentials.Value
	IsSubnetPrivate(subnet string) bool
}

// Client refers to the networkverifier client
type Client struct {
	Service
	Cluster           *v1.Cluster
	ClusterDeployment *hivev1.ClusterDeployment
}

func (c *Client) populateStructWith(externalID string) error {
	var err error

	if c.Cluster == nil {
		c.Cluster, err = c.GetClusterInfo(externalID)
		if err != nil {
			return fmt.Errorf("could not retrieve cluster info for %s: %w", externalID, err)
		}
	}

	if c.ClusterDeployment == nil {
		id := c.Cluster.ID()
		c.ClusterDeployment, err = c.GetClusterDeployment(id)
		if err != nil {
			return fmt.Errorf("could not retrieve Cluster Deployment for %s: %w", id, err)
		}
	}
	return nil
}

type egressConfig struct {
	cloudImageID string
	instanceType string
	cloudTags    map[string]string
	timeout      time.Duration
	kmsKeyID     string
	httpProxy    string
	httpsProxy   string
	CaCert       string
	noTLS        bool
}

var (
	awsDefaultTags = map[string]string{"osd-network-verifier": "owned", "red-hat-managed": "true", "Name": "osd-network-verifier"}
)

// VerifierResult type contains the verifier outcomes
type VerifierResult int

// Verifier outcomes
const (
	Undefined VerifierResult = 0
	Failure
	Success
)

// RunNetworkVerifier runs the network verifier tool to check for network misconfigurations
func (c Client) RunNetworkVerifier(externalClusterID string) (result VerifierResult, whatisthis string, name error) { // TODO
	fmt.Printf("Running Network Verifier...\n")
	err := c.populateStructWith(externalClusterID)
	if err != nil {
		return Undefined, "", fmt.Errorf("failed to populate struct in runNetworkVerifier in networkverifier step: %w", err)
	}

	infraID := c.ClusterDeployment.Spec.ClusterMetadata.InfraID

	credentials := c.GetAWSCredentials()
	if err != nil {
		return Undefined, "", fmt.Errorf("failed to get AWS Credentials: %w", err)
	}

	config := egressConfig{}

	p := proxy.ProxyConfig{
		HttpProxy:  config.httpProxy,
		HttpsProxy: config.httpsProxy,
		Cacert:     config.CaCert,
		NoTls:      config.noTLS,
	}

	securityGroupID, err := c.GetSecurityGroupID(infraID)
	if err != nil {
		return Undefined, "", fmt.Errorf("failed to get SecurityGroupId: %w", err)
	}

	subnets, err := c.GetSubnets(infraID)
	// If multiple private subnets are found the networkverifier will run on the first subnet
	subnet := subnets[0]
	if err != nil {
		return Undefined, "", fmt.Errorf("failed to get Subnets: %w", err)
	}

	fmt.Printf("Using Security Group ID: %s\n", securityGroupID)
	fmt.Printf("Using SubnetID: %s\n", subnet)

	// setup non cloud config options
	validateEgressInput := verifier.ValidateEgressInput{
		Ctx:          context.TODO(),
		SubnetID:     subnet,
		CloudImageID: config.cloudImageID,
		Timeout:      config.timeout,
		Tags:         config.cloudTags,
		InstanceType: config.instanceType,
		Proxy:        p,
	}

	if len(validateEgressInput.Tags) == 0 {
		validateEgressInput.Tags = awsDefaultTags
	}

	// Setup AWS Specific Configs
	validateEgressInput.AWS = verifier.AwsEgressConfig{
		KmsKeyID:        config.kmsKeyID,
		SecurityGroupId: securityGroupID,
	}

	awsVerifier, err := awsverifier.NewAwsVerifier(credentials.AccessKeyID, credentials.SecretAccessKey, credentials.SessionToken, c.Cluster.Region().ID(), "", true)
	if err != nil {
		return Undefined, "", fmt.Errorf("could not build awsVerifier %v", err)
	}

	fmt.Printf("Using region: %s", c.Cluster.Region().ID())

	out := verifier.ValidateEgress(awsVerifier, validateEgressInput)

	verifierFailures, verifierExceptions, verifierErrors := out.Parse()

	if len(verifierExceptions) != 0 && len(verifierErrors) != 0 {
		exceptionsSummary := verifierExceptions[0].Error()
		errorsSummary := verifierErrors[0].Error()
		return Undefined, "", fmt.Errorf(exceptionsSummary, errorsSummary)
	}

	if !out.IsSuccessful() {
		failureSummary := verifierFailures[0].Error() // create from verifierFailures
		return Failure, failureSummary, nil
	}
	return Success, "", nil
}

// GetSubnets gets the private subnets for the cluster based on cluster type
func (c Client) GetSubnets(infraID string) ([]string, error) {
	// For non-BYOVPC clusters, retrieve private subnets by tag
	if len(c.Cluster.AWS().SubnetIDs()) == 0 {
		subnets, _ := c.GetSubnetID(infraID)
		return subnets, nil
	}
	// For PrivateLink clusters, any provided subnet is considered a private subnet
	if c.Cluster.AWS().PrivateLink() {
		if len(c.Cluster.AWS().SubnetIDs()) == 0 {
			return nil, fmt.Errorf("unexpected error: %s is a PrivateLink cluster, but no subnets in OCM", infraID)
		}
		subnets := c.Cluster.AWS().SubnetIDs()
		return subnets, nil
	}
	// For non-PrivateLink BYOVPC clusters get subnets from OCM and determine which is private
	if !c.Cluster.AWS().PrivateLink() && len(c.Cluster.AWS().SubnetIDs()) != 0 {
		subnets := c.Cluster.AWS().SubnetIDs()
		for _, subnet := range subnets {
			if c.IsSubnetPrivate(subnet) {
				return []string{subnet}, nil
			}
		}
		return nil, fmt.Errorf("could not determine private subnet")
	}
	return nil, fmt.Errorf("could not retrieve subnets")
}

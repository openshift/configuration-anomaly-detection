// package networkverifier contains functionality for running the network verifier
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
	"github.com/openshift/configuration-anomaly-detection/pkg/pagerduty"

	"github.com/openshift/osd-network-verifier/pkg/proxy"
	"github.com/openshift/osd-network-verifier/pkg/verifier"
	awsverifier "github.com/openshift/osd-network-verifier/pkg/verifier/aws"
)

// AwsClient is a wrapper around the aws client, and is used to import the received functions into the Provider
type AwsClient = aws.Client

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
	// aws.AwsClient feel a bit redundant\
	*AwsClient
	*OcmClient
	*PdClient
}

// Service will wrap all the required commands the client needs to run its operations
type Service interface {
	// OCM
	GetClusterInfo(identifier string) (*v1.Cluster, error)
	GetClusterDeployment(clusterID string) (*hivev1.ClusterDeployment, error)
	// AWS
	GetSubnetID(infraID string) ([]string, error)
	GetSecurityGroupID(infraID string) (string, error)
	GetAWSCredentials() (credentials.Value, error)
	IsSubnetPrivate(subnet string) bool
}

// Client refers to the networkverifier client
type Client struct {
	Service
	cluster *v1.Cluster
	cd      *hivev1.ClusterDeployment
}

func (c *Client) populateStructWith(externalID string) error {
	if c.cluster == nil {
		cluster, err := c.GetClusterInfo(externalID)
		if err != nil {
			return fmt.Errorf("could not retrieve cluster info for %s: %w", externalID, err)
		}
		// fmt.Printf("cluster ::: %v\n", cluster)
		c.cluster = cluster
	}
	id := c.cluster.ID()

	if c.cd == nil {
		cd, err := c.GetClusterDeployment(id)
		if err != nil {
			return fmt.Errorf("could not retrieve Cluster Deployment for %s: %w", id, err)
		}
		c.cd = cd
	}
	// fmt.Printf("cd ::: %v\n", cd)
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
	noTls        bool
}

var (
	awsDefaultTags = map[string]string{"osd-network-verifier": "owned", "red-hat-managed": "true", "Name": "osd-network-verifier"}
)

// VerifierResult
type VerifierResult int

const (
	Undefined VerifierResult = 0
	Failure
	Success
)

//runNetworkVerifier runs the network verifier tool to check for network misconfigurations
func (c Client) RunNetworkVerifier(externalClusterID string) (VerifierResult, string, error) {
	fmt.Printf("Running Network Verifier...\n")
	err := c.populateStructWith(externalClusterID)
	if err != nil {
		return Undefined, "", fmt.Errorf("failed to populate struct in runNetworkVerifier in networkverifier step: %w", err)
	}

	infraID := c.cd.Spec.ClusterMetadata.InfraID

	credentials, err := c.GetAWSCredentials()
	if err != nil {
		return Undefined, "", fmt.Errorf("failed to get AWS Credentials: %w", err)
	}

	config := egressConfig{}

	p := proxy.ProxyConfig{
		HttpProxy:  config.httpProxy,
		HttpsProxy: config.httpsProxy,
		Cacert:     config.CaCert,
		NoTls:      config.noTls,
	}

	securityGroupId, err := c.GetSecurityGroupID(infraID)
	if err != nil {
		return Undefined, "", fmt.Errorf("failed to get SecurityGroupId: %w", err)
	}

	subnets, err := c.GetSubnets(infraID)
	subnet := subnets[0]
	if err != nil {
		return Undefined, "", fmt.Errorf("failed to get Subnets: %w", err)
	}

	fmt.Printf("Using Security Group ID: %s\n", securityGroupId)
	fmt.Printf("Using SubnetID: %s\n", subnet)

	// setup non cloud config options
	vei := verifier.ValidateEgressInput{
		Ctx:          context.TODO(),
		SubnetID:     subnet,
		CloudImageID: config.cloudImageID,
		Timeout:      config.timeout,
		Tags:         config.cloudTags,
		InstanceType: config.instanceType,
		Proxy:        p,
	}

	if len(vei.Tags) == 0 {
		vei.Tags = awsDefaultTags
	}

	//Setup AWS Specific Configs
	vei.AWS = verifier.AwsEgressConfig{
		KmsKeyID:        config.kmsKeyID,
		SecurityGroupId: securityGroupId,
	}

	awsVerifier, err := awsverifier.NewAwsVerifier(credentials.AccessKeyID, credentials.SecretAccessKey, credentials.SessionToken, c.cluster.Region().ID(), "", true)
	if err != nil {
		return Undefined, "", fmt.Errorf("could not build awsVerifier %v", err)
	}

	awsVerifier.Logger.Warn(context.TODO(), "Using region: %s", c.cluster.Region().ID())

	out := verifier.ValidateEgress(awsVerifier, vei)

	verifierFailures, verifierExceptions, verifierErrors := out.Parse()

	if len(verifierExceptions) != 0 && len(verifierErrors) != 0 {
		exceptionsSummary := verifierExceptions[0].Error()
		errorsSummary := verifierErrors[0].Error()
		//AddNote
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
	if len(c.cluster.AWS().SubnetIDs()) == 0 {
		subnets, _ := c.GetSubnetID(infraID)
		return subnets, nil
	}
	// For PrivateLink clusters, any provided subnet is considered a private subnet
	if c.cluster.AWS().PrivateLink() {
		if len(c.cluster.AWS().SubnetIDs()) == 0 {
			return nil, fmt.Errorf("unexpected error: %s is a PrivateLink cluster, but no subnets in OCM", infraID)
		}
		subnets := c.cluster.AWS().SubnetIDs()
		return subnets, nil
	}
	// For non-PrivateLink BYOVPC clusters get subnets from OCM and determine which is private
	if !c.cluster.AWS().PrivateLink() && len(c.cluster.AWS().SubnetIDs()) != 0 {
		subnets := c.cluster.AWS().SubnetIDs()
		for _, subnet := range subnets {
			if c.IsSubnetPrivate(subnet) {
				return []string{subnet}, nil
			}
		}
		return nil, fmt.Errorf("could not determine private subnet")
	}
	return nil, fmt.Errorf("could not retrieve subnets")
}

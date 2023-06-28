// Package networkverifier contains functionality for running the network verifier
package networkverifier

import (
	"context"
	"fmt"
	"strings"
	"time"

	v1 "github.com/openshift-online/ocm-sdk-go/clustersmgmt/v1"
	"github.com/openshift/configuration-anomaly-detection/pkg/aws"
	"github.com/openshift/configuration-anomaly-detection/pkg/services/logging"

	hivev1 "github.com/openshift/hive/apis/hive/v1"
	"github.com/openshift/osd-network-verifier/pkg/proxy"
	"github.com/openshift/osd-network-verifier/pkg/verifier"
	awsverifier "github.com/openshift/osd-network-verifier/pkg/verifier/aws"
)

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
	Failure   VerifierResult = 1
	Success   VerifierResult = 2
)

// Run runs the network verifier tool to check for network misconfigurations
func Run(cluster *v1.Cluster, clusterDeployment *hivev1.ClusterDeployment, awsClient aws.Client) (result VerifierResult, failures string, name error) { // TODO
	logging.Info("Running Network Verifier...")
	infraID := clusterDeployment.Spec.ClusterMetadata.InfraID

	credentials := awsClient.GetAWSCredentials()

	config := egressConfig{}

	p := proxy.ProxyConfig{
		HttpProxy:  config.httpProxy,
		HttpsProxy: config.httpsProxy,
		Cacert:     config.CaCert,
		NoTls:      config.noTLS,
	}

	securityGroupID, err := awsClient.GetSecurityGroupID(infraID)
	if err != nil {
		return Undefined, "", fmt.Errorf("failed to get SecurityGroupId: %w", err)
	}

	subnets, err := getSubnets(infraID, cluster, awsClient)
	// If multiple private subnets are found the networkverifier will run on the first subnet
	subnet := subnets[0]
	if err != nil {
		return Undefined, "", fmt.Errorf("failed to get Subnets: %w", err)
	}

	logging.Infof("Using Security Group ID: %s", securityGroupID)
	logging.Infof("Using SubnetID: %s", subnet)

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

	awsVerifier, err := awsverifier.NewAwsVerifier(credentials.AccessKeyID, credentials.SecretAccessKey, credentials.SessionToken, cluster.Region().ID(), "", false)
	if err != nil {
		return Undefined, "", fmt.Errorf("could not build awsVerifier %v", err)
	}

	logging.Infof("Using region: %s", cluster.Region().ID())

	out := verifier.ValidateEgress(awsVerifier, validateEgressInput)

	verifierFailures, verifierExceptions, verifierErrors := out.Parse()

	if len(verifierExceptions) != 0 || len(verifierErrors) != 0 {

		exceptionsSummary := ""
		errorsSummary := ""

		if len(verifierExceptions) > 0 {
			exceptionsSummary = verifierExceptions[0].Error()
		}
		if len(verifierErrors) > 0 {
			errorsSummary = verifierErrors[0].Error()
		}
		return Undefined, "", fmt.Errorf(exceptionsSummary, errorsSummary)
	}

	if !out.IsSuccessful() {
		failureSummary := ""
		for _, failure := range verifierFailures {
			failureSummary = failureSummary + failure.Error() + ","
		}

		return Failure, strings.TrimSuffix(strings.ReplaceAll(failureSummary, "egressURL error: ", ""), ","), nil
	}

	return Success, "", nil
}

// GetSubnets gets the private subnets for the cluster based on cluster type
func getSubnets(infraID string, cluster *v1.Cluster, awsClient aws.Client) ([]string, error) {
	// For non-BYOVPC clusters, retrieve private subnets by tag
	if len(cluster.AWS().SubnetIDs()) == 0 {
		subnets, _ := awsClient.GetSubnetID(infraID)
		return subnets, nil
	}
	// For PrivateLink clusters, any provided subnet is considered a private subnet
	if cluster.AWS().PrivateLink() {
		if len(cluster.AWS().SubnetIDs()) == 0 {
			return nil, fmt.Errorf("unexpected error: %s is a PrivateLink cluster, but no subnets in OCM", infraID)
		}
		subnets := cluster.AWS().SubnetIDs()
		return subnets, nil
	}
	// For non-PrivateLink BYOVPC clusters get subnets from OCM and determine which is private
	if !cluster.AWS().PrivateLink() && len(cluster.AWS().SubnetIDs()) != 0 {
		subnets := cluster.AWS().SubnetIDs()
		for _, subnet := range subnets {
			if awsClient.IsSubnetPrivate(subnet) {
				return []string{subnet}, nil
			}
		}
		return nil, fmt.Errorf("could not determine private subnet")
	}
	return nil, fmt.Errorf("could not retrieve subnets")
}

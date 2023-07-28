// Package networkverifier contains functionality for running the network verifier
package networkverifier

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	v1 "github.com/openshift-online/ocm-sdk-go/clustersmgmt/v1"
	"github.com/openshift/configuration-anomaly-detection/pkg/aws"
	"github.com/openshift/configuration-anomaly-detection/pkg/logging"

	hivev1 "github.com/openshift/hive/apis/hive/v1"
	"github.com/openshift/osd-network-verifier/pkg/helpers"
	"github.com/openshift/osd-network-verifier/pkg/proxy"
	"github.com/openshift/osd-network-verifier/pkg/verifier"
	onv "github.com/openshift/osd-network-verifier/pkg/verifier"
	onvAwsClient "github.com/openshift/osd-network-verifier/pkg/verifier/aws"
)

// VerifierResult type contains the verifier outcomes
type VerifierResult int

// Verifier outcomes
const (
	Undefined VerifierResult = 0
	Failure   VerifierResult = 1
	Success   VerifierResult = 2
)

func initializeValidateEgressInput(cluster *v1.Cluster, clusterDeployment *hivev1.ClusterDeployment, awsClient aws.Client) (*onv.ValidateEgressInput, error) {
	infraID := clusterDeployment.Spec.ClusterMetadata.InfraID
	securityGroupID, err := awsClient.GetSecurityGroupID(infraID)
	if err != nil {
		return nil, fmt.Errorf("failed to get SecurityGroupId: %w", err)
	}

	subnets, err := getSubnets(infraID, cluster, awsClient)

	if len(subnets) == 0 {
		return nil, errors.New("failed to find a subnet for this cluster")
	}

	// If multiple private subnets are found the networkverifier will run on the first subnet
	subnet := subnets[0]
	if err != nil {
		return nil, fmt.Errorf("failed to get Subnets: %w", err)
	}

	awsDefaultTags := map[string]string{
		"osd-network-verifier": "owned",
		"red-hat-managed":      "true",
		"Name":                 "osd-network-verifier",
	}

	region := cluster.Region().ID()
	if onvAwsClient.GetAMIForRegion(region) == "" {
		return nil, fmt.Errorf("unsupported region: %s", region)
	}

	proxy := proxy.ProxyConfig{}
	// If the cluster has a cluster-wide proxy, configure it
	if cluster.Proxy() != nil && !cluster.Proxy().Empty() {
		proxy.HttpProxy = cluster.Proxy().HTTPProxy()
		proxy.HttpsProxy = cluster.Proxy().HTTPSProxy()
	}

	// The actual trust bundle is redacted in OCM - we would have to get it from hive once CAD has backplane access
	if cluster.AdditionalTrustBundle() != "" {
		return nil, errors.New("cluster has an additional trust bundle configured - this is currently not supported by CAD's network verifier")
	}

	return &onv.ValidateEgressInput{
		Timeout:      2 * time.Second,
		Ctx:          context.TODO(),
		SubnetID:     subnet,
		CloudImageID: onvAwsClient.GetAMIForRegion(region),
		InstanceType: "t3.micro",
		Proxy:        proxy,
		PlatformType: helpers.PlatformAWS,
		Tags:         awsDefaultTags,
		AWS: onv.AwsEgressConfig{
			SecurityGroupId: securityGroupID,
		},
	}, nil
}

// Run runs the network verifier tool to check for network misconfigurations
func Run(cluster *v1.Cluster, clusterDeployment *hivev1.ClusterDeployment, awsClient aws.Client) (result VerifierResult, failures string, name error) {
	validateEgressInput, err := initializeValidateEgressInput(cluster, clusterDeployment, awsClient)
	if err != nil {
		return Undefined, "", fmt.Errorf("failed to initialize validateEgressInput: %w", err)
	}

	credentials := awsClient.GetAWSCredentials()
	awsVerifier, err := onvAwsClient.NewAwsVerifier(credentials.AccessKeyID, credentials.SecretAccessKey, credentials.SessionToken, cluster.Region().ID(), "", false)
	if err != nil {
		return Undefined, "", fmt.Errorf("could not build awsVerifier %w", err)
	}

	logging.Infof("Running Network Verifier with security group '%s' - subnet '%s' - region '%s'... ", validateEgressInput.AWS.SecurityGroupId, validateEgressInput.SubnetID, cluster.Region().ID())

	out := verifier.ValidateEgress(awsVerifier, *validateEgressInput)

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

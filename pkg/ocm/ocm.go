package ocm

import (
	"encoding/json"
	"fmt"
	"os"

	_ "github.com/golang/mock/mockgen/model"
	sdkcfg "github.com/openshift-online/ocm-cli/pkg/config"
	sdk "github.com/openshift-online/ocm-sdk-go"

	awsv1alpha1 "github.com/openshift/aws-account-operator/pkg/apis/aws/v1alpha1"
	hivev1 "github.com/openshift/hive/apis/hive/v1"
)

type ocmClient struct {
	conn *sdk.Connection
	cfg  *sdkcfg.Config
}

// New will create a new ocm client by using the path to a config file
// if no path is provided, it will assume it in the default path
func New(ocmConfigFile string) (ocmClient, error) {
	client := ocmClient{}
	cfg, err := newConfigFromFile(ocmConfigFile)
	if err != nil {
		return client, fmt.Errorf("failed to load config file: %w", err)
	}
	client.cfg = cfg

	conn, err := client.cfg.Connection()
	if err != nil {
		return client, fmt.Errorf("can't create connection: %w", err)
	}
	client.conn = conn
	return client, nil
}

// GetSupportRoleARN returns the support role ARN that allows the access to the cluster
func (client ocmClient) GetSupportRoleARN(clusterID string) (string, error) {
	claim, err := client.GetAWSAccountClaim(clusterID)
	if err != nil {
		return "", fmt.Errorf("failed to get account claim: %w", err)
	}
	arn := claim.Spec.SupportRoleARN
	if arn == "" {
		// if the supportRoleARN is not set, then we won't know which role inside of the customer
		// AWS account to assume into. This is defined by the customer for STS clusters, and defined
		// by the aws-account-operator on CCS and OSD accounts
		return "", fmt.Errorf("AccountClaim is invalid: supportRoleARN is not present in the AccountClaim")
	}
	return arn, nil
}

// GetAWSAccountClaim gets the AWS Account Claim object for a given cluster
func (client ocmClient) GetAWSAccountClaim(clusterID string) (*awsv1alpha1.AccountClaim, error) {
	ac := &awsv1alpha1.AccountClaim{}
	acString, err := client.getClusterResource(clusterID, "aws_account_claim")
	if err != nil {
		return ac, fmt.Errorf("client failed to load GetAWSAccountClaim: %w", err)
	}
	err = json.Unmarshal([]byte(acString), ac)
	if err != nil {
		return ac, fmt.Errorf("failed to unmarshal client response (%s) with error: %w", acString, err)
	}
	return ac, err
}

// GetClusterDeployment gets the ClusterDeployment object for a given cluster
func (client ocmClient) GetClusterDeployment(clusterID string) (*hivev1.ClusterDeployment, error) {
	cd := &hivev1.ClusterDeployment{}
	cdString, err := client.getClusterResource(clusterID, "cluster_deployment")
	if err != nil {
		return cd, fmt.Errorf("client failed to load ClusterDeployment: %w", err)
	}
	err = json.Unmarshal([]byte(cdString), cd)
	if err != nil {
		return cd, fmt.Errorf("failed to unmarshal client response (%s) with error: %w", cdString, err)
	}
	return cd, nil
}

// getClusterResource allows to load different cluster resources
func (client ocmClient) getClusterResource(clusterID string, resourceKey string) (string, error) {

	response, err := client.conn.ClustersMgmt().V1().Clusters().Cluster(clusterID).Resources().Live().Get().Send()
	if err != nil {
		return "", err
	}
	return response.Body().Resources()[resourceKey], nil
}

// newConfigFromFile loads the configuration file (ocmConfigFile, ~/.ocm.json, /ocm/ocm.json)
func newConfigFromFile(ocmConfigFile string) (*sdkcfg.Config, error) {
	if ocmConfigFile != "" {
		err := os.Setenv("OCM_CONFIG", ocmConfigFile)
		if err != nil {
			return nil, err
		}
	}
	// Load the configuration file from std path
	cfg, err := sdkcfg.Load()
	if err != nil {
		return nil, err
	}
	if cfg == nil || cfg == (&sdkcfg.Config{}) {
		return nil, fmt.Errorf("not logged in")
	}
	return cfg, err
}

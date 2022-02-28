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

// NewOcmClient will create a new ocm client by using the path to a config file
// if no path is provided, it will assume it in the default path
func NewOcmClient(ocmConfigFile string) (ocmClient, error) {

	client := ocmClient{}
	cfg, err := newConfigFromFile(ocmConfigFile)
	if err != nil {
		return client, fmt.Errorf("failed to load config file: %w", err) // ConfigError{path: ocmConfigFile, err:err}
	}
	client.cfg = cfg

	conn, err := client.establishConnection()
	if err != nil {
		return client, fmt.Errorf("can't create connection: %w", err) // ConnectionError{client:client, err:err}
	}
	client.conn = conn

	return client, nil
}

// GetAWSAccountClaim gets the AWS Account Claim object for a given cluster
func (client ocmClient) GetAWSAccountClaim(clusterID string) (*awsv1alpha1.AccountClaim, error) {
	ac := &awsv1alpha1.AccountClaim{}
	acString, err := client.getClusterResource(clusterID, "aws_account_claim")
	if err != nil {
		return ac, err
	}
	err = json.Unmarshal([]byte(acString), ac)
	return ac, err
}

// getClusterResource handles caching the live cluster resource endpoint and returns the key
// you're looking for. This function only caches certain values, as some are not necessary at
// this time, such as the cluster install logs.
func (client ocmClient) getClusterResource(clusterID string, resourceKey string) (string, error) {

	response, err := client.conn.ClustersMgmt().V1().Clusters().Cluster(clusterID).Resources().Live().Get().Send()
	if err != nil {
		return "", err
	}
	return response.Body().Resources()[resourceKey], nil
}

// GetClusterDeployment gets the ClusterDeployment object for a given cluster
func (client ocmClient) GetClusterDeployment(clusterID string) (*hivev1.ClusterDeployment, error) {
	cd := &hivev1.ClusterDeployment{}
	cdString, err := client.getClusterResource(clusterID, "cluster_deployment")
	if err != nil {
		return cd, err
	}
	err = json.Unmarshal([]byte(cdString), cd)
	return cd, err
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
	if cfg == nil {
		return nil, fmt.Errorf("not logged in")
	}
	return cfg, err
}

// establishConnection creates a connection from the client settings
func (client ocmClient) establishConnection() (*sdk.Connection, error) {

	if client.cfg == (&sdkcfg.Config{}) || client.cfg == nil {
		return nil, fmt.Errorf("config is empty, aborting")
	}
	builder := sdk.NewConnectionBuilder()
	if client.cfg.TokenURL != "" {
		builder.TokenURL(client.cfg.TokenURL)
	}
	if client.cfg.ClientID != "" || client.cfg.ClientSecret != "" {
		builder.Client(client.cfg.ClientID, client.cfg.ClientSecret)
	}
	if client.cfg.Scopes != nil {
		builder.Scopes(client.cfg.Scopes...)
	}
	if client.cfg.URL != "" {
		builder.URL(client.cfg.URL)
	}
	if client.cfg.User != "" || client.cfg.Password != "" {
		builder.User(client.cfg.User, client.cfg.Password)
	}
	if client.cfg.AccessToken != "" {
		builder.Tokens(client.cfg.AccessToken)
	}
	if client.cfg.RefreshToken != "" {
		builder.Tokens(client.cfg.RefreshToken)
	}
	builder.Insecure(client.cfg.Insecure)
	// Create the connection:
	conn, err := builder.Build()
	if err != nil {
		return nil, err
	}
	return conn, nil
}

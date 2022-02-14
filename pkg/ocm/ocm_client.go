package ocm

import (
	"encoding/json"
	"os"

	sdk "github.com/openshift-online/ocm-sdk-go"
	"github.com/openshift-online/ocm-sdk-go/logging"
	awsv1alpha1 "github.com/openshift/aws-account-operator/pkg/apis/aws/v1alpha1"
	hivev1 "github.com/openshift/hive/apis/hive/v1"
)

type Client interface {
	GetAWSAccountClaim(clusterID string) (*awsv1alpha1.AccountClaim, error)
	GetClusterDeployment(clusterID string) (*hivev1.ClusterDeployment, error)
}

type client struct {
	Conn   *sdk.Connection
	logger *sdk.GlogLogger
}

func NewOcmClient(ocmConfigFile string) (Client, error) {
	if ocmconfig := os.Getenv("OCM_CONFIG"); ocmconfig == "" {
		err := os.Setenv("OCM_CONFIG", ocmConfigFile)
		if err != nil {
			return nil, err
		}
	}

	logger, err := logging.NewGlogLoggerBuilder().
		ErrorV(0).
		WarnV(0).
		InfoV(1).
		DebugV(2).
		Build()

	if err != nil {
		return nil, err
	}

	conn, err := NewConnection().Build()

	if err != nil {
		return nil, err
	}

	client := &client{
		Conn:   conn,
		logger: logger,
	}
	return client, nil
}

// GetAWSAccountClaim gets the AWS Account Claim object for a given cluster
func (client *client) GetAWSAccountClaim(clusterID string) (*awsv1alpha1.AccountClaim, error) {
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
func (client *client) getClusterResource(clusterID string, resourceKey string) (string, error) {

	response, err := client.Conn.ClustersMgmt().V1().Clusters().Cluster(clusterID).Resources().Live().Get().Send()
	if err != nil {
		return "", err
	}
	return response.Body().Resources()[resourceKey], nil
}

// GetClusterDeployment gets the ClusterDeployment object for a given cluster
func (client *client) GetClusterDeployment(clusterID string) (*hivev1.ClusterDeployment, error) {
	cd := &hivev1.ClusterDeployment{}
	cdString, err := client.getClusterResource(clusterID, "cluster_deployment")
	if err != nil {
		return cd, err
	}
	err = json.Unmarshal([]byte(cdString), cd)
	return cd, err
}

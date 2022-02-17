package ocm

import (
	"encoding/json"
	"fmt"
	"os"

	_ "github.com/golang/mock/mockgen/model"
	sdk "github.com/openshift-online/ocm-sdk-go"
	"github.com/openshift-online/ocm-sdk-go/logging"
	awsv1alpha1 "github.com/openshift/aws-account-operator/pkg/apis/aws/v1alpha1"
	hivev1 "github.com/openshift/hive/apis/hive/v1"
)

//go:generate mockgen -destination=./../utils/mocks/ocm_client_mock.go -package=mocks github.com/openshift/configuration-anomaly-detection/pkg/ocm OcmClient
type OcmClient interface {
	GetAWSAccountClaim(clusterID string) (*awsv1alpha1.AccountClaim, error)
	GetClusterDeployment(clusterID string) (*hivev1.ClusterDeployment, error)
}

type ocmclient struct {
	Conn   *sdk.Connection
	logger *sdk.GlogLogger
}

func NewOcmClient(ocmConfigFile string) (OcmClient, error) {
	if ocmconfig := os.Getenv("OCM_CONFIG"); ocmconfig == "" {
		if ocmConfigFile == "" {
			return nil, fmt.Errorf("can not create OCM client: no config forw as specified")
		}
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

	client := &ocmclient{
		Conn:   conn,
		logger: logger,
	}
	return client, nil
}

// GetAWSAccountClaim gets the AWS Account Claim object for a given cluster
func (client *ocmclient) GetAWSAccountClaim(clusterID string) (*awsv1alpha1.AccountClaim, error) {
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
func (client *ocmclient) getClusterResource(clusterID string, resourceKey string) (string, error) {

	response, err := client.Conn.ClustersMgmt().V1().Clusters().Cluster(clusterID).Resources().Live().Get().Send()
	if err != nil {
		return "", err
	}
	return response.Body().Resources()[resourceKey], nil
}

// GetClusterDeployment gets the ClusterDeployment object for a given cluster
func (client *ocmclient) GetClusterDeployment(clusterID string) (*hivev1.ClusterDeployment, error) {
	cd := &hivev1.ClusterDeployment{}
	cdString, err := client.getClusterResource(clusterID, "cluster_deployment")
	if err != nil {
		return cd, err
	}
	err = json.Unmarshal([]byte(cdString), cd)
	return cd, err
}

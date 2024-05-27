// Package managedcloud contains functionality to access cloud environments of managed clusters
package managedcloud

import (
	"context"
	"fmt"
	"os"

	cmv1 "github.com/openshift-online/ocm-sdk-go/clustersmgmt/v1"
	bpcloud "github.com/openshift/backplane-cli/cmd/ocm-backplane/cloud"
	"github.com/openshift/backplane-cli/pkg/cli/config"
	"github.com/openshift/configuration-anomaly-detection/pkg/aws"
	ocm "github.com/openshift/configuration-anomaly-detection/pkg/ocm"
)

// CreateCustomerAWSClient creates an aws.SdkClient to a cluster's AWS account
func CreateCustomerAWSClient(cluster *cmv1.Cluster, ocmClient ocm.Client) (*aws.SdkClient, error) {
	backplaneURL := os.Getenv("BACKPLANE_URL")
	if backplaneURL == "" {
		return nil, fmt.Errorf("could not create new aws client: missing environment variable BACKPLANE_URL")
	}

	backplaneInitialARN := os.Getenv("BACKPLANE_INITIAL_ARN")
	if backplaneInitialARN == "" {
		return nil, fmt.Errorf("missing environment variable BACKPLANE_INITIAL_ARN")
	}

	backplaneProxy := os.Getenv("BACKPLANE_PROXY")

	queryConfig := &bpcloud.QueryConfig{OcmConnection: ocmClient.GetConnection(), BackplaneConfiguration: config.BackplaneConfiguration{URL: backplaneURL, AssumeInitialArn: backplaneInitialARN}, Cluster: cluster}
	if backplaneProxy != "" {
		queryConfig.ProxyURL = &backplaneProxy
	}

	config, err := queryConfig.GetAWSV2Config()
	if err != nil {
		return nil, fmt.Errorf("unable to query aws credentials from backplane: %w", err)
	}

	credentials, err := config.Credentials.Retrieve(context.TODO())
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve aws credentials fetched configuration: %w", err)
	}

	return aws.NewClient(credentials.AccessKeyID, credentials.SecretAccessKey, credentials.SessionToken, cluster.Region().ID())
}

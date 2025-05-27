// Package managedcloud contains functionality to access cloud environments of managed clusters
package managedcloud

import (
	"fmt"
	"net/http"
	"net/url"

	cmv1 "github.com/openshift-online/ocm-sdk-go/clustersmgmt/v1"
	bpcloud "github.com/openshift/backplane-cli/cmd/ocm-backplane/cloud"
	"github.com/openshift/backplane-cli/pkg/cli/config"
	"github.com/openshift/configuration-anomaly-detection/pkg/aws"
	ocm "github.com/openshift/configuration-anomaly-detection/pkg/ocm"
)

// CreateCustomerAWSClient creates an aws.SdkClient to a cluster's AWS account
func CreateCustomerAWSClient(
	cluster *cmv1.Cluster,
	ocmClient ocm.Client,
	backplaneURL string,
	backplaneProxy string,
	backplaneInitialARN string,
	awsProxy string,
) (*aws.SdkClient, error) {
	queryConfig := &bpcloud.QueryConfig{OcmConnection: ocmClient.GetConnection(), BackplaneConfiguration: config.BackplaneConfiguration{URL: backplaneURL, AssumeInitialArn: backplaneInitialARN}, Cluster: cluster}
	if backplaneProxy != "" {
		queryConfig.ProxyURL = &backplaneProxy
	}

	config, err := queryConfig.GetAWSV2Config()
	if err != nil {
		return nil, fmt.Errorf("unable to query aws credentials from backplane: %w", err)
	}

	if awsProxy != "" {
		config.HTTPClient = &http.Client{
			Transport: &http.Transport{
				Proxy: func(*http.Request) (*url.URL, error) {
					return url.Parse(awsProxy)
				},
			},
		}
	}

	return aws.NewClient(config)
}

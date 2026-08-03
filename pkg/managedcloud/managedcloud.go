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

// Client holds the configuration needed to access cloud environments of managed clusters.
type Client struct {
	backplaneURL        string
	backplaneInitialARN string
	backplaneProxy      string
	awsProxy            string
}

// NewClient creates a new managedcloud Client with the given backplane and AWS configuration.
func NewClient(backplaneURL, backplaneInitialARN, backplaneProxy, awsProxy string) *Client {
	return &Client{
		backplaneURL:        backplaneURL,
		backplaneInitialARN: backplaneInitialARN,
		backplaneProxy:      backplaneProxy,
		awsProxy:            awsProxy,
	}
}

// CreateCustomerAWSClient creates an aws.SdkClient to a cluster's AWS account
func (c *Client) CreateCustomerAWSClient(cluster *cmv1.Cluster, ocmClient ocm.Client) (*aws.SdkClient, error) {
	if c.backplaneURL == "" {
		return nil, fmt.Errorf("could not create new aws client: backplane URL not configured")
	}

	if c.backplaneInitialARN == "" {
		return nil, fmt.Errorf("could not create new aws client: backplane initial ARN not configured")
	}

	queryConfig := &bpcloud.QueryConfig{OcmConnection: ocmClient.GetConnection(), BackplaneConfiguration: config.BackplaneConfiguration{URL: c.backplaneURL, AssumeInitialArn: c.backplaneInitialARN}, Cluster: cluster}
	if c.backplaneProxy != "" {
		queryConfig.ProxyURL = &c.backplaneProxy
	}

	awsConfig, err := queryConfig.GetAWSV2Config()
	if err != nil {
		return nil, fmt.Errorf("unable to query aws credentials from backplane: %w", err)
	}

	if c.awsProxy != "" {
		awsConfig.HTTPClient = &http.Client{
			Transport: &http.Transport{
				Proxy: func(*http.Request) (*url.URL, error) {
					return url.Parse(c.awsProxy)
				},
			},
		}
	}

	return aws.NewClient(awsConfig)
}

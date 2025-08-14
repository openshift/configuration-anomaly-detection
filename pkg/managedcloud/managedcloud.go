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

var (
	backplaneURL        string
	backplaneInitialARN string
	backplaneProxy      string
	awsProxy            string
)

// SetBackplaneURL sets the backplane URL to use for managed cloud connections
// FIXME: Replace with proper config mechanism when implemented service
func SetBackplaneURL(url string) {
	backplaneURL = url
}

// SetBackplaneInitialARN sets the backplane initial ARN to use for managed cloud connections
// FIXME: Replace with proper config mechanism when implemented service
func SetBackplaneInitialARN(arn string) {
	backplaneInitialARN = arn
}

// SetBackplaneProxy sets the backplane proxy to use for managed cloud connections
// FIXME: Replace with proper config mechanism when implemented service
func SetBackplaneProxy(proxy string) {
	backplaneProxy = proxy
}

// SetAWSProxy sets the AWS proxy to use for managed cloud connections
// FIXME: Replace with proper config mechanism when implemented service
func SetAWSProxy(proxy string) {
	awsProxy = proxy
}

// CreateCustomerAWSClient creates an aws.SdkClient to a cluster's AWS account
func CreateCustomerAWSClient(cluster *cmv1.Cluster, ocmClient ocm.Client) (*aws.SdkClient, error) {
	if backplaneURL == "" {
		return nil, fmt.Errorf("could not create new aws client: backplane URL not configured, call SetBackplaneURL first")
	}

	if backplaneInitialARN == "" {
		return nil, fmt.Errorf("could not create new aws client: backplane initial ARN not configured, call SetBackplaneInitialARN first")
	}

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

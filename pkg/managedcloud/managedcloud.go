// Package managedcloud contains functionality to access cloud environments of managed clusters
package managedcloud

import (
	"context"
	"fmt"
	"net/http"
	"net/url"

	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	awscreds "github.com/aws/aws-sdk-go-v2/credentials"
	cmv1 "github.com/openshift-online/ocm-sdk-go/clustersmgmt/v1"
	"github.com/openshift/configuration-anomaly-detection/pkg/aws"
	"github.com/openshift/configuration-anomaly-detection/pkg/backplane"
	ocm "github.com/openshift/configuration-anomaly-detection/pkg/ocm"
)

var (
	backplaneClient     backplane.Client
	backplaneInitialARN string
	awsProxy            string
)

// SetBackplaneClient sets the backplane client to use for managed cloud connections
func SetBackplaneClient(client backplane.Client) {
	backplaneClient = client
}

// SetBackplaneInitialARN sets the backplane initial ARN to use for managed cloud connections
// FIXME: Replace with proper config mechanism when implemented service
func SetBackplaneInitialARN(arn string) {
	backplaneInitialARN = arn
}

// SetAWSProxy sets the AWS proxy to use for managed cloud connections
// FIXME: Replace with proper config mechanism when implemented service
func SetAWSProxy(proxy string) {
	awsProxy = proxy
}

// CreateCustomerAWSClient creates an aws.SdkClient to a cluster's AWS account
func CreateCustomerAWSClient(cluster *cmv1.Cluster, ocmClient ocm.Client) (*aws.SdkClient, error) {
	if backplaneClient == nil {
		return nil, fmt.Errorf("could not create new aws client: backplane client not configured, call SetBackplaneClient first")
	}

	if cluster.CloudProvider().ID() != "aws" {
		return nil, fmt.Errorf("only AWS cloud provider is supported, cluster has: %s", cluster.CloudProvider().ID())
	}

	ctx := context.Background()
	var creds *backplane.AWSCredentials
	var err error

	// Determine if the cluster uses isolated backplane access (HCP, newer STS)
	isolated, isoErr := backplane.IsIsolatedBackplaneAccess(cluster, ocmClient)
	if isoErr != nil {
		return nil, fmt.Errorf("failed to determine if cluster is using isolated backplane access: %w", isoErr)
	}

	if isolated {
		creds, err = backplaneClient.GetIsolatedAWSCredentials(ctx, cluster, backplaneInitialARN, awsProxy)
	} else {
		creds, err = backplaneClient.GetAWSCredentials(ctx, cluster.ID(), cluster.Region().ID())
	}
	if err != nil {
		return nil, fmt.Errorf("unable to query aws credentials from backplane: %w", err)
	}

	// Create AWS config with the credentials
	awsConfig := awsv2.Config{
		Region: creds.Region,
		Credentials: awscreds.NewStaticCredentialsProvider(
			creds.AccessKeyID,
			creds.SecretAccessKey,
			creds.SessionToken,
		),
	}

	if awsProxy != "" {
		awsConfig.HTTPClient = &http.Client{
			Transport: &http.Transport{
				Proxy: func(*http.Request) (*url.URL, error) {
					return url.Parse(awsProxy)
				},
			},
		}
	}

	return aws.NewClient(awsConfig)
}

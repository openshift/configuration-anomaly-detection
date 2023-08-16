// Package utils contains utility functions
package utils

import (
	"fmt"
	"os"
	"time"

	v1 "github.com/openshift-online/ocm-sdk-go/clustersmgmt/v1"
	"github.com/openshift/configuration-anomaly-detection/pkg/aws"
	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
	"github.com/openshift/configuration-anomaly-detection/pkg/ocm"
)

// WithRetries runs a function with up to 10 retries on error
func WithRetries(fn func() error) error {
	const defaultRetries = 10
	const defaultInitialBackoff = time.Second * 2

	return WithRetriesConfigurable(defaultRetries, defaultInitialBackoff, fn)
}

// WithRetriesConfigurable runs a function with a configurable retry count and backoff interval on error
func WithRetriesConfigurable(count int, initialBackoff time.Duration, fn func() error) error {
	var err error
	for i := 0; i < count; i++ {
		if i > 0 {
			logging.Warnf("Retry %d: %s \n", i, err.Error())
			time.Sleep(initialBackoff)
			initialBackoff *= 2
		}
		err = fn()
		if err == nil {
			return nil
		}
	}
	return fmt.Errorf("failed after %d retries: %w", count, err)
}

// assumeSupportRoleChain will jump between the current aws.Client to the customers aws.Client
func assumeSupportRoleChain(baseClient aws.Client, ocmClient ocm.Client, cluster *v1.Cluster, ccsJumpRole string, supportRole string) (*aws.SdkClient, error) {
	region := cluster.Region().ID()
	internalID := cluster.ID()

	tempClient, err := baseClient.AssumeRole(ccsJumpRole, region)
	if err != nil {
		return nil, fmt.Errorf("2 failed to assume into jump-role: %w", err)
	}

	jumpRoleClient, err := tempClient.AssumeRole(supportRole, region)
	if err != nil {
		return nil, fmt.Errorf("3 failed to assume into jump-role: %w", err)
	}
	customerRole, err := ocmClient.GetSupportRoleARN(internalID)
	if err != nil {
		return nil, fmt.Errorf("4 failed to get support Role: %w", err)
	}

	customerClient, err := jumpRoleClient.AssumeRole(customerRole, region)
	if err != nil {
		return nil, fmt.Errorf("5 failed to assume into support-role: %w", err)
	}

	logging.Infof("Successfully logged into customer account with role: %s", customerRole)

	return customerClient, nil
}

// JumpRoles will return an aws client or an error after trying to jump into support role
func JumpRoles(cluster *v1.Cluster, baseAwsClient aws.Client, ocmClient ocm.Client) (*aws.SdkClient, error) {
	cssJumprole, ok := os.LookupEnv("CAD_AWS_CSS_JUMPROLE")
	if !ok {
		return nil, fmt.Errorf("CAD_AWS_CSS_JUMPROLE is missing")
	}

	supportRole, ok := os.LookupEnv("CAD_AWS_SUPPORT_JUMPROLE")
	if !ok {
		return nil, fmt.Errorf("CAD_AWS_SUPPORT_JUMPROLE is missing")
	}

	return assumeSupportRoleChain(baseAwsClient, ocmClient, cluster, cssJumprole, supportRole)
}

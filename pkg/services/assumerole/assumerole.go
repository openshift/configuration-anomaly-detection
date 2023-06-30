// Package assumerole contains functions needed to assumeRole jump into an aws account
package assumerole

import (
	"fmt"

	"github.com/openshift/configuration-anomaly-detection/pkg/aws"
	"github.com/openshift/configuration-anomaly-detection/pkg/ocm"
	"github.com/openshift/configuration-anomaly-detection/pkg/services/logging"

	v1 "github.com/openshift-online/ocm-sdk-go/clustersmgmt/v1"
)

// AssumeSupportRoleChain will jump between the current aws.Client to the customers aws.Client
func AssumeSupportRoleChain(baseClient aws.Client, ocmClient ocm.Client, cluster *v1.Cluster, ccsJumpRole string, supportRole string) (*aws.SdkClient, error) {
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

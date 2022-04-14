package assumerole

import (
	"fmt"

	"github.com/openshift/configuration-anomaly-detection/pkg/aws"
	"github.com/openshift/configuration-anomaly-detection/pkg/ocm"

	v1 "github.com/openshift-online/ocm-sdk-go/clustersmgmt/v1"
)

// these type aliases are here to make the types unique and unambiguus when using inside the struct

// AwsClient is a wrapper around the aws client, and is used to import the received functions into the Provider
type AwsClient = aws.Client

// OcmClient is a wrapper around the aws client, and is used to import the received functions into the Provider
type OcmClient = ocm.Client

// Provider should have all of the functions that ChgmService is implementing
type Provider struct {
	// having awsClient and ocmClient this way
	// allows for all of the method receivers defined on them to be passed into the parent struct,
	// thus making it more composable than just having each func redefined here
	//
	// a different solution is to have the structs have unique names to begin with, which makes the code
	// aws.AwsClient feel a bit redundant
	AwsClient
	OcmClient
}

// This will generate mocks for the interfaces in this file
//go:generate mockgen --build_flags=--mod=readonly -source $GOFILE -destination ./mock/interfaces.go -package mock

// Service will wrap all the required commands the client needs to run it's operations
type Service interface {
	// AWS
	AssumeRole(roleARN, region string) (aws.Client, error)

	// OCM
	GetClusterInfo(identifier string) (*v1.Cluster, error)
	GetSupportRoleARN(clusterID string) (string, error)
}

// Client is an implementation of the Interface, and adds functionality above it
// to create 'Client' you can use a mock, or fill it with
// this differs from the ChgmProvider as it makes sure you are intentional when using functions.
// if I am missing a func I will copy it from the corresponding package to the interface instead of
// having a function change break my code.
// TODO: decide if the Client should be the ChgmProvider
type Client struct {
	Service
}

// AssumeSupportRoleChain will jump between the current aws.Client to the customers aws.Client
func (c Client) AssumeSupportRoleChain(identifier, ccsJumpRole, supportRole string) (aws.Client, error) {
	cluster, err := c.GetClusterInfo(identifier)
	if err != nil {
		return aws.Client{}, fmt.Errorf("1 failed to get the cluster details :%w", err)
	}
	region := cluster.Region().Name()
	internalID := cluster.ID()

	tempClient, err := c.AssumeRole(ccsJumpRole, region)
	if err != nil {
		return aws.Client{}, fmt.Errorf("2 failed to assume into jump-role: %w", err)
	}

	jumpRoleClient, err := tempClient.AssumeRole(supportRole, region)
	if err != nil {
		return aws.Client{}, fmt.Errorf("3 failed to assume into jump-role: %w", err)
	}
	customerRole, err := c.GetSupportRoleARN(internalID)
	if err != nil {
		return aws.Client{}, fmt.Errorf("4 failed to get support Role: %w", err)
	}

	customerClient, err := jumpRoleClient.AssumeRole(customerRole, region)
	if err != nil {
		return aws.Client{}, fmt.Errorf("5 failed to assume into support-role: %w", err)
	}

	fmt.Printf("Successfully logged into customer account with role: %s\n", customerRole)

	return customerClient, nil
}

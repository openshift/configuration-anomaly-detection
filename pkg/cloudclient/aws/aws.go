package aws

import (
	"fmt"
	"io/ioutil"
	"path"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/sts"

	"github.com/golang/glog"
	awsv1alpha1 "github.com/openshift/aws-account-operator/pkg/apis/aws/v1alpha1"
	awsclient "github.com/openshift/configuration-anomaly-detection/pkg/cloudclient/aws/client"
	ccerrors "github.com/openshift/configuration-anomaly-detection/pkg/cloudclient/errors"
	"github.com/openshift/configuration-anomaly-detection/pkg/ocm"
	hivev1 "github.com/openshift/hive/apis/hive/v1"
	"github.com/pkg/errors"
)

const (
	jumpRole      = "ba"
	defaultRegion = "us-east-1" // TODO extract to own config
	credentialDir = "~/.aws"    // TODO extract to own config
)

const (
	// the ClusterDeployment label key we're expecting to be able to pull the ClusterID from
	cdClusterIDLabelKey string = "api.openshift.com/id"
)

// CloudClient is the client used for handling AWS Cloud Handler requests
type CloudClient struct {
	// clusterDeployment is the ClusterDeployment for the target cluster (the one
	// for which a login url is requested)
	clusterDeployment *hivev1.ClusterDeployment

	// awsClient is the awsClient that has the BACKPLANE user credentials.  This client
	// is used to create other clients in order to perform the necessary role chaining to
	// access a customer's account via STS assume roles.
	awsClient awsclient.AwsClient

	// ocmClient is a client that can query OCM in order to get the AccountClaim
	ocmClient ocm.Client

	// awsClientBuilder is responsible for building the aws client in order to
	// allow mocking during testing
	awsClientBuilder awsclient.BuilderIface

	// region is the region in which we are building sts clients
	region string
}

// NewCloudClient makes a new AWS CloudClient based on the ClusterDeployment and
// handles initial configuration building for a single request.
func NewCloudClient(cloudConfig *interface{}, ocmClient ocm.Client, cd *hivev1.ClusterDeployment) (*CloudClient, error) {
	region := defaultRegion
	if cd.Spec.Platform.AWS != nil {
		// overwrite default region if it's set
		glog.V(8).Infof("Overwriting default region with %s", cd.Spec.Platform.AWS.Region)
		region = cd.Spec.Platform.AWS.Region
	}

	accessKeyID, secretAccessKey, err := getAWSCredentialsFromDirectory(credentialDir)
	if err != nil {
		glog.Errorf("Couldn't obtain credentials from secret. Error: %s", err.Error())
		return nil, &ccerrors.InternalError{Err: err}
	}

	awsClient, err := singletonClient.getAwsClientBuilder().New(accessKeyID, secretAccessKey, "", region)
	if err != nil {
		glog.Errorf("Couldn't create AWS cloud client: %s", err.Error())
		return nil, &ccerrors.UpstreamError{Err: err}
	}

	return &CloudClient{
		clusterDeployment: cd,
		awsClient:         awsClient,
		ocmClient:         ocmClient,
		region:            region,
	}, nil
}

// The singleton client defined here is used to build the initial cloud client for a request.
// the biggest use for this client is to be able to inject the awsclient builder during unit testing
var singletonClient = &CloudClient{}

func (c *CloudClient) getAwsClientBuilder() awsclient.BuilderIface {
	if c.awsClientBuilder != nil {
		return c.awsClientBuilder
	}
	return &awsclient.Builder{}
}

func getAWSCredentialsFromDirectory(dir string) (string, string, error) {
	accessKeyIDFilename := "aws_access_key_id"
	secretAccessKeyIDFilename := "aws_secret_access_key"

	// ensure that the directory has no trailing slash
	filepath := strings.TrimSuffix(dir, "/")

	accessKeyBytes, err := ioutil.ReadFile(path.Join(filepath, accessKeyIDFilename))
	if err != nil {
		glog.Error(err)
		return "", "", fmt.Errorf("%s cannot be read from %s", accessKeyIDFilename, filepath)
	}
	secretKeyBytes, err := ioutil.ReadFile(path.Join(filepath, secretAccessKeyIDFilename))
	if err != nil {
		glog.Error(err)
		return "", "", fmt.Errorf("%s cannot be read from %s", secretAccessKeyIDFilename, filepath)
	}
	accessKeyID := strings.TrimRight(string(accessKeyBytes), "\n")
	secretKeyID := strings.TrimRight(string(secretKeyBytes), "\n")
	return accessKeyID, secretKeyID, nil
}

// extracts a cluster ID from a given clusterdeployment
func extractClusterID(cd *hivev1.ClusterDeployment) (string, error) {
	clusterID := cd.ObjectMeta.Labels[cdClusterIDLabelKey]
	if clusterID == "" {
		return "", &ccerrors.ValidationError{Err: fmt.Errorf("Unable to parse ClusterID from ClusterDeployment, label missing or malformed")}

	}
	return clusterID, nil
}

// abstracted functionality in order to do the assume-role chaining in order to assume the support role
// credentials in a given customer cluster. This function will get the accountclaim, assume the jump role,
// and then from that assumed role make another assume_role call into the customer's account
func (c *CloudClient) AssumeSupportRole() (*sts.Credentials, error) {

	clusterID, err := extractClusterID(c.clusterDeployment)
	if err != nil {
		glog.Errorf("Could not extract ClusterID from ClusterDeployment: %s", err.Error())
		return nil, err
	}

	glog.V(0).Infof("Getting AccountClaim for %s", clusterID)
	ac, err := c.ocmClient.GetAWSAccountClaim(clusterID)
	glog.V(0).Infof("Received %+v", ac)
	if err != nil || ac == nil {
		return nil, &ccerrors.UpstreamError{Err: fmt.Errorf("could not obtain an accountclaim from OCM")}
	}

	glog.V(0).Info("Validating AccountClaim")
	err = c.validateAccountClaim(ac)
	if err != nil {
		return nil, &ccerrors.ValidationError{Err: err}
	}
	glog.V(0).Info("AccountClaim Validated")

	jumpRole := jumpRole
	glog.V(0).Infof("Obtained Jump Role ARN %s from configmap", jumpRole)

	sessionName := fmt.Sprintf("cad-check")
	glog.Info("Building aws session for ", sessionName)

	glog.V(0).Info("Assuming role into the jump role ", jumpRole)
	// We don't need to limit the scope of the jump role, as the only permission the Jump role should
	// have is AssumeRole, so we pass in `nil` as the role here.
	jrCreds, err := c.getAssumedRoleCredentials(c.awsClient, jumpRole, sessionName)
	if err != nil {
		return nil, &ccerrors.UpstreamError{Err: err}
	}
	if jrCreds == nil {
		return nil, &ccerrors.UpstreamError{
			Err: fmt.Errorf("Jump Role Assume returned empty credentials"),
		}
	}
	jumpRoleClient, err := c.getAwsClientBuilder().New(*jrCreds.AccessKeyId, *jrCreds.SecretAccessKey, *jrCreds.SessionToken, c.region)
	if err != nil {
		return nil, &ccerrors.UpstreamError{
			Err: fmt.Errorf("Could not build new jump role client with assumed creds: %s", err.Error()),
		}
	}

	glog.V(0).Info("Assuming Support Role ", ac.Spec.SupportRoleARN)
	cuCreds, err := c.getAssumedRoleCredentials(jumpRoleClient, ac.Spec.SupportRoleARN, sessionName)
	if err != nil {
		return nil, &ccerrors.RequestError{
			Err: fmt.Errorf("Could not assume support role in customer's account: %s", err.Error()),
		}
	}
	return cuCreds, nil
}

func (c *CloudClient) validateAccountClaim(ac *awsv1alpha1.AccountClaim) error {
	supportRoleArn := ac.Spec.SupportRoleARN
	if supportRoleArn == "" {
		// if the supportRoleARN is not set, then we won't know which role inside of the customer
		// AWS account to assume into. This is defined by the customer for STS clusters, and defined
		// by the aws-account-operator on CCS and OSD accounts
		return errors.Wrap(fmt.Errorf("AccountClaim is invalid"), "supportRoleARN is not present in the AccountClaim")
	}
	return nil
}

// getAssumeRoleCredentials uses the given client to assume a given Role
func (c *CloudClient) getAssumedRoleCredentials(client awsclient.AwsClient, roleARN string, sessionName string) (*sts.Credentials, error) {
	input := &sts.AssumeRoleInput{
		RoleArn:         aws.String(roleARN),
		RoleSessionName: aws.String(sessionName),
	}

	glog.V(8).Infof("Assume Role Input: %+v", *input)

	result, err := client.AssumeRole(input)
	if err != nil {
		return &sts.Credentials{}, err
	}
	return result.Credentials, nil
}

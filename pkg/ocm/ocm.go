// Package ocm contains ocm api related functions
package ocm

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"

	_ "github.com/golang/mock/mockgen/model" //revive:disable:blank-imports used for the mockgen generation
	sdk "github.com/openshift-online/ocm-sdk-go"

	v1 "github.com/openshift-online/ocm-sdk-go/clustersmgmt/v1"
	awsv1alpha1 "github.com/openshift/aws-account-operator/pkg/apis/aws/v1alpha1"
	hivev1 "github.com/openshift/hive/apis/hive/v1"
)

// LimitedSupportReason is the internal representation of a limited support reason
type LimitedSupportReason struct {
	Details string
	Summary string
}

// Client is the ocm client with which we can run the commands
// currently we do not need to export the connection or the config, as we create the Client using the New func
type Client struct {
	conn *sdk.Connection
}

// New will create a new ocm client by using the path to a config file
// if no path is provided, it will assume it in the default path
func New(ocmConfigFile string) (Client, error) {
	var err error
	client := Client{}

	// The debug environment variable ensures that we will never use
	// an ocm config file on a cluster deployment. The debug environment variable
	// is only for local cadctl development
	debugMode := os.Getenv("CAD_DEBUG")

	// strconv.ParseBool raises an error when debugMode is empty, thus
	// we have to set it to false if the value is empty.
	if debugMode == "" {
		debugMode = "false"
	}

	debugEnabled, err := strconv.ParseBool(debugMode)
	if err != nil {
		return client, fmt.Errorf("failed to parse CAD_DEBUG value '%s': %w", debugMode, err)
	}

	if debugEnabled {
		client.conn, err = newConnectionFromFile(ocmConfigFile)
		if err != nil {
			return client, fmt.Errorf("failed to create connection from ocm.json config file: %w", err)
		}
		return client, nil
	}

	client.conn, err = newConnectionFromClientPair()
	if err != nil {
		return client, fmt.Errorf("failed to create connection from client key pair: %w", err)
	}

	return client, nil
}

// newConnectionFromFile loads the configuration file (ocmConfigFile, ~/.ocm.json, /ocm/ocm.json)
// and creates a connection.
func newConnectionFromFile(ocmConfigFile string) (*sdk.Connection, error) {
	if ocmConfigFile != "" {
		err := os.Setenv("OCM_CONFIG", ocmConfigFile)
		if err != nil {
			return nil, err
		}
	}
	// Load the configuration file from std path
	cfg, err := Load()
	if err != nil {
		return nil, err
	}
	if cfg == nil || cfg == (&Config{}) {
		return nil, fmt.Errorf("not logged in")
	}
	return cfg.Connection()
}

// newConnectionFromClientPair creates a new connection via set of client ID, client secret
// and the target OCM API URL.
func newConnectionFromClientPair() (*sdk.Connection, error) {
	ocmClientID, hasOcmClientID := os.LookupEnv("CAD_OCM_CLIENT_ID")
	ocmClientSecret, hasOcmClientSecret := os.LookupEnv("CAD_OCM_CLIENT_SECRET")
	ocmURL, hasOcmURL := os.LookupEnv("CAD_OCM_URL")
	if !hasOcmClientID || !hasOcmClientSecret || !hasOcmURL {
		return nil, fmt.Errorf("missing environment variables: CAD_OCM_CLIENT_ID CAD_OCM_CLIENT_SECRET CAD_OCM_URL")
	}
	return sdk.NewConnectionBuilder().URL(ocmURL).Client(ocmClientID, ocmClientSecret).Insecure(false).Build()
}

// GetSupportRoleARN returns the support role ARN that allows the access to the cluster from internal cluster ID
func (c Client) GetSupportRoleARN(clusterID string) (string, error) {
	claim, err := c.GetAWSAccountClaim(clusterID)
	if err != nil {
		return "", fmt.Errorf("failed to get account claim: %w", err)
	}
	arn := claim.Spec.SupportRoleARN
	if arn == "" {
		// if the supportRoleARN is not set, then we won't know which role inside of the customer
		// AWS account to assume into. This is defined by the customer for STS clusters, and defined
		// by the aws-account-operator on CCS and OSD accounts
		return "", fmt.Errorf("AccountClaim is invalid: supportRoleARN is not present in the AccountClaim")
	}
	return arn, nil
}

// GetAWSAccountClaim gets the AWS Account Claim object for a given cluster
func (c Client) GetAWSAccountClaim(clusterID string) (*awsv1alpha1.AccountClaim, error) {
	ac := &awsv1alpha1.AccountClaim{}
	acString, err := c.getClusterResource(clusterID, "aws_account_claim")
	if err != nil {
		return ac, fmt.Errorf("client failed to load AWS AccountClaim: %w", err)
	}
	err = json.Unmarshal([]byte(acString), ac)
	if err != nil {
		return ac, fmt.Errorf("failed to unmarshal client response (%s) with error: %w", acString, err)
	}
	return ac, err
}

// GetClusterInfo returns cluster information from ocm by using either internal, external id or the cluster name
// Returns a v1.Cluster object or an error
func (c Client) GetClusterInfo(identifier string) (*v1.Cluster, error) {
	q := fmt.Sprintf("(id like '%[1]s' or external_id like '%[1]s' or display_name like '%[1]s')", identifier)
	resp, err := c.conn.ClustersMgmt().V1().Clusters().List().Search(q).Send()
	if err != nil || resp.Error() != nil || resp.Status() != http.StatusOK {
		return nil, fmt.Errorf("received error while fetch ClusterInfo from ocm: %w with resp %#v", err, resp)
	}
	if resp.Total() > 1 {
		return nil, fmt.Errorf("the provided cluster identifier is ambiguous: %s", identifier)
	}
	if resp.Total() == 0 {
		return nil, fmt.Errorf("no cluster found for %s", identifier)
	}

	return resp.Items().Get(0), nil
}

// GetClusterDeployment gets the ClusterDeployment object for a given cluster
func (c Client) GetClusterDeployment(clusterID string) (*hivev1.ClusterDeployment, error) {
	cd := &hivev1.ClusterDeployment{}
	cdString, err := c.getClusterResource(clusterID, "cluster_deployment")
	if err != nil {
		return cd, fmt.Errorf("client failed to load ClusterDeployment: %w", err)
	}
	err = json.Unmarshal([]byte(cdString), cd)
	if err != nil {
		return cd, fmt.Errorf("failed to unmarshal client response (%s) with error: %w", cdString, err)
	}
	return cd, nil
}

// GetClusterMachinePools get the machine pools for a given cluster
func (c Client) GetClusterMachinePools(clusterID string) ([]*v1.MachinePool, error) {
	response, err := c.conn.ClustersMgmt().V1().Clusters().Cluster(clusterID).MachinePools().List().Page(1).Size(-1).Send()
	if err != nil {
		return nil, err
	}
	return response.Items().Slice(), nil
}

// getClusterResource allows to load different cluster resources
func (c Client) getClusterResource(clusterID string, resourceKey string) (string, error) {
	response, err := c.conn.ClustersMgmt().V1().Clusters().Cluster(clusterID).Resources().Live().Get().Send()
	if err != nil {
		return "", err
	}
	return response.Body().Resources()[resourceKey], nil
}

// GetCloudProviderID returns the cloud provider name for a given cluster as a string
func (c Client) GetCloudProviderID(identifier string) (string, error) {
	cluster, err := c.GetClusterInfo(identifier)
	if err != nil {
		return "", fmt.Errorf("GetClusterInfo failed on: %w", err)
	}

	cloudProvider, ok := cluster.GetCloudProvider()
	if !ok {
		return "", fmt.Errorf("could not get clusters cloudProvider")
	}
	cloudProviderID, ok := cloudProvider.GetID()
	if !ok {
		return "", fmt.Errorf("could not get cloudProvider id")
	}
	return cloudProviderID, nil
}

// PostLimitedSupportReason allows to post a generic limited support reason to a cluster
func (c Client) PostLimitedSupportReason(limitedSupportReason LimitedSupportReason, clusterID string) error {
	fmt.Printf("Sending limited support reason: %s\n", limitedSupportReason.Summary)

	ls, err := c.newLimitedSupportReasonBuilder(limitedSupportReason).Build()
	if err != nil {
		return fmt.Errorf("could not create post request: %w", err)
	}

	request := c.conn.ClustersMgmt().V1().Clusters().Cluster(clusterID).LimitedSupportReasons().Add()
	request = request.Body(ls)
	resp, err := request.Send()
	if err != nil {
		return fmt.Errorf("received error from ocm: %w. Full Response: %#v", err, resp)
	}

	return nil
}

// newLimitedSupportReasonBuilder creates a Limited Support reason
func (c Client) newLimitedSupportReasonBuilder(ls LimitedSupportReason) *v1.LimitedSupportReasonBuilder {
	builder := v1.NewLimitedSupportReason()
	builder.Summary(ls.Summary)
	builder.Details(ls.Details)
	builder.DetectionType(v1.DetectionTypeManual)
	return builder
}

// LimitedSupportExists takes a LimitedSupportReason and matches the Summary against
// a clusters limited support reasons
// Returns true if any match is found
func (c Client) LimitedSupportExists(ls LimitedSupportReason, clusterID string) (bool, error) {
	reasons, err := c.listLimitedSupportReasons(clusterID)
	if err != nil {
		return false, fmt.Errorf("could not list existing limited support reasons: %w", err)
	}
	for _, reason := range reasons {
		if c.reasonsMatch(ls, reason) {
			return true, nil
		}
	}
	return false, nil
}

// DeleteLimitedSupportReasons removes *all* limited support reasons for a cluster which match the given summary
func (c Client) DeleteLimitedSupportReasons(ls LimitedSupportReason, clusterID string) error {
	reasons, err := c.listLimitedSupportReasons(clusterID)
	if err != nil {
		return fmt.Errorf("could not list current limited support reasons: %w", err)
	}

	// Remove each limited support reason matching the given template
	removedReasons := false
	for _, reason := range reasons {
		if c.reasonsMatch(ls, reason) {
			reasonID, ok := reason.GetID()
			if !ok {
				return fmt.Errorf("one of the cluster's limited support reasons does not contain an ID. Limited Support Reason: %#v", reason)
			}
			response, err := c.conn.ClustersMgmt().V1().Clusters().Cluster(clusterID).LimitedSupportReasons().LimitedSupportReason(reasonID).Delete().Send()
			if err != nil {
				return fmt.Errorf("received error while deleting limited support reason '%s': %w. Full response: %#v", reasonID, err, response)
			}
			removedReasons = true
		}
	}
	if removedReasons {
		fmt.Printf("Removed limited support reason `%s`\n", ls.Summary)
	} else {
		fmt.Printf("Found no limited support reason to remove for `%s`\n", ls.Summary)
	}
	return nil
}

// IsInLimitedSupport indicates whether any LS reasons exist on a given cluster
func (c Client) IsInLimitedSupport(clusterID string) (bool, error) {
	reasons, err := c.listLimitedSupportReasons(clusterID)
	if err != nil {
		return false, fmt.Errorf("failed to list existing limited support reasons: %w", err)
	}
	if len(reasons) == 0 {
		return false, nil
	}
	return true, nil
}

// UnrelatedLimitedSupportExists takes a cluster id and limited support reason
// Returns true if any other limited support reason than the given one exists on the cluster
func (c Client) UnrelatedLimitedSupportExists(ls LimitedSupportReason, clusterID string) (bool, error) {
	reasons, err := c.listLimitedSupportReasons(clusterID)
	if err != nil {
		return false, fmt.Errorf("UnrelatedLimitedSupportExists: failed to list current limited support reasons: %w", err)
	}
	if len(reasons) == 0 {
		return false, nil
	}

	for _, reason := range reasons {
		if !c.reasonsMatch(ls, reason) {
			fmt.Printf("UnrelatedLimitedSupportExists: cluster is in limited support for unrelated reason: %s\n", reason.Summary())
			return true, nil
		}
	}
	return false, nil
}

// LimitedSupportReasonExists takes a cluster id and limited support reason
// Returns true if the limited support reason exists on the cluster
func (c Client) LimitedSupportReasonExists(ls LimitedSupportReason, clusterID string) (bool, error) {
	reasons, err := c.listLimitedSupportReasons(clusterID)
	if err != nil {
		return false, fmt.Errorf("LimitedSupportReasonExists: failed to list current limited support reasons: %w", err)
	}
	if len(reasons) == 0 {
		return false, nil
	}

	for _, reason := range reasons {
		if c.reasonsMatch(ls, reason) {
			fmt.Printf("LimitedSupportReasonExists: cluster is in limited support for reason: %s\n", reason.Summary())
			return true, nil
		}
	}
	return false, nil
}

func (c Client) reasonsMatch(template LimitedSupportReason, reason *v1.LimitedSupportReason) bool {
	return reason.Summary() == template.Summary && reason.Details() == template.Details
}

// listLimitedSupportReasons returns all limited support reasons attached to the given cluster
func (c Client) listLimitedSupportReasons(clusterID string) ([]*v1.LimitedSupportReason, error) {
	// Only the internal cluster ID can be used to retrieve LS reasons currently attached to a cluster
	cluster, err := c.GetClusterInfo(clusterID)
	if err != nil {
		return []*v1.LimitedSupportReason{}, fmt.Errorf("failed to retrieve cluster info from OCM: %w", err)
	}

	// List reasons
	clusterLimitedSupport := c.conn.ClustersMgmt().V1().Clusters().Cluster(cluster.ID()).LimitedSupportReasons()
	reasons, err := clusterLimitedSupport.List().Send()
	if err != nil {
		return []*v1.LimitedSupportReason{}, fmt.Errorf("received error from ocm: %w. Full Response: %#v", err, reasons)
	}
	return reasons.Items().Slice(), nil
}

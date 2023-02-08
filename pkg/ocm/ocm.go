// Package ocm contains ocm related functionality
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

type limitedSupportReasonTemplate struct {
	Details string
	Summary string
}

// NOTE: USE CAUTION WHEN CHANGING THESE TEMPLATES!!
// Changing the templates' summaries will likely prevent CAD from removing clusters with these Limited Support reasons in the future, since it identifies which reasons to delete via their summaries.
// If the summaries *must* be modified, it's imperative that existing clusters w/ these LS reasons have the new summary applied to them (currently, the only way to do this is to delete the current
// reason & apply the new one). Failure to do so will result in orphan clusters that are not managed by CAD.
var chgmLimitedSupport = limitedSupportReasonTemplate{
	Summary: "Cluster not checking in",
	Details: "Your cluster is no longer checking in with Red Hat OpenShift Cluster Manager. Possible causes include stopped instances or a networking misconfiguration. If you have stopped the cluster instances, please start them again - stopping instances is not supported. If you intended to terminate this cluster then please delete the cluster in the Red Hat console",
}

var ccamLimitedSupport = limitedSupportReasonTemplate{
	Summary: "Restore missing cloud credentials",
	Details: "Your cluster requires you to take action because Red Hat is not able to access the infrastructure with the provided credentials. Please restore the credentials and permissions provided during install",
}

// CAUTION!!

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

// PostCHGMLimitedSupportReason will post a CCAM limited support reason for a cluster
// On success, it returns true
func (c Client) PostCHGMLimitedSupportReason(clusterID string) (*v1.LimitedSupportReason, error) {
	return c.postLimitedSupportReason(c.newLimitedSupportReasonBuilder(chgmLimitedSupport), clusterID)
}

// PostCCAMLimitedSupportReason will post a CCAM limited support reason for a cluster
// On success, it returns true
func (c Client) PostCCAMLimitedSupportReason(clusterID string) (*v1.LimitedSupportReason, error) {
	return c.postLimitedSupportReason(c.newLimitedSupportReasonBuilder(ccamLimitedSupport), clusterID)
}

// postLimitedSupportReason allows to post a generic limited support reason to a cluster
// On success, returns sent limited support reason
func (c Client) postLimitedSupportReason(builder *v1.LimitedSupportReasonBuilder, clusterID string) (*v1.LimitedSupportReason, error) {
	ls, err := builder.Build()
	if err != nil {
		return nil, fmt.Errorf("could not create post request: %w", err)
	}

	request := c.conn.ClustersMgmt().V1().Clusters().Cluster(clusterID).LimitedSupportReasons().Add()
	request = request.Body(ls)
	resp, err := request.Send()
	if err != nil {
		return nil, fmt.Errorf("received error from ocm: %w. Full Response: %#v", err, resp)
	}
	return ls, nil
}

// newLimitedSupportReasonBuilder creates a Limited Support reason
func (c Client) newLimitedSupportReasonBuilder(ls limitedSupportReasonTemplate) *v1.LimitedSupportReasonBuilder {
	builder := v1.NewLimitedSupportReason()
	builder.Summary(ls.Summary)
	builder.Details(ls.Details)
	builder.DetectionType(v1.DetectionTypeManual)
	return builder
}

// CCAMLimitedSupportExists indicates whether CAD has posted a CCAM LS reason to the given cluster already
func (c Client) CCAMLimitedSupportExists(clusterID string) (bool, error) {
	return c.limitedSupportExists(ccamLimitedSupport, clusterID)
}

// CHGMLimitedSupportExists indicates whether CAD has posted a CHGM LS reason to the given cluster already
func (c Client) CHGMLimitedSupportExists(clusterID string) (bool, error) {
	return c.limitedSupportExists(chgmLimitedSupport, clusterID)
}

// limitedSupportExists returns true if the provided limitedSupportReasonTemplate's summary and details fields match an existing
// reason on the given cluster
func (c Client) limitedSupportExists(ls limitedSupportReasonTemplate, clusterID string) (bool, error) {
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

// DeleteCCAMLimitedSupportReason removes the CCAM-specific limited support reasons from a cluster, returning true if any reasons were removed
func (c Client) DeleteCCAMLimitedSupportReason(clusterID string) (bool, error) {
	return c.deleteLimitedSupportReasons(ccamLimitedSupport.Summary, clusterID)
}

// DeleteCHGMLimitedSupportReason removes the CHGM-specific limited support reasons from a cluster, returning true if any reasons were removed
func (c Client) DeleteCHGMLimitedSupportReason(clusterID string) (bool, error) {
	return c.deleteLimitedSupportReasons(chgmLimitedSupport.Summary, clusterID)
}

// deleteLimitedSupportReasons removes *all* limited support reasons for a cluster which match the given summary
func (c Client) deleteLimitedSupportReasons(summaryToDelete, clusterID string) (bool, error) {
	reasons, err := c.listLimitedSupportReasons(clusterID)
	if err != nil {
		return false, fmt.Errorf("could not list current limited support reasons: %w", err)
	}

	// Remove each limited support reason matching the given template
	removedReasons := false
	for _, reason := range reasons {
		if reason.Summary() == summaryToDelete {
			reasonID, ok := reason.GetID()
			if !ok {
				return false, fmt.Errorf("one of the cluster's limited support reasons does not contain an ID. Limited Support Reason: %#v", reason)
			}
			response, err := c.conn.ClustersMgmt().V1().Clusters().Cluster(clusterID).LimitedSupportReasons().LimitedSupportReason(reasonID).Delete().Send()
			if err != nil {
				return false, fmt.Errorf("received error while deleting limited support reason '%s': %w. Full response: %#v", reasonID, err, response)
			}
			removedReasons = true
		}
	}
	return removedReasons, nil
}

// LimitedSupportReasonsExist indicates whether any LS reasons exist on a given cluster
func (c Client) LimitedSupportReasonsExist(clusterID string) (bool, error) {
	reasons, err := c.listLimitedSupportReasons(clusterID)
	if err != nil {
		return false, fmt.Errorf("failed to list existing limited support reasons: %w", err)
	}
	if len(reasons) == 0 {
		return false, nil
	}
	return true, nil
}

// NonCADLimitedSupportExists returns true if the given cluster has a limited support reason that doesn't appear to be one of CAD's
func (c Client) NonCADLimitedSupportExists(clusterID string) (bool, error) {
	reasons, err := c.listLimitedSupportReasons(clusterID)
	if err != nil {
		return false, fmt.Errorf("failed to list current limited support reasons: %w", err)
	}
	if len(reasons) == 0 {
		return false, nil
	}

	for _, reason := range reasons {
		if !c.reasonsMatch(ccamLimitedSupport, reason) && !c.reasonsMatch(chgmLimitedSupport, reason) {
			// Reason differs from CAD's reasons - cluster is in LS for something else
			return true, nil
		}
	}
	return false, nil
}

func (c Client) reasonsMatch(template limitedSupportReasonTemplate, reason *v1.LimitedSupportReason) bool {
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

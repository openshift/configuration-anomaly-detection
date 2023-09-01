// Package ocm contains ocm api related functions
package ocm

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	_ "github.com/golang/mock/mockgen/model" //revive:disable:blank-imports used for the mockgen generation
	sdk "github.com/openshift-online/ocm-sdk-go"

	v1 "github.com/openshift-online/ocm-sdk-go/clustersmgmt/v1"
	servicelogsv1 "github.com/openshift-online/ocm-sdk-go/servicelogs/v1"
	awsv1alpha1 "github.com/openshift/aws-account-operator/pkg/apis/aws/v1alpha1"
	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
	hivev1 "github.com/openshift/hive/apis/hive/v1"
)

//go:generate mockgen --build_flags=--mod=readonly -source $GOFILE -destination ./mock/ocmmock.go -package ocmmock

// LimitedSupportReason is the internal representation of a limited support reason
type LimitedSupportReason struct {
	Details string
	Summary string
}

// Client is the interface exposing OCM related functions
type Client interface {
	GetClusterMachinePools(internalClusterID string) ([]*v1.MachinePool, error)
	PostLimitedSupportReason(limitedSupportReason LimitedSupportReason, internalClusterID string) error
	IsInLimitedSupport(internalClusterID string) (bool, error)
	UnrelatedLimitedSupportExists(ls LimitedSupportReason, internalClusterID string) (bool, error)
	LimitedSupportReasonExists(ls LimitedSupportReason, internalClusterID string) (bool, error)
	DeleteLimitedSupportReasons(ls LimitedSupportReason, internalClusterID string) (bool, error)
	GetSupportRoleARN(internalClusterID string) (string, error)
}

// SdkClient is the ocm client with which we can run the commands
// currently we do not need to export the connection or the config, as we create the SdkClient using the New func
type SdkClient struct {
	conn *sdk.Connection
}

// New will create a new ocm client by using the path to a config file
// if no path is provided, it will assume it in the default path
func New(ocmConfigFile string) (*SdkClient, error) {
	var err error
	client := SdkClient{}

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
		return nil, fmt.Errorf("failed to parse CAD_DEBUG value '%s': %w", debugMode, err)
	}

	if debugEnabled {
		client.conn, err = newConnectionFromFile(ocmConfigFile)
		if err != nil {
			return nil, fmt.Errorf("failed to create connection from ocm.json config file: %w", err)
		}
		return &client, nil
	}

	client.conn, err = newConnectionFromClientPair()
	if err != nil {
		return nil, fmt.Errorf("failed to create connection from client key pair: %w", err)
	}

	return &client, nil
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
func (c *SdkClient) GetSupportRoleARN(internalClusterID string) (string, error) {
	claim, err := c.GetAWSAccountClaim(internalClusterID)
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
func (c *SdkClient) GetAWSAccountClaim(internalClusterID string) (*awsv1alpha1.AccountClaim, error) {
	ac := &awsv1alpha1.AccountClaim{}
	acString, err := c.getClusterResource(internalClusterID, "aws_account_claim")
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
func (c *SdkClient) GetClusterInfo(identifier string) (*v1.Cluster, error) {
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
func (c *SdkClient) GetClusterDeployment(internalClusterID string) (*hivev1.ClusterDeployment, error) {
	cd := &hivev1.ClusterDeployment{}
	cdString, err := c.getClusterResource(internalClusterID, "cluster_deployment")
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
func (c *SdkClient) GetClusterMachinePools(internalClusterID string) ([]*v1.MachinePool, error) {
	response, err := c.conn.ClustersMgmt().V1().Clusters().Cluster(internalClusterID).MachinePools().List().Page(1).Size(-1).Send()
	if err != nil {
		return nil, err
	}
	return response.Items().Slice(), nil
}

// getClusterResource allows to load different cluster resources
func (c *SdkClient) getClusterResource(internalClusterID string, resourceKey string) (string, error) {
	response, err := c.conn.ClustersMgmt().V1().Clusters().Cluster(internalClusterID).Resources().Live().Get().Send()
	if err != nil {
		return "", err
	}
	return response.Body().Resources()[resourceKey], nil
}

// PostLimitedSupportReason allows to post a generic limited support reason to a cluster
func (c *SdkClient) PostLimitedSupportReason(limitedSupportReason LimitedSupportReason, internalClusterID string) error {
	logging.Infof("Sending limited support reason: %s", limitedSupportReason.Summary)

	ls, err := newLimitedSupportReasonBuilder(limitedSupportReason).Build()
	if err != nil {
		return fmt.Errorf("could not create post request: %w", err)
	}

	request := c.conn.ClustersMgmt().V1().Clusters().Cluster(internalClusterID).LimitedSupportReasons().Add()
	request = request.Body(ls)
	resp, err := request.Send()
	if err != nil && !strings.Contains(err.Error(), "Operation is not allowed for a cluster in 'uninstalling' state") {
		return fmt.Errorf("received error from ocm: %w. Full Response: %#v", err, resp)
	}

	return nil
}

// newLimitedSupportReasonBuilder creates a Limited Support reason
func newLimitedSupportReasonBuilder(ls LimitedSupportReason) *v1.LimitedSupportReasonBuilder {
	builder := v1.NewLimitedSupportReason()
	builder.Summary(ls.Summary)
	builder.Details(ls.Details)
	builder.DetectionType(v1.DetectionTypeManual)
	return builder
}

// LimitedSupportExists takes a LimitedSupportReason and matches the Summary against
// a clusters limited support reasons
// Returns true if any match is found
func (c *SdkClient) LimitedSupportExists(ls LimitedSupportReason, internalClusterID string) (bool, error) {
	reasons, err := c.listLimitedSupportReasons(internalClusterID)
	if err != nil {
		return false, fmt.Errorf("could not list existing limited support reasons: %w", err)
	}
	for _, reason := range reasons {
		if reasonsMatch(ls, reason) {
			return true, nil
		}
	}
	return false, nil
}

// isLimitedSupportReasonFlapping checks if a cluster has been put in limited support too many times
// Returns true if the cluster has been put in limited support at least 2 times in the last 24 hours
func (c *SdkClient) isLimitedSupportReasonFlapping(ls LimitedSupportReason, internalClusterID string) (bool, error) {
	// Retrieve external ID
	info, err := c.GetClusterInfo(internalClusterID)
	if err != nil {
		return false, fmt.Errorf("could not retrieve cluster info: %w", err)
	}

	externalID := info.ExternalID()

	// Rerieve service logs
	resp, err := c.conn.ServiceLogs().V1().Clusters().Cluster(externalID).ClusterLogs().List().Send()
	if err != nil {
		return false, fmt.Errorf("could not list service logs history: %w", err)
	}

	serviceLogs, ok := resp.GetItems()
	if !ok {
		return false, nil
	}

	// Check if the cluster has been put in limited support at least 2 times in the last 24 hours
	fourHoursAgo := time.Now().Add(-24 * time.Hour)

	var filteredLogs []*servicelogsv1.LogEntry
	for _, log := range serviceLogs.Slice() {
		if log.ServiceName() == "LimitedSupport" &&
			log.Username() == "service-account-ocm-cad-production" &&
			log.Timestamp().After(fourHoursAgo) &&
			log.Summary() == ls.Summary {
			filteredLogs = append(filteredLogs, log)
		}
	}

	return len(filteredLogs) >= 2, nil
}

// DeleteLimitedSupportReasons removes *all* limited support reasons for a cluster which match the given summary
// Returns true if a limited support reason got removed
func (c *SdkClient) DeleteLimitedSupportReasons(ls LimitedSupportReason, internalClusterID string) (bool, error) {
	isFlapping, err := c.isLimitedSupportReasonFlapping(ls, internalClusterID)
	if err != nil {
		return false, err
	}

	if isFlapping {
		logging.Infof("Limited support reason is flapping `%s`", ls.Summary)
		return false, nil
	}

	reasons, err := c.listLimitedSupportReasons(internalClusterID)
	if err != nil {
		return false, fmt.Errorf("could not list current limited support reasons: %w", err)
	}

	// Remove each limited support reason matching the given template
	removedReasons := false
	for _, reason := range reasons {
		if reasonsMatch(ls, reason) {
			reasonID, ok := reason.GetID()
			if !ok {
				return false, fmt.Errorf("one of the cluster's limited support reasons does not contain an ID. Limited Support Reason: %#v", reason)
			}
			response, err := c.conn.ClustersMgmt().V1().Clusters().Cluster(internalClusterID).LimitedSupportReasons().LimitedSupportReason(reasonID).Delete().Send()
			if err != nil {
				return false, fmt.Errorf("received error while deleting limited support reason '%s': %w. Full response: %#v", reasonID, err, response)
			}
			removedReasons = true
		}
	}
	if removedReasons {
		logging.Infof("Removed limited support reason `%s`", ls.Summary)
		return true, nil
	}
	logging.Infof("Found no limited support reason to remove for `%s`", ls.Summary)
	return false, nil
}

// IsInLimitedSupport indicates whether any LS reasons exist on a given cluster
func (c *SdkClient) IsInLimitedSupport(internalClusterID string) (bool, error) {
	reasons, err := c.listLimitedSupportReasons(internalClusterID)
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
func (c *SdkClient) UnrelatedLimitedSupportExists(ls LimitedSupportReason, internalClusterID string) (bool, error) {
	reasons, err := c.listLimitedSupportReasons(internalClusterID)
	if err != nil {
		return false, fmt.Errorf("UnrelatedLimitedSupportExists: failed to list current limited support reasons: %w", err)
	}
	if len(reasons) == 0 {
		return false, nil
	}

	for _, reason := range reasons {
		if !reasonsMatch(ls, reason) {
			logging.Infof("UnrelatedLimitedSupportExists: cluster is in limited support for unrelated reason: %s", reason.Summary())
			return true, nil
		}
	}
	return false, nil
}

// LimitedSupportReasonExists takes a cluster id and limited support reason
// Returns true if the limited support reason exists on the cluster
func (c *SdkClient) LimitedSupportReasonExists(ls LimitedSupportReason, internalClusterID string) (bool, error) {
	reasons, err := c.listLimitedSupportReasons(internalClusterID)
	if err != nil {
		return false, fmt.Errorf("LimitedSupportReasonExists: failed to list current limited support reasons: %w", err)
	}
	if len(reasons) == 0 {
		return false, nil
	}

	for _, reason := range reasons {
		if reasonsMatch(ls, reason) {
			logging.Infof("LimitedSupportReasonExists: cluster is in limited support for reason: %s", reason.Summary())
			return true, nil
		}
	}
	return false, nil
}

func reasonsMatch(template LimitedSupportReason, reason *v1.LimitedSupportReason) bool {
	return reason.Summary() == template.Summary && reason.Details() == template.Details
}

// listLimitedSupportReasons returns all limited support reasons attached to the given cluster
func (c *SdkClient) listLimitedSupportReasons(internalClusterID string) ([]*v1.LimitedSupportReason, error) {
	// List reasons
	clusterLimitedSupport := c.conn.ClustersMgmt().V1().Clusters().Cluster(internalClusterID).LimitedSupportReasons()
	reasons, err := clusterLimitedSupport.List().Send()
	if err != nil {
		return []*v1.LimitedSupportReason{}, fmt.Errorf("received error from ocm: %w. Full Response: %#v", err, reasons)
	}
	return reasons.Items().Slice(), nil
}
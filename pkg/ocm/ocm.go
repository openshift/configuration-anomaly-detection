// Package ocm contains ocm api related functions
package ocm

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"

	_ "github.com/golang/mock/mockgen/model" //revive:disable:blank-imports used for the mockgen generation
	sdk "github.com/openshift-online/ocm-sdk-go"

	cmv1 "github.com/openshift-online/ocm-sdk-go/clustersmgmt/v1"
	servicelogsv1 "github.com/openshift-online/ocm-sdk-go/servicelogs/v1"
	awsv1alpha1 "github.com/openshift/aws-account-operator/api/v1alpha1"
	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
	hivev1 "github.com/openshift/hive/apis/hive/v1"
)

//go:generate mockgen --build_flags=--mod=readonly -source $GOFILE -destination ./mock/ocmmock.go -package ocmmock

// LimitedSupportReason is the internal representation of a limited support reason
type LimitedSupportReason struct {
	Details string
	Summary string
}

// ServiceLog is the internal representation of a service log
type ServiceLog struct {
	Severity     string
	ServiceName  string
	Summary      string
	Description  string
	InternalOnly bool
}

// Client is the interface exposing OCM related functions
type Client interface {
	GetClusterMachinePools(internalClusterID string) ([]*cmv1.MachinePool, error)
	PostLimitedSupportReason(limitedSupportReason *LimitedSupportReason, internalClusterID string) error
	GetSupportRoleARN(internalClusterID string) (string, error)
	GetServiceLog(cluster *cmv1.Cluster, filter string) (*servicelogsv1.ClusterLogsUUIDListResponse, error)
	PostServiceLog(clusterID string, sl *ServiceLog) error
	AwsClassicJumpRoleCompatible(cluster *cmv1.Cluster) (bool, error)
	GetConnection() *sdk.Connection
	IsAccessProtected(cluster *cmv1.Cluster) (bool, error)
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
func (c *SdkClient) GetClusterInfo(identifier string) (*cmv1.Cluster, error) {
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
func (c *SdkClient) GetClusterMachinePools(internalClusterID string) ([]*cmv1.MachinePool, error) {
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
func (c *SdkClient) PostLimitedSupportReason(limitedSupportReason *LimitedSupportReason, internalClusterID string) error {
	logging.Infof("Sending limited support reason: %s", limitedSupportReason.Summary)

	ls, err := newLimitedSupportReasonBuilder(limitedSupportReason).Build()
	if err != nil {
		return fmt.Errorf("could not create post request (LS): %w", err)
	}

	request := c.conn.ClustersMgmt().V1().Clusters().Cluster(internalClusterID).LimitedSupportReasons().Add()
	request = request.Body(ls)
	resp, err := request.Send()
	if err != nil && !strings.Contains(err.Error(), "Operation is not allowed for a cluster in 'uninstalling' state") {
		return fmt.Errorf("received error from ocm: %w. Full Response: %#v", err, resp)
	}

	return nil
}

// GetServiceLog returns all ServiceLogs for a cluster.
// When supplying a filter it will use the Search call and pass it to this one directly.
func (c *SdkClient) GetServiceLog(cluster *cmv1.Cluster, filter string) (*servicelogsv1.ClusterLogsUUIDListResponse, error) {
	if filter != "" {
		return c.conn.ServiceLogs().V1().Clusters().Cluster(cluster.ExternalID()).ClusterLogs().List().Search(filter).Send()
	}
	return c.conn.ServiceLogs().V1().Clusters().Cluster(cluster.ExternalID()).ClusterLogs().List().Send()
}

// PostServiceLog allows to send a generic servicelog to a cluster.
func (c *SdkClient) PostServiceLog(clusterID string, sl *ServiceLog) error {
	builder := &servicelogsv1.LogEntryBuilder{}
	builder.Severity(servicelogsv1.Severity(sl.Severity))
	builder.ServiceName(sl.ServiceName)
	builder.Summary(sl.Summary)
	builder.Description(sl.Description)
	builder.InternalOnly(sl.InternalOnly)
	builder.ClusterID(clusterID)
	le, err := builder.Build()
	if err != nil {
		return fmt.Errorf("could not create post request (SL): %w", err)
	}

	request := c.conn.ServiceLogs().V1().ClusterLogs().Add()
	request = request.Body(le)

	if _, err = request.Send(); err != nil {
		return fmt.Errorf("could not post service log %s: %w", sl.Summary, err)
	}

	logging.Infof("Successfully sent servicelog: %s", sl.Summary)

	return nil
}

// newLimitedSupportReasonBuilder creates a Limited Support reason
func newLimitedSupportReasonBuilder(ls *LimitedSupportReason) *cmv1.LimitedSupportReasonBuilder {
	builder := cmv1.NewLimitedSupportReason()
	builder.Summary(ls.Summary)
	builder.Details(ls.Details)
	builder.DetectionType(cmv1.DetectionTypeManual)
	return builder
}

// AwsClassicJumpRoleCompatible check whether or not the CAD jumprole path is supported by the cluster
func (c *SdkClient) AwsClassicJumpRoleCompatible(cluster *cmv1.Cluster) (bool, error) {
	// If the cluster is STS, check if it compatible.
	if cluster.AWS().STS().Empty() {
		// All non STS clusters are compatible.
		return true, nil
	}

	resp, err := c.conn.ClustersMgmt().V1().Clusters().Cluster(cluster.ID()).StsSupportJumpRole().Get().Send()
	if err != nil {
		return false, fmt.Errorf("could not query sts support role from ocm: %w", err)
	}

	roleARN, ok := resp.Body().GetRoleArn()
	if !ok {
		return false, errors.New("unable to get sts support role ARN for cluster")
	}

	// This ARN has a different formatting depending on whether it's accessible using the new backplane flow or not
	// - Clusters using the new access (SDE-3036, unsupported by CAD): arn:aws:iam::<aws_id>:role/RH-Technical-Support-123456
	//-  Clusters using the old access (supported by CAD): arn:aws:iam::<aws_id>:role/RH-Technical-Support-Access
	return strings.Contains(roleARN, "RH-Technical-Support-Access"), nil
}

// GetConnection returns the active connection of the SdkClient
func (c *SdkClient) GetConnection() *sdk.Connection {
	return c.conn
}

// IsAccessProtected returns whether access protection is enabled for a cluster
func (c *SdkClient) IsAccessProtected(cluster *cmv1.Cluster) (bool, error) {
	resp, err := c.conn.AccessTransparency().V1().AccessProtection().Get().ClusterId(cluster.ID()).Send()
	if err != nil {
		return false, fmt.Errorf("could not query access protection status from ocm: %w", err)
	}
	enabled, ok := resp.Body().GetEnabled()
	if !ok {
		return false, fmt.Errorf("unable to get AccessProtection status for cluster")
	}
	return enabled, nil
}

// Package ocm contains ocm api related functions
package ocm

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	sdk "github.com/openshift-online/ocm-sdk-go"

	amv1 "github.com/openshift-online/ocm-sdk-go/accountsmgmt/v1"
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

// UserBanedError contains the reason for a user's ban
type UserBannedError struct {
	Code        string
	Description string
}

// Client is the interface exposing OCM related functions
type Client interface {
	GetClusterMachinePools(internalClusterID string) ([]*cmv1.MachinePool, error)
	PostLimitedSupportReason(cluster *cmv1.Cluster, limitedSupportReason *LimitedSupportReason) error
	GetSupportRoleARN(internalClusterID string) (string, error)
	GetServiceLog(cluster *cmv1.Cluster, filter string) (*servicelogsv1.ClusterLogsUUIDListResponse, error)
	PostServiceLog(cluster *cmv1.Cluster, sl *ServiceLog) error
	AwsClassicJumpRoleCompatible(cluster *cmv1.Cluster) (bool, error)
	GetConnection() *sdk.Connection
	IsAccessProtected(cluster *cmv1.Cluster) (bool, error)
	GetClusterHypershiftConfig(cluster *cmv1.Cluster) (*cmv1.HypershiftConfig, error)
	GetOrganizationID(clusterID string) (string, error)
	GetClusterInfo(identifier string) (*cmv1.Cluster, error)
	IsManagingCluster(clusterID string) (bool, error)
	GetDynatraceURL(cluster *cmv1.Cluster) (string, error)
	CheckIfUserBanned(cluster *cmv1.Cluster) error
	GetCreatorFromCluster(cluster *cmv1.Cluster) (*amv1.Account, error)
}

// SdkClient is the ocm client with which we can run the commands
// currently we do not need to export the connection or the config, as we create the SdkClient using the New func
type SdkClient struct {
	conn *sdk.Connection
}

// New will create a new ocm client using the provided credentials
func New(clientID, clientSecret, url string) (*SdkClient, error) {
	var err error
	client := SdkClient{}

	client.conn, err = newConnectionFromClientPair(clientID, clientSecret, url)
	if err != nil {
		return nil, fmt.Errorf("failed to create connection from client key pair: %w", err)
	}

	return &client, nil
}

// newConnectionFromClientPair creates a new connection via set of client ID, client secret
// and the target OCM API URL.
func newConnectionFromClientPair(clientID, clientSecret, url string) (*sdk.Connection, error) {
	if clientID == "" || clientSecret == "" || url == "" {
		return nil, fmt.Errorf("missing required parameters: clientID, clientSecret, or url")
	}
	return sdk.NewConnectionBuilder().URL(url).Client(clientID, clientSecret).Insecure(false).Build()
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

// GetOrganizationID returns the organization ID for a cluster, or empty string if not part of an organization.
func (c *SdkClient) GetOrganizationID(clusterID string) (string, error) {
	cluster, err := c.GetClusterInfo(clusterID)
	if err != nil {
		return "", err
	}

	cmv1Subscription, ok := cluster.GetSubscription()
	if !ok {
		return "", nil
	}

	subscriptionResponse, err := c.conn.AccountsMgmt().V1().Subscriptions().Subscription(cmv1Subscription.ID()).Get().Send()
	if err != nil {
		return "", err
	}

	subscription, ok := subscriptionResponse.GetBody()
	if !ok {
		return "", nil
	}

	return subscription.OrganizationID(), nil
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

// GetClusterMachinePools gets the machine pools for a given cluster
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
func (c *SdkClient) PostLimitedSupportReason(cluster *cmv1.Cluster, limitedSupportReason *LimitedSupportReason) error {
	if cluster == nil {
		return errors.New("cluster must not be nil")
	}

	product := GetClusterProduct(cluster)
	if mismatch, link := findDocumentationMismatch(product, limitedSupportReason.Details); mismatch != ProductUnknown {
		return &DocumentationMismatchError{
			ExpectedProduct: product,
			DetectedProduct: mismatch,
			Link:            link,
			Summary:         limitedSupportReason.Summary,
			Details:         limitedSupportReason.Details,
			Kind:            documentationMessageKindLimitedSupport,
		}
	}

	logging.Infof("Sending limited support reason: %s", limitedSupportReason.Summary)

	ls, err := newLimitedSupportReasonBuilder(limitedSupportReason).Build()
	if err != nil {
		return fmt.Errorf("could not create post request (LS): %w", err)
	}

	request := c.conn.ClustersMgmt().V1().Clusters().Cluster(cluster.ID()).LimitedSupportReasons().Add()
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
func (c *SdkClient) PostServiceLog(cluster *cmv1.Cluster, sl *ServiceLog) error {
	if cluster == nil {
		return errors.New("cluster must not be nil")
	}

	product := GetClusterProduct(cluster)
	if mismatch, link := findDocumentationMismatch(product, sl.Description); mismatch != ProductUnknown {
		return &DocumentationMismatchError{
			ExpectedProduct: product,
			DetectedProduct: mismatch,
			Link:            link,
			Summary:         sl.Summary,
			Details:         sl.Description,
			Kind:            documentationMessageKindServiceLog,
		}
	}

	builder := &servicelogsv1.LogEntryBuilder{}
	builder.Severity(servicelogsv1.Severity(sl.Severity))
	builder.ServiceName(sl.ServiceName)
	builder.Summary(sl.Summary)
	builder.Description(sl.Description)
	builder.InternalOnly(sl.InternalOnly)
	builder.ClusterID(cluster.ID())
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

func (c *SdkClient) GetClusterHypershiftConfig(cluster *cmv1.Cluster) (*cmv1.HypershiftConfig, error) {
	resp, err := c.conn.ClustersMgmt().V1().Clusters().Cluster(cluster.ID()).Hypershift().Get().Send()
	if err != nil {
		return nil, fmt.Errorf("could not query hypershift status from ocm: %w", err)
	}

	return resp.Body(), nil
}

func (c *SdkClient) CheckIfUserBanned(cluster *cmv1.Cluster) error {
	user, err := c.GetCreatorFromCluster(cluster)
	if err != nil {
		return fmt.Errorf("while checking if the cluster owner is banned: %w", err)
	}

	if user.Banned() {
		return UserBannedError{
			Code:        user.BanCode(),
			Description: user.BanDescription(),
		}
	}

	// User is not banned
	return nil
}

const (
	hypershiftClusterTypeLabel  = "ext-hypershift.openshift.io/cluster-type"
	managementClusterLabelValue = "management-cluster"
	serviceClusterLabelValue    = "service-cluster"
	hiveLabel                   = "ext-managed.openshift.io/hive-shard"
	hiveLabelValue              = "true"
)

// IsManagingCluster returns true if the cluster is a managing cluster,
// meaning it is one of: hive shard, service cluster, or management cluster.
func (c *SdkClient) IsManagingCluster(clusterID string) (bool, error) {
	resp, err := c.conn.ClustersMgmt().V1().Clusters().Cluster(clusterID).ExternalConfiguration().Labels().List().Send()
	if err != nil {
		return false, fmt.Errorf("failed to fetch external configuration labels for cluster %s: %w", clusterID, err)
	}

	for _, label := range resp.Items().Slice() {
		key := label.Key()
		value := label.Value()

		if (key == hypershiftClusterTypeLabel && (value == managementClusterLabelValue || value == serviceClusterLabelValue)) ||
			(key == hiveLabel && value == hiveLabelValue) {
			return true, nil
		}
	}

	return false, nil
}

func (c *SdkClient) GetCreatorFromCluster(cluster *cmv1.Cluster) (*amv1.Account, error) {
	logging.Debugf("Getting subscription from cluster: %s", cluster.ID())
	cmv1Subscription, ok := cluster.GetSubscription()
	if !ok {
		return nil, fmt.Errorf("failed to get subscription from cluster: %s", cluster.ID())
	}
	subscriptionResponse, err := c.conn.AccountsMgmt().V1().Subscriptions().Subscription(cmv1Subscription.ID()).Get().Send()
	if err != nil {
		return nil, err
	}

	subscription, ok := subscriptionResponse.GetBody()
	if !ok {
		return nil, errors.New("failed to get subscription")
	}

	if status := subscription.Status(); status != "Active" {
		return nil, fmt.Errorf("expecting status 'Active' found %v", status)
	}

	accountResponse, err := c.conn.AccountsMgmt().V1().Accounts().Account(subscription.Creator().ID()).Get().Send()
	if err != nil {
		return nil, err
	}

	creator, ok := accountResponse.GetBody()
	if !ok {
		return nil, errors.New("failed to get creator from subscription")
	}
	return creator, nil
}

// GetDynatraceURL retrieves the Dynatrace tenant URL from the cluster's subscription labels
func (c *SdkClient) GetDynatraceURL(cluster *cmv1.Cluster) (string, error) {
	const dynatraceTenantKeyLabel = "dynatrace.regional-tenant"

	cmv1Subscription, ok := cluster.GetSubscription()
	if !ok {
		return "", fmt.Errorf("failed to get subscription from cluster: %s", cluster.ID())
	}

	subscriptionLabels, err := c.conn.AccountsMgmt().V1().Subscriptions().Subscription(cmv1Subscription.ID()).Labels().List().Send()
	if err != nil {
		return "", fmt.Errorf("failed to get subscription labels: %w", err)
	}

	labels, ok := subscriptionLabels.GetItems()
	if !ok {
		return "", errors.New("failed to get labels from subscription")
	}

	for _, label := range labels.Slice() {
		if key, ok := label.GetKey(); ok {
			if key == dynatraceTenantKeyLabel {
				if value, ok := label.GetValue(); ok {
					if value == "" {
						return "", errors.New("dynatrace tenant label is empty")
					}
					return fmt.Sprintf("https://%s.apps.dynatrace.com/", value), nil
				}
			}
		}
	}

	return "", errors.New("dynatrace tenant label not found in subscription")
}

func (e UserBannedError) Error() string {
	return fmt.Sprintf("user is banned (%s): %s", e.Code, e.Description)
}

func NewOCMBannedUserServiceLog() ServiceLog {
	return ServiceLog{
		Severity:     "Critical",
		Summary:      "Action required: Arrange new cluster owner",
		Description:  "Your cluster requires you to take action because it is no longer owned by a user with an enabled Red Hat account. This will impact the cluster's ability to upgrade to future versions. Please raise a support case with Red Hat to nominate a new owner for the cluster in https://console.redhat.com/openshift/.",
		InternalOnly: false,
		ServiceName:  "SREManualAction",
	}
}

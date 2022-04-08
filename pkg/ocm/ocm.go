package ocm

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	_ "github.com/golang/mock/mockgen/model" //revive:disable:blank-imports used for the mockgen generation
	sdk "github.com/openshift-online/ocm-sdk-go"

	v1 "github.com/openshift-online/ocm-sdk-go/clustersmgmt/v1"
	servicelog "github.com/openshift-online/ocm-sdk-go/servicelogs/v1"
	awsv1alpha1 "github.com/openshift/aws-account-operator/pkg/apis/aws/v1alpha1"
	hivev1 "github.com/openshift/hive/apis/hive/v1"
)

type slTemplate struct {
	Severity     string
	ServiceName  string
	Summary      string
	Description  string
	InternalOnly bool
}

var chgmServiceLog = slTemplate{
	Severity:     "Error",
	ServiceName:  "SREManualAction",
	Summary:      "Action required: cluster not checking in",
	Description:  "Your cluster requires you to take action because it is no longer checking in with Red Hat OpenShift Cluster Manager. Possible causes include stopping instances or a networking misconfiguration. If you have stopped the cluster instances, please start them again - stopping instances is not supported. If you intended to terminate this cluster then please delete the cluster in the Red Hat console.",
	InternalOnly: false,
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

	cfg, err := newConfigFromFile(ocmConfigFile)
	if err != nil {
		return client, fmt.Errorf("failed to load config file: %w", err)
	}

	client.conn, err = cfg.Connection()
	if err != nil {
		return client, fmt.Errorf("failed to create new OCM connection: %w", err)
	}

	return client, nil
}

// GetSupportRoleARN returns the support role ARN that allows the access to the cluster
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

// SendCHGMServiceLog allows to send a cluster has gone missing servicelog.
// On success it will return the sent service log entry.
func (client Client) SendCHGMServiceLog(cluster *v1.Cluster) (*servicelog.LogEntry, error) {
	return client.sendServiceLog(client.newServiceLogBuilder(chgmServiceLog), cluster)
}

// sendServiceLog allows to send a generic servicelog to a cluster.
// On success it will return the sent service log entry for further processing.
func (client Client) sendServiceLog(builder *servicelog.LogEntryBuilder, cluster *v1.Cluster) (*servicelog.LogEntry, error) {
	builder.ClusterUUID(cluster.ExternalID())
	builder.ClusterID(cluster.ID())
	builder.SubscriptionID(cluster.Subscription().ID())
	le, err := builder.Build()
	if err != nil {
		return nil, fmt.Errorf("could not create post request: %w", err)
	}

	request := c.conn.ServiceLogs().V1().ClusterLogs().Add()
	request = request.Body(le)
	resp, err := request.Send()
	if err != nil {
		return nil, fmt.Errorf("received error from ocm: %w. Full Response: %#v", err, resp)
	}
	return le, nil
}

// newServiceLogBuilder creates a service log template
func (c Client) newServiceLogBuilder(sl slTemplate) *servicelog.LogEntryBuilder {
	builder := servicelog.NewLogEntry()
	// it does not work if we use servicelog.SeverityError directly, because SeverityError
	// is lower-case and the service log API wants it in upper-case.
	builder.Severity(servicelog.Severity(sl.Severity))
	builder.ServiceName(sl.ServiceName)
	builder.Summary(sl.Summary)
	builder.Description(sl.Description)
	builder.InternalOnly(sl.InternalOnly)
	return builder
}

// newConfigFromFile loads the configuration file (ocmConfigFile, ~/.ocm.json, /ocm/ocm.json)
func newConfigFromFile(ocmConfigFile string) (*Config, error) {
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
	return cfg, err
}

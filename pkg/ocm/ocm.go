package ocm

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"

	_ "github.com/golang/mock/mockgen/model"
	sdk "github.com/openshift-online/ocm-sdk-go"

	v1 "github.com/openshift-online/ocm-sdk-go/clustersmgmt/v1"
	servicelog "github.com/openshift-online/ocm-sdk-go/servicelogs/v1"
	awsv1alpha1 "github.com/openshift/aws-account-operator/pkg/apis/aws/v1alpha1"
	hivev1 "github.com/openshift/hive/apis/hive/v1"
)

var (
	sl_clusterHasGoneMissing = "https://raw.githubusercontent.com/openshift/managed-notifications/master/osd/cluster_has_gone_missing.json"
)

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

	if ocmConfigFile != "" {
		err := os.Setenv("OCM_CONFIG", ocmConfigFile)
		if err != nil {
			return client, err
		}
	}

	client.conn, err = sdk.NewConnectionBuilder().Load(ocmConfigFile).Build()
	if err != nil {
		return client, fmt.Errorf("failed to create new OCM connection: %w", err)
	}

	return client, nil
}

// GetSupportRoleARN returns the support role ARN that allows the access to the cluster
func (client Client) GetSupportRoleARN(clusterID string) (string, error) {
	claim, err := client.GetAWSAccountClaim(clusterID)
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
func (client Client) GetAWSAccountClaim(clusterID string) (*awsv1alpha1.AccountClaim, error) {
	ac := &awsv1alpha1.AccountClaim{}
	acString, err := client.getClusterResource(clusterID, "aws_account_claim")
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
func (client Client) GetClusterInfo(identifier string) (*v1.Cluster, error) {
	q := fmt.Sprintf("(id like '%[1]s' or external_id like '%[1]s' or display_name like '%[1]s')", identifier)
	resp, err := client.conn.ClustersMgmt().V1().Clusters().List().Search(q).Send()
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
func (client Client) GetClusterDeployment(clusterID string) (*hivev1.ClusterDeployment, error) {
	cd := &hivev1.ClusterDeployment{}
	cdString, err := client.getClusterResource(clusterID, "cluster_deployment")
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
func (client Client) getClusterResource(clusterID string, resourceKey string) (string, error) {

	response, err := client.conn.ClustersMgmt().V1().Clusters().Cluster(clusterID).Resources().Live().Get().Send()
	if err != nil {
		return "", err
	}
	return response.Body().Resources()[resourceKey], nil
}

// SendCHGMServiceLog allows to send a cluster has gone missing servicelog
func (client Client) SendCHGMServiceLog(cluster *v1.Cluster) error {
	json, err := getServiceLogTemplate(sl_clusterHasGoneMissing)
	if err != nil {
		return fmt.Errorf("failed to get CHGM-SL template: %w", err)
	}
	le, err := servicelog.UnmarshalLogEntry(json)
	if err != nil {
		return fmt.Errorf("failed to create SL message from json (%s): %w", json, err)
	}
	return client.sendServiceLog(le, cluster)
}

// sendServiceLog allows to send a generic servicelog to a cluster
func (client Client) sendServiceLog(le *servicelog.LogEntry, cluster *v1.Cluster) error {
	builder := servicelog.NewLogEntry()
	builder.Copy(le)
	builder.ClusterUUID(cluster.ExternalID())
	builder.ClusterID(cluster.ID())
	builder.SubscriptionID(cluster.Subscription().ID())
	le, err := builder.Build()
	if err != nil {
		return fmt.Errorf("could not create post request: %w", err)
	}

	request := client.conn.ServiceLogs().V1().ClusterLogs().Add()
	request = request.Body(le)
	resp, err := request.Send()
	if err != nil {
		return fmt.Errorf("received error from ocm: %w. Full Response: %#v", err, resp)
	}
	return nil
}

// getServiceLogTemplate fetches a servicelog template from a url
func getServiceLogTemplate(url string) (string, error) {
	var err error
	//#nosec G107 -- the url is hardcoded so no permutations can happen
	resp, err := http.Get(url)
	if err != nil {
		return "", fmt.Errorf("HTTP protocol error: %w", err)
	}
	defer func() {
		internalErr := resp.Body.Close()
		if internalErr != nil {
			err = fmt.Errorf("could not close http body: %w", internalErr)
		}
	}()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("received bad http status code: %#v", resp)
	}
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read body: %w", err)
	}

	// as the defer can raise an error, returning the error here aswell
	return string(bodyBytes), err
}

package ocm

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"

	_ "github.com/golang/mock/mockgen/model"
	sdkcfg "github.com/openshift-online/ocm-cli/pkg/config"
	sdk "github.com/openshift-online/ocm-sdk-go"

	v1 "github.com/openshift-online/ocm-sdk-go/clustersmgmt/v1"
	servicelog "github.com/openshift-online/ocm-sdk-go/servicelogs/v1"
	awsv1alpha1 "github.com/openshift/aws-account-operator/pkg/apis/aws/v1alpha1"
	hivev1 "github.com/openshift/hive/apis/hive/v1"
)

var (
	sl_clusterHasGoneMissing = "https://raw.githubusercontent.com/openshift/managed-notifications/master/osd/cluster_has_gone_missing.json"
)

type ocmClient struct {
	conn *sdk.Connection
	cfg  *sdkcfg.Config
}

// New will create a new ocm client by using the path to a config file
// if no path is provided, it will assume it in the default path
func New(ocmConfigFile string) (ocmClient, error) {
	client := ocmClient{}
	cfg, err := newConfigFromFile(ocmConfigFile)
	if err != nil {
		return client, fmt.Errorf("failed to load config file: %w", err)
	}
	client.cfg = cfg

	conn, err := client.cfg.Connection()
	if err != nil {
		return client, fmt.Errorf("can't create connection: %w", err)
	}
	client.conn = conn
	return client, nil
}

// GetSupportRoleARN returns the support role ARN that allows the access to the cluster
func (client ocmClient) GetSupportRoleARN(clusterID string) (string, error) {
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
func (client ocmClient) GetAWSAccountClaim(clusterID string) (*awsv1alpha1.AccountClaim, error) {
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
func (client ocmClient) GetClusterInfo(identifier string) (*v1.Cluster, error) {
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
func (client ocmClient) GetClusterDeployment(clusterID string) (*hivev1.ClusterDeployment, error) {
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
func (client ocmClient) getClusterResource(clusterID string, resourceKey string) (string, error) {

	response, err := client.conn.ClustersMgmt().V1().Clusters().Cluster(clusterID).Resources().Live().Get().Send()
	if err != nil {
		return "", err
	}
	return response.Body().Resources()[resourceKey], nil
}

// SendCHGMServiceLog allows to send a cluster has gone missing servicelog
func (client ocmClient) SendCHGMServiceLog(cluster *v1.Cluster) error {
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
func (client ocmClient) sendServiceLog(le *servicelog.LogEntry, cluster *v1.Cluster) error {

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

// newConfigFromFile loads the configuration file (ocmConfigFile, ~/.ocm.json, /ocm/ocm.json)
func newConfigFromFile(ocmConfigFile string) (*sdkcfg.Config, error) {
	if ocmConfigFile != "" {
		err := os.Setenv("OCM_CONFIG", ocmConfigFile)
		if err != nil {
			return nil, err
		}
	}
	// Load the configuration file from std path
	cfg, err := sdkcfg.Load()
	if err != nil {
		return nil, err
	}
	if cfg == nil || cfg == (&sdkcfg.Config{}) {
		return nil, fmt.Errorf("not logged in")
	}
	return cfg, err
}

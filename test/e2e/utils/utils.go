package utils

import (
	"fmt"

	sdk "github.com/openshift-online/ocm-sdk-go"
	amv1 "github.com/openshift-online/ocm-sdk-go/accountsmgmt/v1"
	cmv1 "github.com/openshift-online/ocm-sdk-go/clustersmgmt/v1"
	servicelogsv1 "github.com/openshift-online/ocm-sdk-go/servicelogs/v1"
	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
	"github.com/openshift/configuration-anomaly-detection/pkg/ocm"
	ocme2e "github.com/openshift/osde2e-common/pkg/clients/ocm"
	"k8s.io/client-go/tools/clientcmd"
	pclient "sigs.k8s.io/controller-runtime/pkg/client"
)

func GetLimitedSupportReasons(ocme2eCli *ocme2e.Client, clusterID string) (*cmv1.LimitedSupportReasonsListResponse, error) {
	lsResponse, err := ocme2eCli.ClustersMgmt().V1().Clusters().Cluster(clusterID).LimitedSupportReasons().List().Send()
	if err != nil {
		return nil, fmt.Errorf("failed sending service log: %w", err)
	}
	return lsResponse, nil
}

func GetServiceLogs(ocmLike interface{}, cluster *cmv1.Cluster) (*servicelogsv1.ClusterLogsUUIDListResponse, error) {
	const filter = "log_type='cluster-state-updates'"

	switch v := ocmLike.(type) {
	case ocm.Client:
		clusterLogsUUIDListResponse, err := v.GetServiceLog(cluster, filter)
		if err != nil {
			return nil, fmt.Errorf("Failed to get service log: %w", err)
		}
		return clusterLogsUUIDListResponse, nil
	case *ocme2e.Client:
		adapter := &e2eOCMAdapter{conn: v.Connection}
		clusterLogsUUIDListResponse, err := adapter.GetServiceLog(cluster, filter)
		if err != nil {
			return nil, fmt.Errorf("Failed to get service log (via adapter): %w", err)
		}
		return clusterLogsUUIDListResponse, nil
	default:
		return nil, fmt.Errorf("unsupported type for GetServiceLogs: %T", v)
	}
}

type e2eOCMAdapter struct {
	conn *sdk.Connection
}

func (a *e2eOCMAdapter) GetServiceLog(cluster *cmv1.Cluster, filter string) (*servicelogsv1.ClusterLogsUUIDListResponse, error) {
	if filter != "" {
		return a.conn.ServiceLogs().V1().Clusters().Cluster(cluster.ExternalID()).ClusterLogs().List().Search(filter).Send()
	}
	return a.conn.ServiceLogs().V1().Clusters().Cluster(cluster.ExternalID()).ClusterLogs().List().Send()
}

// === IS USER BANNED (uses ocme2eCli.Connection) ===
func IsUserBanned(ocme2eCli *ocme2e.Client, cluster *cmv1.Cluster) (bool, string, error) {
	conn := ocme2eCli.Connection
	user, err := getCreatorFromCluster(conn, cluster)
	if err != nil {
		return false, "encountered an issue when checking if the cluster owner is banned. Please investigate.", err
	}

	if user.Banned() {
		noteMessage := fmt.Sprintf("User is banned %s. Ban description %s.\n Please open a proactive case, so that MCS can resolve the ban or organize an ownership transfer.", user.BanCode(), user.BanDescription())
		logging.Warnf(noteMessage)
		return true, noteMessage, nil
	}
	return false, "User is not banned.", nil
}

func getCreatorFromCluster(conn *sdk.Connection, cluster *cmv1.Cluster) (*amv1.Account, error) {
	logging.Debugf("Getting subscription from cluster: %s", cluster.ID())
	sub, ok := cluster.GetSubscription()
	if !ok {
		return nil, fmt.Errorf("failed to get subscription from cluster: %s", cluster.ID())
	}
	subResp, err := conn.AccountsMgmt().V1().Subscriptions().Subscription(sub.ID()).Get().Send()
	if err != nil {
		return nil, err
	}
	subscription, ok := subResp.GetBody()
	if !ok {
		return nil, fmt.Errorf("failed to get subscription body")
	}
	if subscription.Status() != "Active" {
		return nil, fmt.Errorf("expecting status 'Active' found %v", subscription.Status())
	}
	accResp, err := conn.AccountsMgmt().V1().Accounts().Account(subscription.Creator().ID()).Get().Send()
	if err != nil {
		return nil, err
	}
	account, ok := accResp.GetBody()
	if !ok {
		return nil, fmt.Errorf("failed to get account body")
	}
	return account, nil
}

// === CREATE CLIENT FROM KUBECONFIG ===
func CreateClientFromKubeConfig(kubeConfigPath string) (pclient.Client, error) {
	cfg, err := clientcmd.BuildConfigFromFlags("", kubeConfigPath)
	if err != nil {
		return nil, fmt.Errorf("failed to build kubeconfig: %v", err)
	}
	cl, err := pclient.New(cfg, pclient.Options{})
	if err != nil {
		return nil, fmt.Errorf("failed to create Kubernetes client: %v", err)
	}
	return cl, nil
}

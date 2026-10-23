package micro

import (
	amv1 "github.com/openshift-online/ocm-sdk-go/accountsmgmt/v1"
	cmv1 "github.com/openshift-online/ocm-sdk-go/clustersmgmt/v1"
	"github.com/openshift/configuration-anomaly-detection/pkg/notewriter"
	"github.com/openshift/configuration-anomaly-detection/pkg/ocm"
)

// ClusterCreator fetches the cluster owner's OCM account. The returned
// account can be passed to CheckBan for ban-status inspection.
func ClusterCreator(ocmClient ocm.Client, cluster *cmv1.Cluster, notes *notewriter.NoteWriter) (DataResult[*amv1.Account], error) {
	user, err := ocmClient.GetCreatorFromCluster(cluster)
	if err != nil {
		return DataResult[*amv1.Account]{}, err
	}

	return DataResult[*amv1.Account]{
		Result: Result{Done: false},
		Value:  user,
	}, nil
}

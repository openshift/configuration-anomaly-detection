package precheck

import (
	"errors"

	cmv1 "github.com/openshift-online/ocm-sdk-go/clustersmgmt/v1"
	investigation "github.com/openshift/configuration-anomaly-detection/pkg/investigations/investigation"
	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
)

type ClusterStatePrecheck struct{}

// Checks pre-requisites for a cluster investigation:
// - the cluster's state is supported by CAD for an investigation (= not uninstalling)
// - the cloud provider is supported by CAD (cluster is AWS)
// Performs according pagerduty actions and returns whether CAD needs to investigate the cluster
func (c *ClusterStatePrecheck) Run(rb investigation.ResourceBuilder) (investigation.InvestigationResult, error) {
	result := investigation.InvestigationResult{}
	r, err := rb.WithCluster().Build()
	if err != nil {
		return result, err
	}
	cluster := r.Cluster
	pdClient := r.PdClient
	ocmClient := r.OcmClient
	if cluster.State() == cmv1.ClusterStateUninstalling {
		logging.Info("Cluster is uninstalling and requires no investigation. Silencing alert.")
		result.StopInvestigations = errors.New("cluster is already uninstalling")
		return result, pdClient.SilenceIncidentWithNote("CAD: Cluster is already uninstalling, silencing alert.")
	}

	if cluster.AWS() == nil {
		logging.Info("Cloud provider unsupported, forwarding to primary.")
		result.StopInvestigations = errors.New("unsupported cloud provider (non-AWS)")
		return result, pdClient.EscalateIncidentWithNote("CAD could not run an automated investigation on this cluster: unsupported cloud provider.")
	}

	isAccessProtected, err := ocmClient.IsAccessProtected(cluster)
	if err != nil {
		logging.Warnf("failed to get access protection status for cluster: %v. Escalating for manual handling.", err)
		result.StopInvestigations = errors.New("access protection could not be determined")
		return result, pdClient.EscalateIncidentWithNote("CAD could not determine access protection status for this cluster, as CAD is unable to run against access protected clusters, please investigate manually.")
	}
	if isAccessProtected {
		logging.Info("Cluster is access protected. Escalating alert.")
		result.StopInvestigations = errors.New("cluster is access protected")
		return result, pdClient.EscalateIncidentWithNote("CAD is unable to run against access protected clusters. Please investigate.")
	}
	return result, nil
}

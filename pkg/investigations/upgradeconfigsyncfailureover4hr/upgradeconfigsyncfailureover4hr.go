// Package upgradeconfigsyncfailureover4hr contains functionality for the UpgradeConfigSyncFailureOver4HrSRE investigation
package upgradeconfigsyncfailureover4hr

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/investigation"
	k8sclient "github.com/openshift/configuration-anomaly-detection/pkg/k8s"
	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
	"github.com/openshift/configuration-anomaly-detection/pkg/notewriter"
	"github.com/openshift/configuration-anomaly-detection/pkg/ocm"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type Investigation struct {
}

const (
	alertname       = "UpgradeConfigSyncFailureOver4HrSRE"
	remediationName = "upgradeconfigsyncfailureover4hr"
)

func (c *Investigation) Run(r *investigation.Resources) (investigation.InvestigationResult, error) {
	result := investigation.InvestigationResult{}
	notes := notewriter.New("UpgradeConfigSyncFailureOver4Hr", logging.RawLogger)
	k8scli, err := k8sclient.New(r.Cluster.ID(), r.OcmClient, remediationName)
	if err != nil {
		return result, fmt.Errorf("unable to initialize k8s cli: %w", err)
	}
	defer func() {
		deferErr := k8sclient.Cleanup(r.Cluster.ID(), r.OcmClient, remediationName)
		if deferErr != nil {
			logging.Error(deferErr)
			err = errors.Join(err, deferErr)
		}
	}()
	logging.Infof("client : %v", k8scli)

	logging.Infof("ClusterID: %s", r.Cluster.ID())
	// Checks if user is banned
	// https://github.com/openshift/configuration-anomaly-detection/pull/352/
	// Relies on OCM function introduced in this PR
	user, err := ocm.GetCreatorFromCluster(r.OcmClient.GetConnection(), r.Cluster)
	if err != nil {
		notes.AppendWarning("encountered an issue when checking if the cluster owner is banned. Please investigate.")
		return result, r.PdClient.EscalateIncidentWithNote(notes.String())
	}

	if user.Banned() {
		// Lets make a nice copyable snippet here.
		notes.AppendWarning("User is banned: %s", user.BanCode())
		notes.AppendWarning("Ban description: %s", user.BanDescription())
		notes.AppendWarning("Please open a proactive case, so that MCS can resolve the ban or organize a ownership transfer.")
	} else {
		notes.AppendSuccess("User is not banned.")
	}

	//clusterPullSecret, err := getPullSecret(k8scli)
	logging.Warnf("############### Checking the secret ############")
	clusterSecret, err := getPullSecret(k8scli)
	if err != nil {
		logging.Errorf("Failure getting ClusterSecret: %v", err)
	}
	logging.Infof("******** Passed Function Call********")
	logging.Infof("Cluster Secret Is: %s", clusterSecret)
	return result, r.PdClient.EscalateIncidentWithNote("testing")
}

func getPullSecret(k8scli client.Client) (string, error) {
	secret := &corev1.Secret{}
	logging.Infof("client : %v", k8scli)
	logging.Infof("++++++ running Get Function +++++++")
	err := k8scli.Get(context.TODO(), types.NamespacedName{
		Namespace: "openshift-config",
		Name:      "pull-secret",
	}, secret)
	if err != nil {
		return "", err
	}

	if secret.Data == nil {
		return "", err
	}

	value, exists := secret.Data[".dockerconfigjson"]
	if !exists {
		return "", err
	}
	return string(value), nil
}

func (c *Investigation) Name() string {
	return "UpgradeConfigSyncFailureOver4hr"
}

func (c *Investigation) Description() string {
	return "Investigates the UpgradeConfigSyncFailureOver4hr alert"
}

func (c *Investigation) ShouldInvestigateAlert(alert string) bool {
	return strings.Contains(alert, "UpgradeConfigSyncFailureOver4HrSRE")
}

func (c *Investigation) IsExperimental() bool {
	return false
}

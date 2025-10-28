// Package upgradeconfigsyncfailureover4hr contains functionality for the UpgradeConfigSyncFailureOver4HrSRE investigation
package upgradeconfigsyncfailureover4hr

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"

	v1 "github.com/openshift-online/ocm-sdk-go/accountsmgmt/v1"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/investigation"
	k8sclient "github.com/openshift/configuration-anomaly-detection/pkg/k8s"
	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
	"github.com/openshift/configuration-anomaly-detection/pkg/notewriter"
	ocm "github.com/openshift/configuration-anomaly-detection/pkg/ocm"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type Investigation struct{}

func (c *Investigation) Run(rb investigation.ResourceBuilder) (investigation.InvestigationResult, error) {
	result := investigation.InvestigationResult{}
	r, err := rb.Build()
	if err != nil {
		return result, err
	}
	notes := notewriter.New("UpgradeConfigSyncFailureOver4Hr", logging.RawLogger)

	logging.Infof("Checking if user is Banned.")
	userBannedStatus, userBannedNotes, err := ocm.CheckIfUserBanned(r.OcmClient, r.Cluster)
	if err != nil {
		notes.AppendWarning("encountered an issue when checking if the cluster owner is banned: %s\nPlease investigate.", err)
		return result, r.PdClient.EscalateIncidentWithNote(notes.String())
	}
	if userBannedStatus {
		notes.AppendWarning("%s", userBannedNotes)
	} else {
		notes.AppendSuccess("User is not banned.")
	}
	user, err := ocm.GetCreatorFromCluster(r.OcmClient.GetConnection(), r.Cluster)
	logging.Infof("User ID is: %v", user.ID())
	if err != nil {
		notes.AppendWarning("Failed getting cluster creator from ocm: %s", err)
		return result, r.PdClient.EscalateIncidentWithNote(notes.String())
	}

	r, err = rb.WithK8sClient().Build()
	if err != nil {
		if errors.Is(err, k8sclient.ErrAPIServerUnavailable) {
			return result, r.PdClient.EscalateIncidentWithNote("CAD was unable to access cluster's kube-api. Please investigate manually.")
		}
		if errors.Is(err, k8sclient.ErrCannotAccessInfra) {
			return result, r.PdClient.EscalateIncidentWithNote("CAD is not allowed to access hive, management or service cluster's kube-api. Please investigate manually.")
		}
		return result, err
	}

	clusterSecretToken, note, err := getClusterPullSecret(r.K8sClient)
	if err != nil {
		notes.AppendWarning("Failed getting ClusterSecret: %s", err)
		return result, r.PdClient.EscalateIncidentWithNote(notes.String())
	}
	if note != "" {
		notes.AppendWarning("%s", note)
	}
	registryCredential, err := ocm.GetOCMPullSecret(r.OcmClient.GetConnection(), user.ID())
	if err != nil {
		notes.AppendWarning("Error getting OCMPullSecret: %s", err)
		return result, r.PdClient.EscalateIncidentWithNote(notes.String())
	}
	if clusterSecretToken == registryCredential {
		notes.AppendSuccess("Pull Secret matches on cluster and in OCM. Please continue investigation.")
	} else {
		notes.AppendWarning("Pull secret does not match on cluster and in OCM.")
	}
	return result, r.PdClient.EscalateIncidentWithNote(notes.String())
}

func getClusterPullSecret(k8scli client.Client) (secretToken string, note string, err error) {
	secret := &corev1.Secret{}
	err = k8scli.Get(context.TODO(), types.NamespacedName{
		Namespace: "openshift-config",
		Name:      "pull-secret",
	}, secret)
	if err != nil {
		return "", "", err
	}
	if secret.Data == nil {
		return "", "Cluster pull secret Data is empty.", err
	}
	secretValue, exists := secret.Data[".dockerconfigjson"]
	if !exists {
		return "", "Cluster pull secret does not contain the necessary .dockerconfigjson", err
	}

	dockerConfigJson, err := v1.UnmarshalAccessToken(secretValue)
	if err != nil {
		return "", "", err
	}
	_, exists = dockerConfigJson.Auths()["cloud.openshift.com"]
	if !exists {
		return "", "cloud.openshift.com value not found in clusterPullSecret. This means there is an issue with the pull secret on the cluster.", err
	}

	value, err := base64.StdEncoding.DecodeString(dockerConfigJson.Auths()["registry.connect.redhat.com"].Auth())
	if err != nil {
		return "", "", err
	}
	_, splitValue, _ := strings.Cut(string(value), ":")
	return splitValue, "", nil
}

func (c *Investigation) Name() string {
	return "upgradeconfigsyncfailureover4hr"
}

func (c *Investigation) AlertTitle() string {
	return "UpgradeConfigSyncFailureOver4HrSRE"
}

func (c *Investigation) Description() string {
	return "Investigates the UpgradeConfigSyncFailureOver4hr alert"
}

func (c *Investigation) IsExperimental() bool {
	return false
}

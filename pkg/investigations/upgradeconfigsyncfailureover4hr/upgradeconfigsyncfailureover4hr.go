// Package upgradeconfigsyncfailureover4hr contains functionality for the UpgradeConfigSyncFailureOver4HrSRE investigation
package upgradeconfigsyncfailureover4hr

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
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
	logging.Infof("Checking if user is Banned.")
	userBannedStatus, userBannedNotes, err := ocm.CheckIfUserBanned(r.OcmClient, r.Cluster)
	if err != nil {
		notes.AppendWarning("encountered an issue when checking if the cluster owner is banned: %s\nPlease investigate.", err)
		return result, r.PdClient.EscalateIncidentWithNote(notes.String())
	}
	if userBannedStatus {
		notes.AppendWarning(userBannedNotes)
	} else {
		notes.AppendSuccess("User is not banned.")
	}

	logging.Infof("############### Checking the secret ############")
	user, err := ocm.GetCreatorFromCluster(r.OcmClient.GetConnection(), r.Cluster)
	logging.Infof("User ID is: %v", user.ID())
	clusterSecretEmail, clusterSecretToken, err := getClusterPullSecret(k8scli, *notes)
	if err != nil {
		logging.Errorf("Failure getting ClusterSecret: %v", err)
	}
	logging.Infof("Cluster Secret Email Is: %s", clusterSecretEmail)
	registrycredential, err := ocm.GetOCMPullSecret(r.OcmClient.GetConnection(), user.ID())
	if err != nil {
		logging.Infof("Error getting OCMPullSecret: %v", err)
	}
	logging.Infof("Token is %s", clusterSecretToken)
	logging.Infof("Email is: %s", clusterSecretEmail)
	logging.Infof("registryCredential is: %v", registrycredential)
	return result, r.PdClient.EscalateIncidentWithNote("testing")
}

func getClusterPullSecret(k8scli client.Client, notes notewriter.NoteWriter) (string, string, error) {
	secret := &corev1.Secret{}
	err := k8scli.Get(context.TODO(), types.NamespacedName{
		Namespace: "openshift-config",
		Name:      "pull-secret",
	}, secret)
	if err != nil {
		return "", "", err
	}

	if secret.Data == nil {
		return "", "", err
	}

	secretValue, exists := secret.Data[".dockerconfigjson"]
	if !exists {
		return "", "", err
	}

	dockerConfigJson, err := v1.UnmarshalAccessToken(secretValue)
	if err != nil {
		return "", "", err
	}

	cloudOpenshiftAuth, exists := dockerConfigJson.Auths()["cloud.openshift.com"]
	if !exists {
		notes.AppendWarning("cloud.openshift.com value not found. This almost certainly means there is an issue with the pull secret on the cluster.")
		return "", "", err
	}

	email := cloudOpenshiftAuth.Email()
	value, err := base64.StdEncoding.DecodeString(dockerConfigJson.Auths()["registry.connect.redhat.com"].Auth())
	if err != nil {
		return "", "", err
	}
	_, splitValue, _ := strings.Cut(string(value), ":")
	return string(email), splitValue, nil
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

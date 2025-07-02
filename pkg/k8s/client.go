package k8sclient

import (
	"errors"
	"fmt"
	"os"

	"github.com/openshift/backplane-cli/pkg/cli/config"
	bpremediation "github.com/openshift/backplane-cli/pkg/remediation"
	"github.com/openshift/configuration-anomaly-detection/pkg/ocm"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type Cleaner interface {
	Clean() error
}

type Client interface {
	client.Client
	Cleaner
}

type clientImpl struct {
	client.Client
	Cleaner
}

// New returns a Kubernetes client for the given cluster scoped to a given remediation's permissions.
func New(clusterID string, ocmClient ocm.Client, remediationName string) (k8scli Client, err error) {
	cfg, err := NewCfg(clusterID, ocmClient, remediationName)
	if err != nil {
		return nil, err
	}

	cfgToClean := cfg
	defer func() {
		if cfgToClean != nil {
			deferErr := cfgToClean.Clean()
			if deferErr != nil {
				err = errors.Join(err, deferErr)
			}
		}
	}()

	scheme, err := initScheme()
	if err != nil {
		return nil, err
	}

	decoratedClient, err := client.New(&cfg.Config, client.Options{Scheme: scheme})
	if err != nil {
		return nil, err
	}

	cfgToClean = nil
	return clientImpl{decoratedClient, cfg}, nil
}

type Config struct {
	rest.Config
	Cleaner
}

type remediationCleaner struct {
	clusterID             string
	ocmClient             ocm.Client
	remediationInstanceId string
}

func (cleaner remediationCleaner) Clean() error {
	return deleteRemediation(cleaner.clusterID, cleaner.ocmClient, cleaner.remediationInstanceId)
}

// New returns a the k8s rest config for the given cluster scoped to a given remediation's permissions.
func NewCfg(clusterID string, ocmClient ocm.Client, remediationName string) (cfg *Config, err error) {
	backplaneURL := os.Getenv("BACKPLANE_URL")
	if backplaneURL == "" {
		return nil, fmt.Errorf("could not create new k8sclient: missing environment variable BACKPLANE_URL")
	}

	decoratedCfg, remediationInstanceId, err := bpremediation.CreateRemediationWithConn(
		config.BackplaneConfiguration{URL: backplaneURL},
		ocmClient.GetConnection(),
		clusterID,
		remediationName,
	)
	if err != nil {
		if isAPIServerUnavailable(err) {
			return nil, fmt.Errorf("%w: %w", ErrAPIServerUnavailable, err)
		}
		return nil, err
	}

	return &Config{*decoratedCfg, remediationCleaner{clusterID, ocmClient, remediationInstanceId}}, nil
}

// Cleanup removes the remediation created for the cluster.
func deleteRemediation(clusterID string, ocmClient ocm.Client, remediationInstanceId string) error {
	backplaneURL := os.Getenv("BACKPLANE_URL")
	if backplaneURL == "" {
		return fmt.Errorf("could not clean up k8sclient: missing environment variable BACKPLANE_URL")
	}

	return bpremediation.DeleteRemediationWithConn(
		config.BackplaneConfiguration{URL: backplaneURL},
		ocmClient.GetConnection(),
		clusterID,
		remediationInstanceId,
	)
}

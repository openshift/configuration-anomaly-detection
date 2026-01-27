// Package mustgather implements an investigation that collects must-gather diagnostics
// from ROSA classic clusters and uploads them to the Red Hat SFTP server for analysis.
// The investigation creates a compressed tarball of the must-gather output and uploads
// it using anonymous SFTP credentials, then posts the upload location to PagerDuty.
package mustgather

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/openshift/configuration-anomaly-detection/pkg/executor"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/investigation"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/utils/tarball"
	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
	"github.com/openshift/configuration-anomaly-detection/pkg/types"
)

const (
	// constants for must-gather output storage
	mustGatherDirectoryPattern = "must-gather.cad.*"   // the directory name of the local temporary storage used to store the must-gather
	archiveTimestampLayout     = "2006-01-02_15-04-05" // the layout of the timestamp used to create the must-gather archive name to be stored on the SFTP server

	// constants for the HCP must-gather
	defaultAcmHcpMustGatherImage    = "registry.redhat.io/multicluster-engine/must-gather-rhel9:v2.8"
	AcmHcpMustGatherCommandTemplate = "/usr/bin/gather hosted-cluster-namespace=%s hosted-cluster-name=%s"
	mustGatherNamespacePrefix       = "openshift-must-gather-"
	mustGatherOperatorNamespace     = "openshift-must-gather-operator" // permanent namespace to exclude from checks
	mustGatherWaitTimeout           = 30 * time.Minute                 // timeout for waiting for existing must-gather namespace to be deleted
	mustGatherPollInterval          = 60 * time.Second                 // interval for polling namespace existence

	// label for metrics
	productNameClassic = "ROSA classic"
	productNameHCP     = "ROSA HCP"
)

// getAcmHcpMustGatherImage returns the ACM HCP must-gather image to use.
// It can be overridden via the CAD_ACM_HCP_MUST_GATHER_IMAGE environment variable.
func getAcmHcpMustGatherImage() string {
	if image := os.Getenv("CAD_ACM_HCP_MUST_GATHER_IMAGE"); image != "" {
		return image
	}
	return defaultAcmHcpMustGatherImage
}

type Investigation struct{}

func (c *Investigation) Run(rb investigation.ResourceBuilder) (investigation.InvestigationResult, error) {
	result := investigation.InvestigationResult{}

	r, err := rb.WithNotes().WithOC().WithManagementOCClient().WithManagementK8sClient().Build()
	if err != nil {
		return result, err
	}

	productName := productNameClassic

	mustGatherResultDir, err := os.MkdirTemp("", mustGatherDirectoryPattern)
	if err != nil {
		result.Actions = []types.Action{
			executor.Note(fmt.Sprintf("CAD was unable to create a temporary directory for the must-gather results. Error: %v", err)),
			executor.Escalate("Failed to create temporary directory"),
		}
		return result, nil
	}
	defer func() {
		err := os.RemoveAll(mustGatherResultDir)
		if err != nil {
			logging.Errorf("Error cleaning up temporary directory for must gather results: %v", err)
		}
	}()

	mustGatherCommandFlags := []string{fmt.Sprintf("--dest-dir=%v", mustGatherResultDir)}

	if r.IsHCP {
		productName = productNameHCP
		err = waitForMustGatherNamespaceDeletion(context.Background(), r.ManagementK8sClient, mustGatherWaitTimeout, mustGatherPollInterval)
		if err != nil {
			return result, r.PdClient.EscalateIncidentWithNote(fmt.Errorf("CAD was unable to proceed with must-gather: %w", err).Error())
		}

		mustGatherCommandFlags = append(mustGatherCommandFlags,
			fmt.Sprintf("--image=%s", getAcmHcpMustGatherImage()),
			fmt.Sprintf(AcmHcpMustGatherCommandTemplate, r.HCPNamespace, r.Cluster.Name()),
		)
		err = r.ManagementOCClient.CreateMustGather(mustGatherCommandFlags)
	} else {
		err = r.OCClient.CreateMustGather(mustGatherCommandFlags)
	}
	if err != nil {
		return result, investigation.WrapInfrastructure(
			fmt.Errorf("failed to create must-gather: %w", err),
			"K8s must-gather execution failed")
	}

	mustGatherTarballName := fmt.Sprintf("%s-must-gather-%s.tar.gz", time.Now().UTC().Format(archiveTimestampLayout), r.Cluster.ID())
	tarballPath := filepath.Join(os.TempDir(), mustGatherTarballName)
	tarfile, err := os.Create(tarballPath) // #nosec G304 -- tarballPath is constructed from temp dir and timestamp/cluster ID
	if err != nil {
		result.Actions = []types.Action{
			executor.Note(fmt.Sprintf("CAD was unable to create a temporary file for the must gather results tar file: %v", err)),
			executor.Escalate("Failed to create tarball file"),
		}
		return result, nil
	}

	defer func() {
		err := os.Remove(tarfile.Name())
		if err != nil {
			logging.Errorf("Error cleaning up temporary file for must gather results: %v", err)
		}
	}()

	err = tarball.CreateTarball(mustGatherResultDir, tarfile)
	if err != nil {
		result.Actions = []types.Action{
			executor.Note(fmt.Sprintf("CAD was unable to create a tar file for the must gather results: %v", err)),
			executor.Escalate("Failed to create tarball"),
		}
		return result, nil
	}

	err = tarfile.Close()
	if err != nil {
		logging.Warnf("CAD was unable to close the must-gather tar file descriptor: %v\n Attempting to proceed anyway...", err)
	}

	// Get SFTP credentials with a reasonable timeout for the HTTP request
	credCtx, credCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer credCancel()
	username, token, err := getAnonymousSftpCredentials(credCtx, http.DefaultClient)
	if err != nil {
		return result, investigation.WrapInfrastructure(
			fmt.Errorf("CAD was unable to get the Red Hat sftp server credentials: %w", err),
			"failure retrieving sftp credentials")
	}

	logging.Infof("anonymous SFTP username: %s", username)

	// Upload with extended timeout - during testing, uploading to the SFTP server was very slow at 10 MB/min
	// FIXME: As in improvement, CAD could use its own service account to upload to the SFTP server.
	uploadCtx, uploadCancel := context.WithTimeout(context.Background(), time.Hour*6)
	defer uploadCancel()
	err = sftpUpload(uploadCtx, tarfile.Name(), username, token)
	if err != nil {
		return result, investigation.WrapInfrastructure(
			fmt.Errorf("CAD was unable to upload to the Red Hat sftp server: %w", err),
			"sftp upload failed")
	}

	r.Notes.AppendAutomation("CAD collected a must-gather and uploaded it to the Red Hat SFTP server under /anonymous/users/%s/%s", username, path.Base(tarfile.Name()))
	result.MustGatherPerformed = investigation.InvestigationStep{Performed: true, Labels: []string{productName}}
	result.Actions = []types.Action{
		executor.NoteFrom(r.Notes),
	}
	return result, nil
}

func (c *Investigation) Name() string {
	return "mustgather"
}

func (c *Investigation) AlertTitle() string { return "CreateMustGather" }

func (c *Investigation) Description() string {
	return "creates a must gather for a cluster"
}

func (c *Investigation) IsExperimental() bool {
	// TODO: Update to false when graduating to production.
	return true
}

// waitForMustGatherNamespaceDeletion waits for any existing openshift-must-gather-* namespace to be deleted
// from the management cluster. This ensures that a previous must-gather job has completed before starting a new one.
// Returns an error if the namespace still exists after the timeout period.
func waitForMustGatherNamespaceDeletion(ctx context.Context, k8sClient client.Client, timeout time.Duration, pollInterval time.Duration) error {
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	timeoutCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	for {
		select {
		case <-timeoutCtx.Done():
			return fmt.Errorf("timeout waiting for must-gather namespace to be deleted after %v", timeout)
		case <-ticker.C:
			namespaceList := &corev1.NamespaceList{}
			err := k8sClient.List(ctx, namespaceList, &client.ListOptions{})
			if err != nil {
				return fmt.Errorf("failed to list namespaces on management cluster: %w", err)
			}

			var mustGatherNamespaceFound bool
			var foundNamespaceName string
			for _, ns := range namespaceList.Items {
				// Check if namespace starts with prefix and is not the permanent operator namespace
				if strings.HasPrefix(ns.Name, mustGatherNamespacePrefix) && ns.Name != mustGatherOperatorNamespace {
					mustGatherNamespaceFound = true
					foundNamespaceName = ns.Name
					break
				}
			}

			if !mustGatherNamespaceFound {
				logging.Info("No must-gather namespace found on management cluster, proceeding with must-gather")
				return nil
			}

			logging.Infof("Must-gather namespace %s still exists on management cluster, waiting for deletion...", foundNamespaceName)
		}
	}
}

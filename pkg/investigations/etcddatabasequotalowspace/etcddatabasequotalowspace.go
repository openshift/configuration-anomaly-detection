// Package etcddatabasequotalowspace takes etcd snapshots for non-HCP clusters for analysis
package etcddatabasequotalowspace

import (
	"bytes"
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	cmv1 "github.com/openshift-online/ocm-sdk-go/clustersmgmt/v1"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/investigation"
	k8sclient "github.com/openshift/configuration-anomaly-detection/pkg/k8s"
	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
)

type Investigation struct{}

// SnapshotResult contains information about the etcd snapshot that was taken
type SnapshotResult struct {
	PodName      string
	NodeName     string
	SnapshotPath string
	SnapshotSize int64
	Namespace    string
}

func (i *Investigation) Run(rb investigation.ResourceBuilder) (investigation.InvestigationResult, error) {
	ctx := context.Background()
	result := investigation.InvestigationResult{}

	r, err := rb.
		WithCluster().
		WithK8sClient().
		WithNotes().
		Build()
	if err != nil {
		return result, err
	}

	// Check if cluster is HCP - skip if it is
	isHCP, err := isHCPCluster(r.Cluster)
	if err != nil {
		r.Notes.AppendWarning("Failed to determine if cluster is HCP: %v", err)
		logging.Warnf("failed to check if cluster is HCP: %v", err)
		return result, r.PdClient.EscalateIncidentWithNote(r.Notes.String())
	}
	if isHCP {
		r.Notes.AppendWarning("Cluster is HCP - skipping snapshot")
		logging.Info("skipping etcd snapshot for HCP cluster")
		return result, r.PdClient.EscalateIncidentWithNote(r.Notes.String())
	}

	r.Notes.AppendSuccess("Cluster is non-HCP, proceeding with etcd snapshot")

	// Find etcd pod and take snapshot
	snapshotResult, err := takeEtcdSnapshot(ctx, r.K8sClient)
	if err != nil {
		r.Notes.AppendWarning("Failed to take etcd snapshot: %v", err)
		logging.Errorf("failed to take etcd snapshot: %v", err)
		return result, r.PdClient.EscalateIncidentWithNote(r.Notes.String())
	}

	r.Notes.AppendSuccess("Successfully took etcd snapshot from pod %s", snapshotResult.PodName)
	r.Notes.AppendSuccess("Snapshot Details:\n  - Pod: %s\n  - Node: %s\n  - Namespace: %s\n  - Size: %.2f MB\n  - Node Path: %s",
		snapshotResult.PodName,
		snapshotResult.NodeName,
		snapshotResult.Namespace,
		float64(snapshotResult.SnapshotSize)/(1024*1024),
		snapshotResult.SnapshotPath)
	r.Notes.AppendAutomation("Snapshot saved to node filesystem at: %s", snapshotResult.SnapshotPath)
	r.Notes.AppendAutomation("Node name saved for Phase 2 job scheduling: %s", snapshotResult.NodeName)
	r.Notes.AppendAutomation("Phase 2 will analyze this snapshot using Kubernetes Job with octosql-etcd image and hostPath mount")

	logging.Infof("etcd snapshot taken successfully from pod %s on node %s", snapshotResult.PodName, snapshotResult.NodeName)

	return result, r.PdClient.EscalateIncidentWithNote(r.Notes.String())
}

func (i *Investigation) Name() string {
	return "etcddatabasequotalowspace"
}

func (i *Investigation) AlertTitle() string {
	return "etcdDatabaseQuotaLowSpace CRITICAL (1)"
}

func (i *Investigation) Description() string {
	return "Takes etcd snapshots for non-HCP clusters for analysis"
}

func (i *Investigation) IsExperimental() bool {
	return true
}

// isHCPCluster checks if the cluster is a Hosted Control Plane (HCP) cluster
func isHCPCluster(cluster *cmv1.Cluster) (bool, error) {
	hypershift, ok := cluster.GetHypershift()
	if !ok {
		// No hypershift configuration means it's not HCP
		return false, nil
	}

	enabled, ok := hypershift.GetEnabled()
	if !ok {
		// Hypershift exists but enabled flag not set
		return false, nil
	}

	return enabled, nil
}

// takeEtcdSnapshot finds an etcd pod and takes a snapshot
func takeEtcdSnapshot(ctx context.Context, k8sClient k8sclient.Client) (*SnapshotResult, error) {
	const etcdNamespace = "openshift-etcd"

	// List etcd pods (use k8s-app=etcd to avoid matching etcd-guard pods)
	podList := &corev1.PodList{}
	err := k8sClient.List(ctx, podList,
		client.InNamespace(etcdNamespace),
		client.MatchingLabels{"k8s-app": "etcd"},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to list etcd pods: %w", err)
	}

	if len(podList.Items) == 0 {
		return nil, fmt.Errorf("no etcd pods found in namespace %s", etcdNamespace)
	}

	// Select first running pod
	var selectedPod *corev1.Pod
	for i := range podList.Items {
		pod := &podList.Items[i]
		if pod.Status.Phase == corev1.PodRunning {
			selectedPod = pod
			break
		}
	}

	if selectedPod == nil {
		return nil, fmt.Errorf("no running etcd pods found in namespace %s", etcdNamespace)
	}

	logging.Infof("selected etcd pod %s on node %s", selectedPod.Name, selectedPod.Spec.NodeName)

	// Take snapshot and save it to the node
	snapshotPath, snapshotSize, err := execSnapshotCommands(ctx, k8sClient, selectedPod)
	if err != nil {
		return nil, fmt.Errorf("failed to execute snapshot commands: %w", err)
	}

	return &SnapshotResult{
		PodName:      selectedPod.Name,
		NodeName:     selectedPod.Spec.NodeName,
		SnapshotPath: snapshotPath,
		SnapshotSize: snapshotSize,
		Namespace:    etcdNamespace,
	}, nil
}

// execSnapshotCommands executes the commands to take etcd snapshot and save it to the node
func execSnapshotCommands(ctx context.Context, k8sClient k8sclient.Client, pod *corev1.Pod) (string, int64, error) {
	// Get the REST config for exec operations
	restConfig, err := k8sclient.GetRestConfig(k8sClient)
	if err != nil {
		return "", 0, fmt.Errorf("failed to get REST config: %w", err)
	}

	// Define the snapshot path on the node's filesystem
	// etcd pod has /var/lib/etcd mounted from the node, which is writable
	// This will be accessible via hostPath mount in Phase 2 Job
	snapshotPath := "/var/lib/etcd/etcd.snapshot"

	// Step 1: Take snapshot and save directly to node's filesystem
	logging.Info("taking etcd snapshot and saving to node...")
	takeSnapshotCmd := []string{
		"/bin/sh", "-c",
		fmt.Sprintf("unset ETCDCTL_ENDPOINTS; etcdctl snapshot save %s", snapshotPath),
	}

	_, err = k8sclient.ExecInPod(ctx, restConfig, pod, "etcdctl", takeSnapshotCmd)
	if err != nil {
		return "", 0, fmt.Errorf("failed to take snapshot: %w", err)
	}

	// Step 2: Get the snapshot file size
	logging.Info("checking snapshot size...")
	statCmd := []string{
		"/usr/bin/stat", "-c", "%s", snapshotPath,
	}

	output, err := k8sclient.ExecInPod(ctx, restConfig, pod, "etcdctl", statCmd)
	if err != nil {
		return "", 0, fmt.Errorf("failed to get snapshot size: %w", err)
	}

	// Parse the file size
	sizeStr := string(bytes.TrimSpace(output))
	var snapshotSize int64
	_, err = fmt.Sscanf(sizeStr, "%d", &snapshotSize)
	if err != nil {
		return "", 0, fmt.Errorf("failed to parse snapshot size: %w", err)
	}

	logging.Infof("snapshot saved to %s on node (%.2f MB)", snapshotPath, float64(snapshotSize)/(1024*1024))

	// TODO: Delete this cleanup step when work is started for Phase 2
	// Phase 2 will need the snapshot to remain on the node for Job analysis
	logging.Info("cleaning up snapshot from node...")
	cleanupCmd := []string{
		"/bin/rm", "-f", snapshotPath,
	}
	_, err = k8sclient.ExecInPod(ctx, restConfig, pod, "etcdctl", cleanupCmd)
	if err != nil {
		logging.Warnf("failed to clean up snapshot from node (non-fatal): %v", err)
	} else {
		logging.Infof("snapshot cleaned up from node: %s", snapshotPath)
	}

	return snapshotPath, snapshotSize, nil
}

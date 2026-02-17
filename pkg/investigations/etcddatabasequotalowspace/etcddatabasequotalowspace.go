// Package etcddatabasequotalowspace takes etcd snapshots for non-HCP clusters for analysis
package etcddatabasequotalowspace

import (
	"context"
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	cmv1 "github.com/openshift-online/ocm-sdk-go/clustersmgmt/v1"
	"github.com/openshift/configuration-anomaly-detection/pkg/executor"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/investigation"
	k8sclient "github.com/openshift/configuration-anomaly-detection/pkg/k8s"
	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
	"github.com/openshift/configuration-anomaly-detection/pkg/metrics"
	"github.com/openshift/configuration-anomaly-detection/pkg/notewriter"
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
	ctx := context.TODO()
	result := investigation.InvestigationResult{}

	r, err := rb.
		WithCluster().
		WithK8sClient().
		WithNotes().
		Build()
	if err != nil {
		return result, err
	}

	isHCP, err := isHCPCluster(r.Cluster)
	if err != nil {
		r.Notes.AppendWarning("Failed to determine if cluster is HCP: %v", err)
		logging.Warnf("failed to check if cluster is HCP: %v", err)
		result.EtcdDatabaseAnalysis = investigation.InvestigationStep{
			Performed: true,
			Labels:    []string{"failure", "hcp_check_failed"},
		}
		result.Actions = append(
			executor.NoteAndReportFrom(r.Notes, r.Cluster.ID(), i.Name()),
			executor.Escalate("Failed to determine cluster type - manual investigation required"),
		)
		return result, nil
	}
	if isHCP {
		r.Notes.AppendWarning("Cluster is HCP - skipping snapshot")
		logging.Info("skipping etcd snapshot for HCP cluster")
		result.Actions = append(
			executor.NoteAndReportFrom(r.Notes, r.Cluster.ID(), i.Name()),
			executor.Escalate("HCP cluster - manual investigation required"),
		)
		return result, nil
	}

	r.Notes.AppendSuccess("Cluster is non-HCP, proceeding with etcd snapshot")

	snapshotResult, err := takeEtcdSnapshot(ctx, r.K8sClient)
	if err != nil {
		if investigation.IsInfrastructureError(err) {
			return result, err
		}
		r.Notes.AppendWarning("Failed to take etcd snapshot: %v", err)
		logging.Errorf("failed to take etcd snapshot: %v", err)
		result.EtcdDatabaseAnalysis = investigation.InvestigationStep{
			Performed: true,
			Labels:    []string{"failure", "snapshot_failed"},
		}
		result.Actions = append(
			executor.NoteAndReportFrom(r.Notes, r.Cluster.ID(), i.Name()),
			executor.Escalate("Failed to take etcd snapshot - manual investigation required"),
		)
		return result, nil
	}

	r.Notes.AppendSuccess("Successfully took etcd snapshot from pod %s", snapshotResult.PodName)
	r.Notes.AppendSuccess("Snapshot Details:\n  - Pod: %s\n  - Node: %s\n  - Namespace: %s\n  - Size: %.2f MB\n  - Node Path: %s",
		snapshotResult.PodName,
		snapshotResult.NodeName,
		snapshotResult.Namespace,
		float64(snapshotResult.SnapshotSize)/(1024*1024),
		snapshotResult.SnapshotPath)

	logging.Infof("etcd snapshot taken successfully from pod %s on node %s", snapshotResult.PodName, snapshotResult.NodeName)

	defer handleSnapshotCleanup(ctx, r.K8sClient, r.Notes, snapshotResult)

	timestamp := extractTimestampFromPath(snapshotResult.SnapshotPath)

	job, err := createAnalysisJob(ctx, r.K8sClient, snapshotResult.NodeName, snapshotResult.SnapshotPath, timestamp)
	if err != nil {
		if investigation.IsInfrastructureError(err) {
			return result, err
		}
		r.Notes.AppendWarning("Failed to create analysis job: %v", err)
		logging.Errorf("failed to create analysis job: %v", err)
		result.EtcdDatabaseAnalysis = investigation.InvestigationStep{
			Performed: true,
			Labels:    []string{"failure", "analysis_job_failed"},
		}
		result.Actions = append(
			executor.NoteAndReportFrom(r.Notes, r.Cluster.ID(), i.Name()),
			executor.Escalate("Failed to create analysis job - manual investigation required"),
		)
		return result, nil
	}

	r.Notes.AppendAutomation("Created analysis job: %s (will auto-delete after 10 minutes)", job.Name)

	err = waitForJobCompletion(ctx, r.K8sClient, job.Name, analysisJobTimeout)
	if err != nil {
		if investigation.IsInfrastructureError(err) {
			return result, err
		}
		r.Notes.AppendWarning("Analysis job failed or timed out: %v", err)
		logging.Errorf("analysis job failed: %v", err)
		result.EtcdDatabaseAnalysis = investigation.InvestigationStep{
			Performed: true,
			Labels:    []string{"failure", "analysis_job_failed"},
		}
		result.Actions = append(
			executor.NoteAndReportFrom(r.Notes, r.Cluster.ID(), i.Name()),
			executor.Escalate("Analysis job failed or timed out - manual investigation required"),
		)
		return result, nil
	}

	r.Notes.AppendSuccess("Analysis job completed successfully")

	logs, err := getJobLogs(ctx, r.K8sClient, job.Name)
	if err != nil {
		if investigation.IsInfrastructureError(err) {
			return result, err
		}
		r.Notes.AppendWarning("Failed to retrieve analysis results: %v", err)
		logging.Errorf("failed to get job logs: %v", err)
		result.EtcdDatabaseAnalysis = investigation.InvestigationStep{
			Performed: true,
			Labels:    []string{"failure", "parse_failed"},
		}
		result.Actions = append(
			executor.NoteAndReportFrom(r.Notes, r.Cluster.ID(), i.Name()),
			executor.Escalate("Failed to retrieve analysis results - manual investigation required"),
		)
		return result, nil
	}

	analysisResult, err := parseAnalysisOutput(logs)
	if err != nil {
		r.Notes.AppendWarning("Failed to parse analysis results: %v", err)
		logging.Errorf("failed to parse analysis output: %v", err)
		result.EtcdDatabaseAnalysis = investigation.InvestigationStep{
			Performed: true,
			Labels:    []string{"failure", "parse_failed"},
		}
		result.Actions = append(
			executor.NoteAndReportFrom(r.Notes, r.Cluster.ID(), i.Name()),
			executor.Escalate("Failed to parse analysis results - manual investigation required"),
		)
		return result, nil
	}

	formattedResults := formatAnalysisResults(analysisResult)

	logging.Info("etcd snapshot analysis completed successfully")

	// Create backplane report action
	backplaneReportAction := &executor.BackplaneReportAction{
		ClusterID: r.Cluster.ExternalID(),
		Summary:   "CAD Investigation: Analysis of etcd storage utilization",
		Data:      formattedResults,
	}

	result.EtcdDatabaseAnalysis = investigation.InvestigationStep{
		Performed: true,
		Labels:    []string{"success", "completed"},
	}

	// Add the backplane report action and note/escalation to the result
	// The report action will append to notes when executed, then note sends them to PagerDuty
	result.Actions = append(
		executor.NoteAndReportFrom(r.Notes, r.Cluster.ID(), i.Name()),
		backplaneReportAction, // write a second report here, as this contains the formatted results
		executor.Escalate("etcd analysis complete - see report for details"),
	)

	return result, nil
}

func (i *Investigation) Name() string {
	return "etcddatabasequotalowspace"
}

func (i *Investigation) AlertTitle() string {
	return "etcdDatabaseQuotaLowSpace"
}

func (i *Investigation) Description() string {
	return "Takes etcd snapshots for non-HCP clusters for analysis"
}

func (i *Investigation) IsExperimental() bool {
	return false
}

// isHCPCluster checks if the cluster is a Hosted Control Plane (HCP) cluster
func isHCPCluster(cluster *cmv1.Cluster) (bool, error) {
	hypershift, ok := cluster.GetHypershift()
	if !ok {
		return false, nil
	}

	enabled, ok := hypershift.GetEnabled()
	if !ok {
		return false, nil
	}

	return enabled, nil
}

// takeEtcdSnapshot finds an etcd pod and takes a snapshot
func takeEtcdSnapshot(ctx context.Context, k8sClient k8sclient.Client) (*SnapshotResult, error) {
	const etcdNamespace = "openshift-etcd"

	podList := &corev1.PodList{}
	err := k8sClient.List(ctx, podList,
		client.InNamespace(etcdNamespace),
		client.MatchingLabels{"k8s-app": "etcd"},
	)
	if err != nil {
		return nil, investigation.WrapInfrastructure(
			fmt.Errorf("failed to list etcd pods: %w", err),
			"K8s API failure listing etcd pods")
	}

	if len(podList.Items) == 0 {
		return nil, fmt.Errorf("no etcd pods found in namespace %s", etcdNamespace)
	}

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
	restConfig, err := k8sclient.GetRestConfig(k8sClient)
	if err != nil {
		return "", 0, investigation.WrapInfrastructure(
			fmt.Errorf("failed to get REST config: %w", err),
			"K8s REST config failure")
	}

	timestamp := time.Now().Format("20060102_150405")
	snapshotPath := fmt.Sprintf("/var/lib/etcd/etcd_%s.snapshot", timestamp)

	logging.Info("taking etcd snapshot and saving to node...")
	takeSnapshotCmd := []string{
		"/bin/sh", "-c",
		fmt.Sprintf("unset ETCDCTL_ENDPOINTS; etcdctl snapshot save %s", snapshotPath),
	}

	_, err = k8sclient.ExecInPod(ctx, restConfig, pod, "etcdctl", takeSnapshotCmd)
	if err != nil {
		return "", 0, investigation.WrapInfrastructure(
			fmt.Errorf("failed to take snapshot: %w", err),
			"K8s pod exec failure taking snapshot")
	}

	logging.Info("setting snapshot file permissions...")
	chmodCmd := []string{
		"/bin/chmod", "644", snapshotPath,
	}
	_, err = k8sclient.ExecInPod(ctx, restConfig, pod, "etcdctl", chmodCmd)
	if err != nil {
		return "", 0, investigation.WrapInfrastructure(
			fmt.Errorf("failed to set snapshot permissions: %w", err),
			"K8s pod exec failure setting permissions")
	}

	logging.Info("checking snapshot size...")
	statCmd := []string{
		"/usr/bin/stat", "-c", "%s", snapshotPath,
	}

	output, err := k8sclient.ExecInPod(ctx, restConfig, pod, "etcdctl", statCmd)
	if err != nil {
		return "", 0, investigation.WrapInfrastructure(
			fmt.Errorf("failed to get snapshot size: %w", err),
			"K8s pod exec failure getting snapshot size")
	}

	sizeStr := strings.TrimSpace(output)
	var snapshotSize int64
	_, err = fmt.Sscanf(sizeStr, "%d", &snapshotSize)
	if err != nil {
		return "", 0, fmt.Errorf("failed to parse snapshot size: %w", err)
	}

	logging.Infof("snapshot saved to %s on node (%.2f MB)", snapshotPath, float64(snapshotSize)/(1024*1024))

	return snapshotPath, snapshotSize, nil
}

// extractTimestampFromPath extracts the timestamp from a snapshot path
func extractTimestampFromPath(path string) string {
	filename := path[strings.LastIndex(path, "/")+1:]
	filename = strings.TrimPrefix(filename, "etcd_")
	filename = strings.TrimSuffix(filename, ".snapshot")

	return filename
}

// handleSnapshotCleanup attempts to clean up the snapshot and adds appropriate notes
func handleSnapshotCleanup(ctx context.Context, k8sClient k8sclient.Client, notes *notewriter.NoteWriter, snapshotResult *SnapshotResult) {
	cleanupErr := cleanupSnapshot(ctx, k8sClient, snapshotResult.PodName, snapshotResult.SnapshotPath, snapshotResult.Namespace)
	if cleanupErr != nil {
		notes.AppendWarning("Failed to cleanup snapshot: %v", cleanupErr)
		notes.AppendWarning("Manual cleanup required: delete snapshot file %s from pod %s", snapshotResult.SnapshotPath, snapshotResult.PodName)
		logging.Errorf("failed to cleanup snapshot: %v", cleanupErr)
		metrics.Inc(metrics.EtcdSnapshotCleanup, "etcddatabasequotalowspace", "failure")
	} else {
		logging.Infof("snapshot cleanup completed successfully")
		metrics.Inc(metrics.EtcdSnapshotCleanup, "etcddatabasequotalowspace", "success")
	}
}

// cleanupSnapshot attempts to delete the etcd snapshot file from the node
func cleanupSnapshot(ctx context.Context, k8sClient k8sclient.Client, podName, snapshotPath, namespace string) error {
	pod := &corev1.Pod{}
	err := k8sClient.Get(ctx, client.ObjectKey{
		Name:      podName,
		Namespace: namespace,
	}, pod)
	if err != nil {
		return fmt.Errorf("failed to get etcd pod for cleanup: %w", err)
	}

	restConfig, err := k8sclient.GetRestConfig(k8sClient)
	if err != nil {
		return fmt.Errorf("failed to get REST config for cleanup: %w", err)
	}

	logging.Infof("cleaning up snapshot file: %s", snapshotPath)
	rmCmd := []string{
		"/bin/rm", "-f", snapshotPath,
	}

	_, err = k8sclient.ExecInPod(ctx, restConfig, pod, "etcdctl", rmCmd)
	if err != nil {
		return fmt.Errorf("failed to delete snapshot file: %w", err)
	}

	logging.Infof("snapshot file deleted successfully: %s", snapshotPath)
	return nil
}

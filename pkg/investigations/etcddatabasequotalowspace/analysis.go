package etcddatabasequotalowspace

import (
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/investigation"
	k8sclient "github.com/openshift/configuration-anomaly-detection/pkg/k8s"
	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
)

const (
	analysisJobNamespace = "openshift-etcd"
	analysisJobTimeout   = 5 * time.Minute
)

var octosqlImage = os.Getenv("CAD_OCTOSQL_IMAGE")

type AnalysisResult struct {
	TopNamespaces    []NamespaceSize
	LargestResources []ResourceSize
	EventSizesByNS   []NamespaceSize
}

type NamespaceSize struct {
	Namespace string
	SizeMB    float64
}

type ResourceSize struct {
	Namespace    string
	Name         string
	SizeMB       float64
	ResourceType string
}

// createAnalysisJob creates a Kubernetes Job to analyze the etcd snapshot
func createAnalysisJob(ctx context.Context, k8sClient k8sclient.Client, nodeName, snapshotPath, timestamp string) (*batchv1.Job, error) {
	jobName := fmt.Sprintf("etcd-analysis-%s", strings.ReplaceAll(timestamp, "_", "-"))

	snapshotFilename := snapshotPath[strings.LastIndex(snapshotPath, "/")+1:]

	job := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      jobName,
			Namespace: analysisJobNamespace,
			Labels: map[string]string{
				"app":       "etcd-snapshot-analysis",
				"timestamp": timestamp,
			},
		},
		Spec: batchv1.JobSpec{
			BackoffLimit:            int32Ptr(0),
			TTLSecondsAfterFinished: int32Ptr(600), // Keep job and pods for 10 minutes after completion
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					NodeSelector: map[string]string{
						"kubernetes.io/hostname": nodeName,
					},
					Tolerations: []corev1.Toleration{
						{
							Operator: corev1.TolerationOpExists,
							Effect:   corev1.TaintEffectNoSchedule,
						},
						{
							Operator: corev1.TolerationOpExists,
							Effect:   corev1.TaintEffectNoExecute,
						},
					},
					RestartPolicy: corev1.RestartPolicyNever,
					Containers: []corev1.Container{
						{
							Name:    "analyzer",
							Image:   octosqlImage,
							Command: []string{"/bin/bash", "-c"},
							Args: []string{
								fmt.Sprintf("/usr/local/bin/analyze-snapshot.sh --delete /snapshot/%s", snapshotFilename),
							},
							SecurityContext: &corev1.SecurityContext{
								Privileged: boolPtr(true), // Needed to access files with SELinux context
							},
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "etcd-data",
									MountPath: "/snapshot",
								},
							},
						},
					},
					Volumes: []corev1.Volume{
						{
							Name: "etcd-data",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: "/var/lib/etcd",
									Type: hostPathTypePtr(corev1.HostPathDirectory),
								},
							},
						},
					},
				},
			},
		},
	}

	logging.Infof("creating analysis job %s in namespace %s", jobName, analysisJobNamespace)
	err := k8sClient.Create(ctx, job)
	if err != nil {
		return nil, investigation.WrapInfrastructure(
			fmt.Errorf("failed to create analysis job: %w", err),
			"K8s API failure creating analysis job")
	}

	return job, nil
}

// waitForJobCompletion waits for the Job to complete (success or failure)
func waitForJobCompletion(ctx context.Context, k8sClient k8sclient.Client, jobName string, timeout time.Duration) error {
	logging.Infof("waiting for job %s to complete (timeout: %v)", jobName, timeout)

	deadline := time.Now().Add(timeout)
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("context cancelled while waiting for job completion")
		case <-ticker.C:
			if time.Now().After(deadline) {
				return fmt.Errorf("timeout waiting for job to complete")
			}

			job := &batchv1.Job{}
			err := k8sClient.Get(ctx, client.ObjectKey{
				Name:      jobName,
				Namespace: analysisJobNamespace,
			}, job)
			if err != nil {
				return investigation.WrapInfrastructure(
					fmt.Errorf("failed to get job status: %w", err),
					"K8s API failure getting job status")
			}

			if job.Status.Succeeded > 0 {
				logging.Infof("job %s completed successfully", jobName)
				return nil
			}

			if job.Status.Failed > 0 {
				return fmt.Errorf("job %s failed", jobName)
			}

			logging.Debugf("job %s still running (active: %d)", jobName, job.Status.Active)
		}
	}
}

// getJobLogs retrieves logs from the completed Job using the Kubernetes Logs API
func getJobLogs(ctx context.Context, k8sClient k8sclient.Client, jobName string) (string, error) {
	logging.Infof("retrieving logs from job %s", jobName)

	podList := &corev1.PodList{}
	err := k8sClient.List(ctx, podList,
		client.InNamespace(analysisJobNamespace),
		client.MatchingLabels{"job-name": jobName},
	)
	if err != nil {
		return "", investigation.WrapInfrastructure(
			fmt.Errorf("failed to list pods for job: %w", err),
			"K8s API failure listing pods for job")
	}

	if len(podList.Items) == 0 {
		return "", fmt.Errorf("no pods found for job %s", jobName)
	}

	pod := &podList.Items[0]

	restConfig, err := k8sclient.GetRestConfig(k8sClient)
	if err != nil {
		return "", investigation.WrapInfrastructure(
			fmt.Errorf("failed to get REST config: %w", err),
			"K8s REST config failure")
	}

	clientset, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		return "", investigation.WrapInfrastructure(
			fmt.Errorf("failed to create kubernetes clientset: %w", err),
			"K8s clientset creation failure")
	}

	logOptions := &corev1.PodLogOptions{
		Container: "analyzer",
	}

	req := clientset.CoreV1().Pods(analysisJobNamespace).GetLogs(pod.Name, logOptions)
	logStream, err := req.Stream(ctx)
	if err != nil {
		return "", investigation.WrapInfrastructure(
			fmt.Errorf("failed to open log stream: %w", err),
			"K8s API failure opening log stream")
	}
	defer func() {
		if closeErr := logStream.Close(); closeErr != nil {
			logging.Warnf("failed to close log stream: %v", closeErr)
		}
	}()

	buf := new(strings.Builder)
	_, err = io.Copy(buf, logStream)
	if err != nil {
		return "", fmt.Errorf("failed to read logs: %w", err)
	}

	return buf.String(), nil
}

// parseAnalysisOutput parses the CSV output from analyze-snapshot.sh
func parseAnalysisOutput(output string) (*AnalysisResult, error) {
	result := &AnalysisResult{
		TopNamespaces:    make([]NamespaceSize, 0),
		LargestResources: make([]ResourceSize, 0),
		EventSizesByNS:   make([]NamespaceSize, 0),
	}

	lines := strings.Split(output, "\n")
	currentSection := 0
	var sectionLines []string

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		switch line {
		case "namespace,total_size_megabytes":
			if len(sectionLines) > 0 && currentSection > 0 {
				processSection(result, currentSection, strings.Join(sectionLines, "\n"))
			}
			currentSection = 1
			sectionLines = []string{line}
		case "namespace,name,total_size_megabytes,resourceType":
			if len(sectionLines) > 0 && currentSection > 0 {
				processSection(result, currentSection, strings.Join(sectionLines, "\n"))
			}
			currentSection = 2
			sectionLines = []string{line}
		case "namespace,total_event_size_megabytes":
			if len(sectionLines) > 0 && currentSection > 0 {
				processSection(result, currentSection, strings.Join(sectionLines, "\n"))
			}
			currentSection = 3
			sectionLines = []string{line}
		default:
			sectionLines = append(sectionLines, line)
		}
	}

	if len(sectionLines) > 0 && currentSection > 0 {
		processSection(result, currentSection, strings.Join(sectionLines, "\n"))
	}

	return result, nil
}

// processSection processes a specific section of the analysis output
func processSection(result *AnalysisResult, sectionType int, csvData string) {
	switch sectionType {
	case 1:
		result.TopNamespaces = parseNamespaceSizes(csvData)
	case 2:
		result.LargestResources = parseResourceSizes(csvData)
	case 3:
		result.EventSizesByNS = parseNamespaceSizes(csvData)
	}
}

// parseNamespaceSizes parses CSV with namespace,total_size_megabytes format
func parseNamespaceSizes(csvData string) []NamespaceSize {
	results := make([]NamespaceSize, 0)

	reader := csv.NewReader(strings.NewReader(csvData))

	_, err := reader.Read()
	if err != nil {
		logging.Warnf("failed to read CSV header: %v", err)
		return results
	}

	for {
		record, err := reader.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			logging.Warnf("failed to read CSV record: %v", err)
			continue
		}

		if len(record) < 2 {
			continue
		}

		sizeMB, err := strconv.ParseFloat(record[1], 64)
		if err != nil {
			logging.Warnf("failed to parse size: %v", err)
			continue
		}

		results = append(results, NamespaceSize{
			Namespace: record[0],
			SizeMB:    sizeMB,
		})
	}

	return results
}

// parseResourceSizes parses CSV with namespace,name,total_size_megabytes,resourceType format
func parseResourceSizes(csvData string) []ResourceSize {
	results := make([]ResourceSize, 0)

	reader := csv.NewReader(strings.NewReader(csvData))

	_, err := reader.Read()
	if err != nil {
		logging.Warnf("failed to read CSV header: %v", err)
		return results
	}

	for {
		record, err := reader.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			logging.Warnf("failed to read CSV record: %v", err)
			continue
		}

		if len(record) < 4 {
			continue
		}

		sizeMB, err := strconv.ParseFloat(record[2], 64)
		if err != nil {
			logging.Warnf("failed to parse size: %v", err)
			continue
		}

		results = append(results, ResourceSize{
			Namespace:    record[0],
			Name:         record[1],
			SizeMB:       sizeMB,
			ResourceType: record[3],
		})
	}

	return results
}

// formatAnalysisResults formats the analysis results into human-readable text
func formatAnalysisResults(result *AnalysisResult) string {
	var builder strings.Builder

	builder.WriteString("etcd Database Space Analysis\n")
	builder.WriteString("================================\n\n")

	if len(result.TopNamespaces) > 0 {
		builder.WriteString("Top Space Consumers by Namespace:\n")
		builder.WriteString("================================\n")
		for i, ns := range result.TopNamespaces {
			builder.WriteString(fmt.Sprintf("%d. %s: %.2f MB\n", i+1, ns.Namespace, ns.SizeMB))
		}
		builder.WriteString("\n")
	}

	if len(result.LargestResources) > 0 {
		builder.WriteString("Largest ConfigMaps & Secrets:\n")
		builder.WriteString("================================\n")
		for i, res := range result.LargestResources {
			builder.WriteString(fmt.Sprintf("%d. %s/%s: %.2f MB (%s)\n",
				i+1, res.Namespace, res.Name, res.SizeMB, res.ResourceType))
		}
		builder.WriteString("\n")
	}

	if len(result.EventSizesByNS) > 0 {
		builder.WriteString("Event Storage by Namespace:\n")
		builder.WriteString("================================\n")
		for i, ns := range result.EventSizesByNS {
			builder.WriteString(fmt.Sprintf("%d. %s: %.2f MB\n", i+1, ns.Namespace, ns.SizeMB))
		}
		builder.WriteString("\n")
	}

	return builder.String()
}

func int32Ptr(i int32) *int32 {
	return &i
}

func boolPtr(b bool) *bool {
	return &b
}

func hostPathTypePtr(t corev1.HostPathType) *corev1.HostPathType {
	return &t
}

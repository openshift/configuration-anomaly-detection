// pruningcronjoberror remediates the PruningCronjobErrorSRE alerts
// SOP https://github.com/openshift/ops-sop/blob/master/v4/alerts/PruningCronjobErrorSRE.md


package pruningcronjoberror

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/investigation"
	k8sclient "github.com/openshift/configuration-anomaly-detection/pkg/k8s"
	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
	"github.com/openshift/configuration-anomaly-detection/pkg/notewriter"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type Investigation struct {
	// kclient provides access to on-cluster resources
	kclient client.Client
	// notes holds the messages that will be shared with Primary upon completion
	notes *notewriter.NoteWriter
	// recommendations holds the set of actions CAD recommends primary to take
	recommendations investigationRecommendations
}

func (i *Investigation) setup(r *investigation.Resources) error {
	// Setup investigation
	k, err := k8sclient.New(r.Cluster.ID(), r.OcmClient, r.Name)
	if err != nil {
		return fmt.Errorf("failed to initialize kubernetes client: %w", err)
	}
	i.kclient = k
	i.notes = notewriter.New(r.Name, logging.RawLogger)
	i.recommendations = investigationRecommendations{}

	return nil
}

func (i *Investigation) Run(r *investigation.Resources) (investigation.InvestigationResult, error) {
	result := investigation.InvestigationResult{}
	
	// Initialize k8s client
	k8scli, err := k8sclient.New(r.Cluster.ID(), r.OcmClient, r.Name)
	if err != nil {
		return result, fmt.Errorf("unable to initialize k8s cli: %w", err)
	}
	defer func() {
		if k8scli, ok := k8scli.(interface{ Clean() error }); ok {
			deferErr := k8scli.Clean()
			if deferErr != nil {
				logging.Error(deferErr)
				err = errors.Join(err, deferErr)
			}
		}
	}()

	// Execute the remediation decision tree
	err = i.executeRemediationSteps(k8scli, r)
	if err != nil {
		i.notes.AppendWarning(fmt.Sprintf("Error during remediation: %v", err))
	}

	// Summarize recommendations from investigation in PD notes, if any found
	if len(i.recommendations) > 0 {
		i.notes.AppendWarning(i.recommendations.summarize())
	} else {
		i.notes.AppendSuccess("no recommended actions to take against cluster")
	}

	return result, r.PdClient.EscalateIncidentWithNote(i.notes.String())
}


// FilterLines filters the input string line by line, returning only the lines that contain the filter.
func FilterLines(input string, filter string) (string, error) {
	var filteredLines strings.Builder
	reader := strings.NewReader(input)
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, filter) {
			filteredLines.WriteString(line)
			filteredLines.WriteString("\n") // Add newline to preserve original line breaks
		}
	}
	// Check for any errors that occurred during scanning.
	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("error reading input: %w", err)
	}
	return filteredLines.String(), nil
}

// ExecuteCommand executes a shell command and returns the output.
func ExecuteCommand(command string, args ...string) (string, error) {
	cmd := exec.Command(command, args...)
	output, err := cmd.CombinedOutput() // Get both stdout and stderr
	if err != nil {
		return "", fmt.Errorf("error executing command: %w, output: %s", err, output)
	}
	return string(output), nil
}

type investigationRecommendations []string

func (r investigationRecommendations) summarize() string {
	return strings.Join(r, "; ")
}

// addRecommendation adds a recommendation to the investigation
func (i *Investigation) addRecommendation(recommendation string) {
	i.recommendations = append(i.recommendations, recommendation)
}

// executeRemediationSteps runs through the decision tree for remediation
func (i *Investigation) executeRemediationSteps(k8scli client.Client, r *investigation.Resources) error {
	// Step 1: Check for Seccomp Error 524
	isSeccompError, err := i.checkSeccompError524(k8scli)
	if err != nil {
		return fmt.Errorf("failed to check seccomp error: %w", err)
	}

	if isSeccompError {
		i.notes.AppendWarning("Seccomp Error 524 detected. Recommendation: Send a Servicelog and either drain and reboot or replace the node.")
		i.addRecommendation("Send Servicelog for Seccomp Error 524")
		i.addRecommendation("Drain and reboot or replace the affected node")
		return nil
	}

	// Step 2: Check for ImagePullBackOff pods
	hasImagePullBackOff, err := i.checkImagePullBackOffPods(k8scli)
	if err != nil {
		return fmt.Errorf("failed to check ImagePullBackOff pods: %w", err)
	}

	if hasImagePullBackOff {
		i.notes.AppendWarning("Pods in ImagePullBackOff state detected. Recommendation: Check pull secret validity and cluster-image-operator logs.")
		i.addRecommendation("Check whether the pull secret is valid")
		i.addRecommendation("Check cluster-image-operator logs for errors")
		return nil
	}

	// Step 3: Check for ResourceQuota issues
	isResourceQuota, err := i.checkResourceQuotaIssues(k8scli)
	if err != nil {
		return fmt.Errorf("failed to check ResourceQuota issues: %w", err)
	}

	if isResourceQuota {
		i.notes.AppendWarning("ResourceQuota issue detected. Recommendation: Send a Servicelog.")
		i.addRecommendation("Send Servicelog for ResourceQuota issue")
		return nil
	}

	// Step 4: Check for OVN issues
	isOVNIssue, err := i.checkOVNIssues(k8scli)
	if err != nil {
		return fmt.Errorf("failed to check OVN issues: %w", err)
	}

	if isOVNIssue {
		i.notes.AppendWarning("OVN issue detected. Recommendation: Restart the OVN masters.")
		i.addRecommendation("Restart OVN masters: oc delete po -n openshift-ovn-kubernetes -l app=ovnkube-master")
		return nil
	}

	// Step 5: Fallback - output errors and restart command
	errors, restartCommand := i.getErrorsAndRestartCommand(k8scli)
	i.notes.AppendWarning(fmt.Sprintf("No specific issue detected. Errors found: %s", errors))
	i.notes.AppendSuccess(fmt.Sprintf("Restart command: %s", restartCommand))
	i.addRecommendation("Review the errors and execute the restart command if appropriate")

	return nil
}

// checkSeccompError524 checks if there's a seccomp error 524 in the pruning pods
func (i *Investigation) checkSeccompError524(k8scli client.Client) (bool, error) {
	prunerPods := &corev1.PodList{}
	err := k8scli.List(context.TODO(), prunerPods, client.InNamespace("openshift-sre-pruning"))
	if err != nil {
		return false, fmt.Errorf("failed to list pods in openshift-sre-pruning namespace: %w", err)
	}

	for _, pod := range prunerPods.Items {
		// Check pod events for seccomp error
		for _, condition := range pod.Status.Conditions {
			if strings.Contains(condition.Message, "seccomp filter: errno 524") {
				return true, nil
			}
		}

		// Check container statuses for seccomp error
		for _, containerStatus := range pod.Status.ContainerStatuses {
			if containerStatus.State.Waiting != nil &&
				strings.Contains(containerStatus.State.Waiting.Message, "seccomp filter: errno 524") {
				return true, nil
			}
			if containerStatus.State.Terminated != nil &&
				strings.Contains(containerStatus.State.Terminated.Message, "seccomp filter: errno 524") {
				return true, nil
			}
		}
	}

	return false, nil
}

// checkImagePullBackOffPods checks if there are pods in ImagePullBackOff state
func (i *Investigation) checkImagePullBackOffPods(k8scli client.Client) (bool, error) {
	prunerPods := &corev1.PodList{}
	err := k8scli.List(context.TODO(), prunerPods, client.InNamespace("openshift-sre-pruning"))
	if err != nil {
		return false, fmt.Errorf("failed to list pods in openshift-sre-pruning namespace: %w", err)
	}

	for _, pod := range prunerPods.Items {
		if pod.Status.Phase == corev1.PodPending {
			for _, containerStatus := range pod.Status.ContainerStatuses {
				if containerStatus.State.Waiting != nil &&
					containerStatus.State.Waiting.Reason == "ImagePullBackOff" {
					return true, nil
				}
			}
		}
	}

	return false, nil
}

// checkResourceQuotaIssues checks if there are ResourceQuota issues preventing pod creation
func (i *Investigation) checkResourceQuotaIssues(k8scli client.Client) (bool, error) {
	jobs := &batchv1.JobList{}
	err := k8scli.List(context.TODO(), jobs, client.InNamespace("openshift-sre-pruning"))
	if err != nil {
		return false, fmt.Errorf("failed to list jobs in openshift-sre-pruning namespace: %w", err)
	}

	for _, job := range jobs.Items {
		for _, condition := range job.Status.Conditions {
			if condition.Type == batchv1.JobFailed &&
				strings.Contains(condition.Message, "quota") {
				return true, nil
			}
		}
	}

	// Also check events in the namespace for quota-related failures
	events := &corev1.EventList{}
	err = k8scli.List(context.TODO(), events, client.InNamespace("openshift-sre-pruning"))
	if err != nil {
		return false, fmt.Errorf("failed to list events in openshift-sre-pruning namespace: %w", err)
	}

	for _, event := range events.Items {
		if strings.Contains(event.Message, "quota") ||
			strings.Contains(event.Message, "ResourceQuota") {
			return true, nil
		}
	}

	return false, nil
}

// checkOVNIssues checks if there are OVN-related issues
func (i *Investigation) checkOVNIssues(k8scli client.Client) (bool, error) {
	prunerPods := &corev1.PodList{}
	err := k8scli.List(context.TODO(), prunerPods, client.InNamespace("openshift-sre-pruning"))
	if err != nil {
		return false, fmt.Errorf("failed to list pods in openshift-sre-pruning namespace: %w", err)
	}

	for _, pod := range prunerPods.Items {
		for _, condition := range pod.Status.Conditions {
			if strings.Contains(condition.Message, "context deadline exceeded while waiting for annotations") ||
				strings.Contains(condition.Message, "failed to create pod network sandbox") ||
				strings.Contains(condition.Message, "ovn-kubernetes") {
				return true, nil
			}
		}
	}

	// Check events for OVN-related failures
	events := &corev1.EventList{}
	err = k8scli.List(context.TODO(), events, client.InNamespace("openshift-sre-pruning"))
	if err != nil {
		return false, fmt.Errorf("failed to list events in openshift-sre-pruning namespace: %w", err)
	}

	for _, event := range events.Items {
		if strings.Contains(event.Message, "ovn-kubernetes") ||
			strings.Contains(event.Message, "context deadline exceeded") {
			return true, nil
		}
	}

	return false, nil
}

// getErrorsAndRestartCommand collects errors and provides restart command
func (i *Investigation) getErrorsAndRestartCommand(k8scli client.Client) (string, string) {
	var errors []string
	var failedJobs []string

	// Get failed jobs
	jobs := &batchv1.JobList{}
	err := k8scli.List(context.TODO(), jobs, client.InNamespace("openshift-sre-pruning"))
	if err != nil {
		errors = append(errors, fmt.Sprintf("Failed to list jobs: %v", err))
	} else {
		for _, job := range jobs.Items {
			for _, condition := range job.Status.Conditions {
				if condition.Type == batchv1.JobFailed {
					errors = append(errors, fmt.Sprintf("Job %s failed: %s", job.Name, condition.Message))
					failedJobs = append(failedJobs, job.Name)
				}
			}
		}
	}

	// Get pod errors
	pods := &corev1.PodList{}
	err = k8scli.List(context.TODO(), pods, client.InNamespace("openshift-sre-pruning"))
	if err != nil {
		errors = append(errors, fmt.Sprintf("Failed to list pods: %v", err))
	} else {
		for _, pod := range pods.Items {
			if pod.Status.Phase == corev1.PodFailed {
				errors = append(errors, fmt.Sprintf("Pod %s failed: %s", pod.Name, pod.Status.Message))
			}
		}
	}

	// Generate restart command
	restartCommand := "ocm backplane managedjob create SREP/retry-failed-pruning-cronjob"
	if len(failedJobs) > 0 {
		restartCommand += fmt.Sprintf(" # This will retry failed jobs: %s", strings.Join(failedJobs, ", "))
	}

	errorSummary := "No specific errors found"
	if len(errors) > 0 {
		errorSummary = strings.Join(errors, "; ")
	}

	return errorSummary, restartCommand
}

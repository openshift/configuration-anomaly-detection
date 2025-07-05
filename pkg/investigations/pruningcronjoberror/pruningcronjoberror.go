// pruningcronjoberror remediates the PruningCronjobErrorSRE alerts
// SOP https://github.com/openshift/ops-sop/blob/master/v4/alerts/PruningCronjobErrorSRE.md


package pruningcronjoberror

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log"
	"os/exec"
	"strings"

	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/investigation"
	k8sclient "github.com/openshift/configuration-anomaly-detection/pkg/k8s"
	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
	"github.com/openshift/configuration-anomaly-detection/pkg/notewriter"
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
	// Initialize PagerDuty note writer
	notes := notewriter.New(r.Name, logging.RawLogger)

	//Step: node-exporter consuming high cpu in SDN clusters
	//Step: oc get Network.config.openshift.io cluster -o json | jq '.spec.networkType'
	network := r.Cluster.Network().Type()
	fmt.Println("network variable: %v", network)

	// Initialize k8s client
	k8scli, err := k8sclient.New(r.Cluster.ID(), r.OcmClient, r.Name)
	if err != nil {
		return result, fmt.Errorf("unable to initialize k8s cli: %w", err)
	}
	defer func() {
		deferErr := k8sclient.Cleanup(r.Cluster.ID(), r.OcmClient, r.Name)
		if deferErr != nil {
			logging.Error(deferErr)
			err = errors.Join(err, deferErr)
		}
	}()
	//"OpenshiftSDN" means it is a SDN cluster and may impact by this issue.
	//Check if node-exporter pods are taking up high CPU
	//oc adm top pod -n openshift-monitoring | grep node-exporter
	if network != "OVNKubernetes" && network == "OpenshiftSDN" {
		// TODO: Fetch pod metrics in the "openshift-monitoring" namespace
		notes.AppendWarning("non-OVN network detected, please check cpu consumption on node-exporter pods. SOP: https://github.com/openshift/ops-sop/blob/master/v4/alerts/PruningCronjobErrorSRE.md", err)
	}
	// Check CPU consumption on node-exporter pods
	//Usually a node-exporter pod consumes less than 20m CPU. If you see a node-exporter pod is consuming higher than 100m, it likely hits this issue.

	output, err := ExecuteCommand("oc", "adm", "top", "pod", "-n", "openshift-monitoring")
	if err != nil {
		log.Fatalf("Failed to execute oc command: %v", err)
	}

	// Filter the output using `grep node-exporter`.
	filteredOutput, err := FilterLines(output, "node-exporter")
	if err != nil {
		log.Fatalf("Failed to filter output: %v", err)
	}

	prunerPods := &corev1.PodList{}

	err = k8scli.List(context.TODO(), prunerPods, client.InNamespace("openshift-sre-pruning"))

	fmt.Println("Hello World")

	// Iterate through the pods and print their .status.containerStatuses
	for _, pod := range prunerPods.Items {
		fmt.Printf("Pod Name: %s\n", pod.Name)
		for _, containerStatus := range pod.Status.ContainerStatuses {
			fmt.Printf("Container Name: %v, Ready: %v, ContainerStatus State: %v",
				containerStatus.Name, containerStatus.Ready, containerStatus.State)

			// Convert ContainerStatus to text
			containerText := fmt.Sprintf("Container Name: %v, Ready: %v, Restart Count: %v, Image: %v, State: %v", containerStatus.Name,
				containerStatus.Ready, containerStatus.RestartCount, containerStatus.Image, containerStatus.State)

			if strings.Contains(containerText, "seccomp filter: errno 524") {
				fmt.Println("Text contains the seccomp filter: errno 524")
			} else {
				fmt.Println("Text does not contain the seccomp filter: errno 524")
			}
		}
	}

	// Print the filtered output.
	fmt.Print(filteredOutput)

	// Summarize recommendations from investigation in PD notes, if any found
	if len(i.recommendations) > 0 {
		i.notes.AppendWarning(i.recommendations.summarize())
	} else {
		i.notes.AppendSuccess("no recommended actions to take against cluster")
	}
	if err != nil {
		notes.AppendWarning("Error listing pods in openshift-sre-pruning namespace: %v\n", err)
	}

	// want to look at the status condition when it is ContainerCreateFailed
	//.status.containerStatuses

	notes.AppendSuccess("This is a test")


	
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

	//Step: Known issue Seccomp error 524
	//https://github.com/openshift/ops-sop/blob/master/v4/alerts/PruningCronjobErrorSRE.md#seccomp-error-524
	//oc describe pod ${POD} -n openshift-sre-pruning
	

	


// func (i *Investigation) Name() string {
// 	return "pruningcronjoberror"
// }
// func (i *Investigation) Description() string {
// 	return "Steps through PruningCronjobError SOP"
// }

// func (i *Investigation) ShouldInvestigateAlert(alert string) bool {
// 	return strings.Contains(alert, "PruningCronjobErrorSRE")
// }

// func (i *Investigation) IsExperimental() bool {
// 	return false
// }

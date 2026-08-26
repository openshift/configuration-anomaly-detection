// Package alertmanager provides shared utilities for querying firing alerts
// from a cluster's Alertmanager via pod exec.
package alertmanager

import (
	"context"
	"encoding/json"
	"fmt"

	k8sclient "github.com/openshift/configuration-anomaly-detection/pkg/k8s"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// FiringAlert represents a single alert that is currently firing on a cluster.
type FiringAlert struct {
	Name     string
	Severity string
	State    string
	Summary  string
}

type alertmanagerAlert struct {
	Labels      map[string]string       `json:"labels"`
	Annotations map[string]string       `json:"annotations"`
	Status      alertmanagerAlertStatus `json:"status"`
}

type alertmanagerAlertStatus struct {
	State string `json:"state"`
}

// FetchFiringAlerts queries the Alertmanager API on the cluster via pod exec
// and returns all currently firing alerts. It finds a running Alertmanager pod
// in the openshift-monitoring namespace, execs wget to query the API, and
// parses the JSON response.
func FetchFiringAlerts(ctx context.Context, k8sClient client.Client, restConfig *rest.Config) ([]FiringAlert, error) {
	podList := &corev1.PodList{}
	err := k8sClient.List(ctx, podList,
		client.InNamespace("openshift-monitoring"),
		client.MatchingLabels{"app.kubernetes.io/name": "alertmanager"},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to list alertmanager pods: %w", err)
	}

	var amPod *corev1.Pod
	for idx := range podList.Items {
		if podList.Items[idx].Status.Phase == corev1.PodRunning {
			amPod = &podList.Items[idx]
			break
		}
	}
	if amPod == nil {
		return nil, fmt.Errorf("no running alertmanager pods found in openshift-monitoring")
	}

	output, err := k8sclient.ExecInPod(ctx, restConfig, amPod, "alertmanager", []string{
		"wget", "-qO-", "http://localhost:9093/api/v2/alerts?active=true",
	})
	if err != nil {
		return nil, fmt.Errorf("failed to exec in alertmanager pod: %w", err)
	}

	var amAlerts []alertmanagerAlert
	if err := json.Unmarshal([]byte(output), &amAlerts); err != nil {
		return nil, fmt.Errorf("failed to decode alertmanager response: %w", err)
	}

	var firing []FiringAlert
	for _, a := range amAlerts {
		if a.Status.State == "active" || a.Status.State == "firing" {
			alert := FiringAlert{
				Name:     a.Labels["alertname"],
				Severity: a.Labels["severity"],
				State:    a.Status.State,
				Summary:  a.Annotations["summary"],
			}
			firing = append(firing, alert)
		}
	}

	return firing, nil
}

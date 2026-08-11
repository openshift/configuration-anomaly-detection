// Package restartcontrolplane implements an investigation that restarts an HCP control plane.
package restartcontrolplane

import (
	"context"
	"fmt"
	"time"

	"github.com/openshift/configuration-anomaly-detection/pkg/executor"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/investigation"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
)

type Investigation struct{}

func (c *Investigation) Run(rb investigation.ResourceBuilder) (investigation.InvestigationResult, error) {
	result := investigation.InvestigationResult{}

	ctx := context.Background()

	r, err := rb.WithCluster().WithManagementK8sClient().WithNotes().Build()
	if err != nil {
		return result, err
	}

	// report and exit if the cluster isn't an HCP cluster
	if !r.IsHCP {
		r.Notes.AppendSuccess("Cluster is not an HCP cluster, skipping control plane restart")
		result.Actions = append(
			executor.NoteAndReportFrom(r.Notes, r.Cluster.ID(), c.Name()),
			executor.Silence("Control plane restart only applies to HCP clusters"),
		)
		return result, nil
	}

	hcNamespace := r.HCNamespace

	// Create unstructured HostedCluster object
	hc := &unstructured.Unstructured{}
	hc.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   "hypershift.openshift.io",
		Version: "v1beta1",
		Kind:    "HostedCluster",
	})

	// Get the HostedCluster
	err = r.ManagementK8sClient.Get(ctx, types.NamespacedName{
		Namespace: hcNamespace,
		Name:      r.Cluster.DomainPrefix(),
	}, hc)
	if err != nil {
		return result, investigation.WrapInfrastructure(
			fmt.Errorf("failed to get HostedCluster: %w", err),
			"Restarting Control Plane failed")
	}

	// Get annotations or initialize if nil
	annotations := hc.GetAnnotations()
	if annotations == nil {
		annotations = make(map[string]string)
	}

	// Add the annotation
	annotations["hypershift.openshift.io/restart-date"] = time.Now().UTC().Format(time.RFC3339)
	hc.SetAnnotations(annotations)

	// Update the HostedCluster
	err = r.ManagementK8sClient.Update(ctx, hc)
	if err != nil {
		return result, investigation.WrapInfrastructure(
			fmt.Errorf("failed to update HostedCluster: %w", err),
			"Restarting Control Plane failed")
	}

	return result, nil
}

func (c *Investigation) Name() string {
	return "restartcontrolplane"
}

func (c *Investigation) AlertTitle() string { return "RestartControlPlane" }

func (c *Investigation) Description() string {
	return "restarts the control plane of an HCP cluster"
}

func (c *Investigation) IsExperimental() bool {
	return false
}

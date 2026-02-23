package restartcontrolplane

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	cmv1 "github.com/openshift-online/ocm-sdk-go/clustersmgmt/v1"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/investigation"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestInvestigation_Name(t *testing.T) {
	inv := &Investigation{}
	assert.Equal(t, "restartcontrolplane", inv.Name())
}

func TestInvestigation_AlertTitle(t *testing.T) {
	inv := &Investigation{}
	assert.Equal(t, "RestartControlPlane", inv.AlertTitle())
}

func TestInvestigation_Description(t *testing.T) {
	inv := &Investigation{}
	assert.Equal(t, "restarts the control plane of an HCP cluster", inv.Description())
}

func TestInvestigation_IsExperimental(t *testing.T) {
	inv := &Investigation{}
	assert.False(t, inv.IsExperimental())
}

func TestInvestigation_Run_BuildError(t *testing.T) {
	buildErr := errors.New("build failed")
	rb := &investigation.ResourceBuilderMock{
		Resources:  nil,
		BuildError: buildErr,
	}
	inv := &Investigation{}

	result, err := inv.Run(rb)
	assert.Empty(t, result)
	assert.Error(t, err)
	assert.Equal(t, buildErr, err)
}

func TestInvestigation_Run_NonHCPCluster(t *testing.T) {
	rb := &investigation.ResourceBuilderMock{
		Resources: &investigation.Resources{
			IsHCP: false,
		},
		BuildError: nil,
	}
	inv := &Investigation{}

	result, err := inv.Run(rb)
	assert.Empty(t, result)
	assert.Error(t, err)
	var findingErr investigation.FindingError
	assert.True(t, errors.As(err, &findingErr))
	assert.Contains(t, err.Error(), "target cluster isn't an HCP cluster")
	assert.Contains(t, err.Error(), "Restarting Control Plane failed")
}

func TestInvestigation_Run_GetHostedClusterFails(t *testing.T) {
	cluster, err := cmv1.NewCluster().DomainPrefix("test-cluster").Build()
	require.NoError(t, err)

	// Fake client with no HostedCluster -> Get will return not found
	fakeK8s := fake.NewClientBuilder().Build()
	rb := &investigation.ResourceBuilderMock{
		Resources: &investigation.Resources{
			IsHCP:               true,
			HCNamespace:         "clusters-test-cluster",
			Cluster:             cluster,
			ManagementK8sClient: fakeK8s,
		},
		BuildError: nil,
	}
	inv := &Investigation{}

	result, err := inv.Run(rb)
	assert.Empty(t, result)
	assert.Error(t, err)
	var infraErr investigation.InfrastructureError
	assert.True(t, errors.As(err, &infraErr))
	assert.Contains(t, err.Error(), "failed to get HostedCluster")
	assert.Contains(t, err.Error(), "Restarting Control Plane failed")
}

func TestInvestigation_Run_Success(t *testing.T) {
	cluster, err := cmv1.NewCluster().DomainPrefix("test-cluster").Build()
	require.NoError(t, err)

	hcNamespace := "clusters-test-cluster"
	domainPrefix := cluster.DomainPrefix()

	// Pre-create HostedCluster so Get finds it
	hc := &unstructured.Unstructured{}
	hc.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   "hypershift.openshift.io",
		Version: "v1beta1",
		Kind:    "HostedCluster",
	})
	hc.SetNamespace(hcNamespace)
	hc.SetName(domainPrefix)

	fakeK8s := fake.NewClientBuilder().WithObjects(hc).Build()
	rb := &investigation.ResourceBuilderMock{
		Resources: &investigation.Resources{
			IsHCP:               true,
			HCNamespace:         hcNamespace,
			Cluster:             cluster,
			ManagementK8sClient: fakeK8s,
		},
		BuildError: nil,
	}
	inv := &Investigation{}

	result, err := inv.Run(rb)
	assert.NoError(t, err)
	assert.Empty(t, result.StopInvestigations)

	// Verify HostedCluster was updated with restart-date annotation
	updated := &unstructured.Unstructured{}
	updated.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   "hypershift.openshift.io",
		Version: "v1beta1",
		Kind:    "HostedCluster",
	})
	err = fakeK8s.Get(context.Background(), types.NamespacedName{Namespace: hcNamespace, Name: domainPrefix}, updated)
	require.NoError(t, err)
	annotations := updated.GetAnnotations()
	require.NotNil(t, annotations)
	assert.Contains(t, annotations, "hypershift.openshift.io/restart-date")
	assert.NotEmpty(t, annotations["hypershift.openshift.io/restart-date"])
}

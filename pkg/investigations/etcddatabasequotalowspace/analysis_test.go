package etcddatabasequotalowspace

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseNamespaceSizes(t *testing.T) {
	csvData := `namespace,total_size_megabytes
openshift-monitoring,45.23
kube-system,32.10
default,12.50`

	result := parseNamespaceSizes(csvData)

	assert.Len(t, result, 3)
	assert.Equal(t, "openshift-monitoring", result[0].Namespace)
	assert.Equal(t, 45.23, result[0].SizeMB)
	assert.Equal(t, "kube-system", result[1].Namespace)
	assert.Equal(t, 32.10, result[1].SizeMB)
	assert.Equal(t, "default", result[2].Namespace)
	assert.Equal(t, 12.50, result[2].SizeMB)
}

func TestParseResourceSizes(t *testing.T) {
	csvData := `namespace,name,total_size_megabytes,resourceType
openshift-monitoring,prometheus-config,15.23,configmap
kube-system,cluster-info,10.50,secret
default,app-config,8.75,configmap`

	result := parseResourceSizes(csvData)

	assert.Len(t, result, 3)

	assert.Equal(t, "openshift-monitoring", result[0].Namespace)
	assert.Equal(t, "prometheus-config", result[0].Name)
	assert.Equal(t, 15.23, result[0].SizeMB)
	assert.Equal(t, "configmap", result[0].ResourceType)

	assert.Equal(t, "kube-system", result[1].Namespace)
	assert.Equal(t, "cluster-info", result[1].Name)
	assert.Equal(t, 10.50, result[1].SizeMB)
	assert.Equal(t, "secret", result[1].ResourceType)

	assert.Equal(t, "default", result[2].Namespace)
	assert.Equal(t, "app-config", result[2].Name)
	assert.Equal(t, 8.75, result[2].SizeMB)
	assert.Equal(t, "configmap", result[2].ResourceType)
}

func TestParseAnalysisOutput(t *testing.T) {
	output := `namespace,total_size_megabytes
openshift-monitoring,45.23
kube-system,32.10
namespace,name,total_size_megabytes,resourceType
openshift-monitoring,prometheus-config,15.23,configmap
kube-system,cluster-info,10.50,secret
namespace,total_event_size_megabytes
openshift-monitoring,5.00
default,2.50`

	result, err := parseAnalysisOutput(output)

	assert.NoError(t, err)
	assert.NotNil(t, result)

	assert.Len(t, result.TopNamespaces, 2)
	assert.Equal(t, "openshift-monitoring", result.TopNamespaces[0].Namespace)
	assert.Equal(t, 45.23, result.TopNamespaces[0].SizeMB)

	assert.Len(t, result.LargestResources, 2)
	assert.Equal(t, "prometheus-config", result.LargestResources[0].Name)
	assert.Equal(t, 15.23, result.LargestResources[0].SizeMB)

	assert.Len(t, result.EventSizesByNS, 2)
	assert.Equal(t, "openshift-monitoring", result.EventSizesByNS[0].Namespace)
	assert.Equal(t, 5.00, result.EventSizesByNS[0].SizeMB)
}

func TestFormatAnalysisResults(t *testing.T) {
	result := &AnalysisResult{
		TopNamespaces: []NamespaceSize{
			{Namespace: "openshift-monitoring", SizeMB: 45.23},
			{Namespace: "kube-system", SizeMB: 32.10},
		},
		LargestResources: []ResourceSize{
			{Namespace: "openshift-monitoring", Name: "prometheus-config", SizeMB: 15.23, ResourceType: "configmap"},
			{Namespace: "kube-system", Name: "cluster-info", SizeMB: 10.50, ResourceType: "secret"},
		},
		EventSizesByNS: []NamespaceSize{
			{Namespace: "openshift-monitoring", SizeMB: 5.00},
			{Namespace: "default", SizeMB: 2.50},
		},
	}

	formatted := formatAnalysisResults(result)

	assert.Contains(t, formatted, "etcd Database Space Analysis")
	assert.Contains(t, formatted, "Top Space Consumers by Namespace")
	assert.Contains(t, formatted, "openshift-monitoring: 45.23 MB")
	assert.Contains(t, formatted, "kube-system: 32.10 MB")
	assert.Contains(t, formatted, "Largest ConfigMaps & Secrets")
	assert.Contains(t, formatted, "prometheus-config: 15.23 MB (configmap)")
	assert.Contains(t, formatted, "cluster-info: 10.50 MB (secret)")
	assert.Contains(t, formatted, "Event Storage by Namespace")
	assert.Contains(t, formatted, "openshift-monitoring: 5.00 MB")
}

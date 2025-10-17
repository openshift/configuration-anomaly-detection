package chgm

import (
	"fmt"
	"testing"

	"github.com/openshift/configuration-anomaly-detection/pkg/ocm"
	"gotest.tools/v3/assert"
)

// Mock data
var blockedUrls = "example.com, test.com"

// TestCreateEgressSL tests the createEgressSL function
func TestCreateEgressSL(t *testing.T) {
	docLink := "https://docs.example.com"
	expectedDescription := fmt.Sprintf(
		"Your cluster requires you to take action. SRE has observed that there have been changes made to the network configuration which impacts normal working of the cluster, including lack of network egress to these internet-based resources which are required for the cluster operation and support: %s. Please revert changes, and refer to documentation regarding firewall requirements for PrivateLink clusters: %s.",
		blockedUrls,
		docLink,
	)

	expected := &ocm.ServiceLog{
		Severity:     "Critical",
		Summary:      "Action required: Network misconfiguration",
		ServiceName:  "SREManualAction",
		Description:  expectedDescription,
		InternalOnly: false,
	}

	result := createEgressSL(blockedUrls, docLink)
	assert.Equal(t, *expected, *result)
}

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
	expectedDescription := fmt.Sprintf(
		"Your cluster requires you to take action. SRE has observed that there have been changes made to the network configuration which impacts normal working of the cluster, including lack of network egress to these internet-based resources which are required for the cluster operation and support: %s. Please revert changes, and refer to documentation regarding firewall requirements for PrivateLink clusters: https://access.redhat.com/documentation/en-us/red_hat_openshift_service_on_aws/4/html/prepare_your_environment/rosa-sts-aws-prereqs#osd-aws-privatelink-firewall-prerequisites_rosa-sts-aws-prereqs#.",
		blockedUrls,
	)

	expected := &ocm.ServiceLog{
		Severity:     "Critical",
		Summary:      "Action required: Network misconfiguration",
		ServiceName:  "SREManualAction",
		Description:  expectedDescription,
		InternalOnly: false,
	}

	result := createEgressSL(blockedUrls)
	assert.Equal(t, *expected, *result)
}

// TestCreateEgressLS tests the createEgressLS function
func TestCreateEgressLS(t *testing.T) {
	expectedDetails := fmt.Sprintf(
		"Your cluster requires you to take action. SRE has observed that there have been changes made to the network configuration which impacts normal working of the cluster, including lack of network egress to these internet-based resources which are required for the cluster operation and support: %s. Please revert changes, and refer to documentation regarding firewall requirements for PrivateLink clusters: https://access.redhat.com/documentation/en-us/red_hat_openshift_service_on_aws/4/html/prepare_your_environment/rosa-sts-aws-prereqs#osd-aws-privatelink-firewall-prerequisites_rosa-sts-aws-prereqs#.",
		blockedUrls,
	)

	expected := &ocm.LimitedSupportReason{
		Summary: "Cluster is in Limited Support due to unsupported cloud provider configuration",
		Details: expectedDetails,
	}

	result := createEgressLS(blockedUrls)
	assert.Equal(t, *expected, *result)
}

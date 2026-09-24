package chgm

import (
	"fmt"

	servicelogsv1 "github.com/openshift-online/ocm-sdk-go/servicelogs/v1"
	"github.com/openshift/configuration-anomaly-detection/pkg/ocm"
)

func createEgressSL(blockedUrls, docLink string) *ocm.ServiceLog {
	if docLink == "" {
		docLink = ocm.DocumentationLink(ocm.ProductROSA, ocm.DocumentationTopicPrivatelinkFirewall)
	}

	description := fmt.Sprintf("Your cluster requires you to take action. SRE has observed that there have been changes made to the network configuration which impacts normal working of the cluster, including lack of network egress to these internet-based resources which are required for the cluster operation and support: %s. Please revert changes, and refer to documentation regarding firewall requirements for PrivateLink clusters: %s.", blockedUrls, docLink)

	egressSL := ocm.ServiceLog{
		Severity:     servicelogsv1.SeverityCritical,
		Summary:      "Action required: Network misconfiguration",
		ServiceName:  "SREManualAction",
		Description:  description,
		InternalOnly: false,
	}

	return &egressSL
}

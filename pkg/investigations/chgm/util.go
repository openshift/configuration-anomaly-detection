package chgm

import (
	"fmt"

	"github.com/openshift/configuration-anomaly-detection/pkg/ocm"
)

func createEgressSL(blockedUrls string) *ocm.ServiceLog {
	description := fmt.Sprintf("Your cluster requires you to take action. SRE has observed that there have been changes made to the network configuration which impacts normal working of the cluster, including lack of network egress to these internet-based resources which are required for the cluster operation and support: %s. Please revert changes, and refer to documentation regarding firewall requirements for PrivateLink clusters: https://access.redhat.com/documentation/en-us/red_hat_openshift_service_on_aws/4/html/prepare_your_environment/rosa-sts-aws-prereqs#osd-aws-privatelink-firewall-prerequisites_rosa-sts-aws-prereqs#.", blockedUrls)

	egressSL := ocm.ServiceLog{
		Severity:     "Critical",
		Summary:      "Action required: Network misconfiguration",
		ServiceName:  "SREManualAction",
		Description:  description,
		InternalOnly: false,
	}

	return &egressSL
}

func createEgressLS(blockedUrls string) *ocm.LimitedSupportReason {
	details := fmt.Sprintf("Your cluster requires you to take action. SRE has observed that there have been changes made to the network configuration which impacts normal working of the cluster, including lack of network egress to these internet-based resources which are required for the cluster operation and support: %s. Please revert changes, and refer to documentation regarding firewall requirements for PrivateLink clusters: https://access.redhat.com/documentation/en-us/red_hat_openshift_service_on_aws/4/html/prepare_your_environment/rosa-sts-aws-prereqs#osd-aws-privatelink-firewall-prerequisites_rosa-sts-aws-prereqs#", blockedUrls)

	egressLS := ocm.LimitedSupportReason{
		Summary: "Cluster is in Limited Support due to unsupported cloud provider configuration",
		Details: details,
	}

	return &egressLS
}

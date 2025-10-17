package ocm

import (
	"fmt"
	"regexp"
	"strings"

	cmv1 "github.com/openshift-online/ocm-sdk-go/clustersmgmt/v1"
)

type Product string

const (
	ProductUnknown Product = ""
	ProductOSD         Product = "osd"
	ProductROSA       Product = "rosa"
)

type DocumentationTopic string

const (
	DocumentationTopicPrivatelinkFirewall DocumentationTopic = "privatelink-firewall"
	DocumentationTopicMonitoringStack     DocumentationTopic = "monitoring-stack"
	DocumentationTopicAwsCustomVPC        DocumentationTopic = "aws-custom-vpc"
)

var documentationLinks = map[DocumentationTopic]map[Product]string{
	DocumentationTopicPrivatelinkFirewall: {
		ProductROSA: "https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws_classic_architecture/4/html/install_rosa_classic_clusters/deploying-rosa-without-aws-sts#rosa-classic-firewall-prerequisites_prerequisites",
		ProductOSD:  "https://docs.redhat.com/en/documentation/openshift_dedicated/4/html-single/planning_your_environment/index#osd-aws-privatelink-firewall-prerequisites_aws-ccs",
	},
	DocumentationTopicMonitoringStack: {
		ProductROSA: "https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws_classic_architecture/4/html/monitoring/configuring-user-workload-monitoring",
		ProductOSD:  "https://docs.redhat.com/en/documentation/openshift_dedicated/4/html/monitoring/configuring-user-workload-monitoring",
	},
	DocumentationTopicAwsCustomVPC: {
		ProductROSA: "https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws_classic_architecture/4/html/prepare_your_environment/rosa-cloud-expert-prereq-checklist#vpc-requirements-for-privatelink-clusters",
		ProductOSD:  "https://docs.redhat.com/en/documentation/openshift_dedicated/4/html/cluster_administration/configuring-private-connections",
	},
}

var productDocumentationIndicators = map[Product][]string{
	ProductROSA: {
		"docs.openshift.com/rosa/",
		"docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws",
	},
	ProductOSD: {
		"docs.openshift.com/dedicated/",
		"docs.redhat.com/en/documentation/openshift_dedicated",
	},
}

var documentationURLPattern = regexp.MustCompile(`https?://[^\s>"']+`)

func DocumentationLink(product Product, topic DocumentationTopic) string {
	if links, ok := documentationLinks[topic]; ok {
		if link, ok := links[product]; ok && link != "" {
			return link
		}
		if link, ok := links[ProductROSA]; ok {
			return link
		}
	}
	return ""
}

func GetClusterProduct(cluster *cmv1.Cluster) Product {
	if cluster == nil {
		return ProductUnknown
	}
	product, ok := cluster.GetProduct()
	if !ok || product == nil {
		return ProductUnknown
	}
	switch strings.ToLower(product.ID()) {
	case string(ProductOSD):
		return ProductOSD
	case string(ProductROSA):
		return ProductROSA
	default:
		return ProductUnknown
	}
}

type docMsgType string

const (
	documentationMessageKindServiceLog     docMsgType = "service log"
	documentationMessageKindLimitedSupport docMsgType = "limited support reason"
)

// DocumentationMismatchError is returned when CAD detects that a documentation link isn't
// aligned with the product of the cluster it is about to notify.
type DocumentationMismatchError struct {
	ExpectedProduct Product
	DetectedProduct Product
	Link            string
	Summary         string
	Details         string
	Kind            docMsgType
}

func (e *DocumentationMismatchError) Error() string {
	return fmt.Sprintf("documentation link %q targets %s documentation but cluster product is %s", e.Link, productDisplayName(e.DetectedProduct), productDisplayName(e.ExpectedProduct))
}

// EscalationMessage returns the user-facing note that should be escalated to SREs when a
// documentation mismatch is detected.
func (e *DocumentationMismatchError) EscalationMessage() string {
	return fmt.Sprintf("%s: '%s' was to be sent, but detected documentation link %q for %s product while working on a %s cluster. Please send the correct ocumentation for the product manually. Details prepared:\n%s", e.Kind, e.Summary, e.Link, productDisplayName(e.DetectedProduct), productDisplayName(e.ExpectedProduct), e.Details)
}

func productDisplayName(product Product) string {
	switch product {
	case ProductROSA:
		return "ROSA"
	case ProductOSD:
		return "OpenShift Dedicated"
	default:
		return "unknown"
	}
}

func findDocumentationMismatch(expectedProduct Product, text string) (Product, string) {
	if expectedProduct == ProductUnknown || text == "" {
		return ProductUnknown, ""
	}

	links := documentationURLPattern.FindAllString(text, -1)
	for _, link := range links {
		detectedProduct := productFromDocumentationLink(link)
		if detectedProduct == ProductUnknown || detectedProduct == expectedProduct {
			continue
		}
		return detectedProduct, link
	}

	lowerText := strings.ToLower(text)
	for product, indicators := range productDocumentationIndicators {
		if product == expectedProduct {
			continue
		}
		for _, indicator := range indicators {
			if strings.Contains(lowerText, indicator) {
				return product, indicator
			}
		}
	}

	return ProductUnknown, ""
}

func productFromDocumentationLink(link string) Product {
	lowerLink := strings.ToLower(link)
	for product, indicators := range productDocumentationIndicators {
		for _, indicator := range indicators {
			if strings.Contains(lowerLink, indicator) {
				return product
			}
		}
	}
	return ProductUnknown
}

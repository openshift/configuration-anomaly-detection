package ocm

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	cmv1 "github.com/openshift-online/ocm-sdk-go/clustersmgmt/v1"
)

var _ = Describe("GetClusterProduct", func() {
	Context("when cluster is nil", func() {
		It("should return ProductUnknown", func() {
			result := GetClusterProduct(nil)
			Expect(result).To(Equal(ProductUnknown))
		})
	})

	Context("when cluster has no product field", func() {
		It("should return ProductUnknown", func() {
			cluster, err := cmv1.NewCluster().
				ID("test-cluster").
				Build()
			Expect(err).ToNot(HaveOccurred())

			result := GetClusterProduct(cluster)
			Expect(result).To(Equal(ProductUnknown))
		})
	})

	Context("when cluster is an OSD cluster", func() {
		It("should return ProductOSD", func() {
			cluster, err := cmv1.NewCluster().
				ID("test-cluster").
				Product(cmv1.NewProduct().ID("osd")).
				Build()
			Expect(err).ToNot(HaveOccurred())

			result := GetClusterProduct(cluster)
			Expect(result).To(Equal(ProductOSD))
		})
	})

	Context("when cluster is a ROSA cluster", func() {
		It("should return ProductROSA", func() {
			cluster, err := cmv1.NewCluster().
				ID("test-cluster").
				Product(cmv1.NewProduct().ID("rosa")).
				Build()
			Expect(err).ToNot(HaveOccurred())

			result := GetClusterProduct(cluster)
			Expect(result).To(Equal(ProductROSA))
		})
	})

	Context("when cluster has an unknown product type", func() {
		It("should return ProductUnknown", func() {
			cluster, err := cmv1.NewCluster().
				ID("test-cluster").
				Product(cmv1.NewProduct().ID("unknown-product")).
				Build()
			Expect(err).ToNot(HaveOccurred())

			result := GetClusterProduct(cluster)
			Expect(result).To(Equal(ProductUnknown))
		})
	})
})

var _ = Describe("DocumentationLink", func() {
	Context("when product and topic are valid", func() {
		It("should return correct link for ROSA privatelink-firewall", func() {
			link := DocumentationLink(ProductROSA, DocumentationTopicPrivatelinkFirewall)
			Expect(link).To(Equal("https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws_classic_architecture/4/html/install_rosa_classic_clusters/deploying-rosa-without-aws-sts#rosa-classic-firewall-prerequisites_prerequisites"))
		})

		It("should return correct link for OSD privatelink-firewall", func() {
			link := DocumentationLink(ProductOSD, DocumentationTopicPrivatelinkFirewall)
			Expect(link).To(Equal("https://docs.redhat.com/en/documentation/openshift_dedicated/4/html-single/planning_your_environment/index#osd-aws-privatelink-firewall-prerequisites_aws-ccs"))
		})

		It("should return correct link for ROSA monitoring-stack", func() {
			link := DocumentationLink(ProductROSA, DocumentationTopicMonitoringStack)
			Expect(link).To(Equal("https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws_classic_architecture/4/html/monitoring/configuring-user-workload-monitoring"))
		})

		It("should return correct link for OSD monitoring-stack", func() {
			link := DocumentationLink(ProductOSD, DocumentationTopicMonitoringStack)
			Expect(link).To(Equal("https://docs.redhat.com/en/documentation/openshift_dedicated/4/html/monitoring/configuring-user-workload-monitoring"))
		})
	})

	Context("when topic is unknown", func() {
		It("should return empty string", func() {
			link := DocumentationLink(ProductROSA, "unknown-topic")
			Expect(link).To(BeEmpty())
		})
	})

	Context("when product is unknown but topic exists", func() {
		It("should fallback to ROSA link", func() {
			link := DocumentationLink(ProductUnknown, DocumentationTopicPrivatelinkFirewall)
			Expect(link).To(Equal("https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws_classic_architecture/4/html/install_rosa_classic_clusters/deploying-rosa-without-aws-sts#rosa-classic-firewall-prerequisites_prerequisites"))
		})
	})

	Context("when both product and topic are invalid", func() {
		It("should return empty string", func() {
			link := DocumentationLink(ProductUnknown, "unknown-topic")
			Expect(link).To(BeEmpty())
		})
	})
})

var _ = Describe("productFromDocumentationLink", func() {
	Context("when link contains ROSA documentation indicators", func() {
		It("should detect ROSA from docs.openshift.com/rosa/ URL", func() {
			link := "https://docs.openshift.com/rosa/rosa_architecture/rosa_policy_service_definition/rosa-service-definition.html"
			product := productFromDocumentationLink(link)
			Expect(product).To(Equal(ProductROSA))
		})

		It("should detect ROSA from docs.redhat.com ROSA URL", func() {
			link := "https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/install"
			product := productFromDocumentationLink(link)
			Expect(product).To(Equal(ProductROSA))
		})

		It("should be case-insensitive for ROSA detection", func() {
			link := "https://DOCS.OPENSHIFT.COM/ROSA/getting-started"
			product := productFromDocumentationLink(link)
			Expect(product).To(Equal(ProductROSA))
		})
	})

	Context("when link contains OSD documentation indicators", func() {
		It("should detect OSD from docs.openshift.com/dedicated/ URL", func() {
			link := "https://docs.openshift.com/dedicated/4/monitoring/configuring-user-workload-monitoring.html"
			product := productFromDocumentationLink(link)
			Expect(product).To(Equal(ProductOSD))
		})

		It("should detect OSD from docs.redhat.com OSD URL", func() {
			link := "https://docs.redhat.com/en/documentation/openshift_dedicated/4/html/monitoring"
			product := productFromDocumentationLink(link)
			Expect(product).To(Equal(ProductOSD))
		})
	})

	Context("when link is not a documentation URL", func() {
		It("should return ProductUnknown for non-documentation URLs", func() {
			link := "https://www.google.com"
			product := productFromDocumentationLink(link)
			Expect(product).To(Equal(ProductUnknown))
		})

		It("should return ProductUnknown for empty URLs", func() {
			link := ""
			product := productFromDocumentationLink(link)
			Expect(product).To(Equal(ProductUnknown))
		})
	})
})

var _ = Describe("findDocumentationMismatch", func() {
	Context("when product matches documentation", func() {
		It("should return no mismatch when ROSA cluster has ROSA documentation URL", func() {
			text := "See https://docs.redhat.com/en/documentation/red_hat_openshift_service_on_aws/4/html/install for details"
			product, link := findDocumentationMismatch(ProductROSA, text)
			Expect(product).To(Equal(ProductUnknown))
			Expect(link).To(BeEmpty())
		})

		It("should return no mismatch when OSD cluster has OSD documentation URL", func() {
			text := "Check https://docs.redhat.com/en/documentation/openshift_dedicated/4/html/monitoring for info"
			product, link := findDocumentationMismatch(ProductOSD, text)
			Expect(product).To(Equal(ProductUnknown))
			Expect(link).To(BeEmpty())
		})
	})

	Context("when product does not match documentation", func() {
		It("should detect mismatch when ROSA cluster has OSD documentation URL", func() {
			text := "Please check https://docs.openshift.com/dedicated/4/monitoring/index.html for details"
			product, link := findDocumentationMismatch(ProductROSA, text)
			Expect(product).To(Equal(ProductOSD))
			Expect(link).To(Equal("https://docs.openshift.com/dedicated/4/monitoring/index.html"))
		})

		It("should detect mismatch when OSD cluster has ROSA documentation URL", func() {
			text := "Refer to https://docs.openshift.com/rosa/rosa_architecture/rosa-understanding.html"
			product, link := findDocumentationMismatch(ProductOSD, text)
			Expect(product).To(Equal(ProductROSA))
			Expect(link).To(Equal("https://docs.openshift.com/rosa/rosa_architecture/rosa-understanding.html"))
		})
	})

	Context("when expected product is unknown", func() {
		It("should return no mismatch", func() {
			text := "See https://docs.openshift.com/rosa/getting-started.html"
			product, link := findDocumentationMismatch(ProductUnknown, text)
			Expect(product).To(Equal(ProductUnknown))
			Expect(link).To(BeEmpty())
		})
	})

	Context("when text is empty", func() {
		It("should return no mismatch", func() {
			product, link := findDocumentationMismatch(ProductROSA, "")
			Expect(product).To(Equal(ProductUnknown))
			Expect(link).To(BeEmpty())
		})
	})

	Context("when text has no documentation links", func() {
		It("should return no mismatch", func() {
			text := "This is plain text without any documentation links"
			product, link := findDocumentationMismatch(ProductROSA, text)
			Expect(product).To(Equal(ProductUnknown))
			Expect(link).To(BeEmpty())
		})
	})

	Context("when text contains partial indicators without full URLs", func() {
		It("should detect mismatch from partial indicator text", func() {
			text := "More information at docs.openshift.com/dedicated/ section"
			product, link := findDocumentationMismatch(ProductROSA, text)
			Expect(product).To(Equal(ProductOSD))
			Expect(link).To(Equal("docs.openshift.com/dedicated/"))
		})
	})

	Context("when text has multiple links", func() {
		It("should find first mismatch", func() {
			text := "Check https://www.google.com and https://docs.openshift.com/dedicated/4/index.html and https://docs.openshift.com/rosa/install.html"
			product, link := findDocumentationMismatch(ProductROSA, text)
			Expect(product).To(Equal(ProductOSD))
			Expect(link).To(Equal("https://docs.openshift.com/dedicated/4/index.html"))
		})
	})
})

var _ = Describe("DocumentationMismatchError", func() {
	Context("Error method", func() {
		It("should return properly formatted error message", func() {
			err := &DocumentationMismatchError{
				ExpectedProduct: ProductROSA,
				DetectedProduct: ProductOSD,
				Link:            "https://docs.openshift.com/dedicated/4/monitoring/index.html",
				Summary:         "Test summary",
				Details:         "Test details",
				Kind:            documentationMessageKindServiceLog,
			}

			errorMsg := err.Error()
			Expect(errorMsg).To(ContainSubstring("https://docs.openshift.com/dedicated/4/monitoring/index.html"))
			Expect(errorMsg).To(ContainSubstring("OpenShift Dedicated"))
			Expect(errorMsg).To(ContainSubstring("ROSA"))
		})

		It("should handle OSD to ROSA mismatch", func() {
			err := &DocumentationMismatchError{
				ExpectedProduct: ProductOSD,
				DetectedProduct: ProductROSA,
				Link:            "https://docs.openshift.com/rosa/install.html",
				Summary:         "Test summary",
				Details:         "Test details",
				Kind:            documentationMessageKindLimitedSupport,
			}

			errorMsg := err.Error()
			Expect(errorMsg).To(ContainSubstring("https://docs.openshift.com/rosa/install.html"))
			Expect(errorMsg).To(ContainSubstring("ROSA"))
			Expect(errorMsg).To(ContainSubstring("OpenShift Dedicated"))
		})
	})

	Context("EscalationMessage method", func() {
		It("should return proper escalation note for service log", func() {
			err := &DocumentationMismatchError{
				ExpectedProduct: ProductROSA,
				DetectedProduct: ProductOSD,
				Link:            "https://docs.openshift.com/dedicated/4/monitoring/index.html",
				Summary:         "Monitoring stack issue",
				Details:         "Please check the monitoring documentation for more details.",
				Kind:            documentationMessageKindServiceLog,
			}

			escalationMsg := err.EscalationMessage()
			Expect(escalationMsg).To(ContainSubstring("service log"))
			Expect(escalationMsg).To(ContainSubstring("Monitoring stack issue"))
			Expect(escalationMsg).To(ContainSubstring("https://docs.openshift.com/dedicated/4/monitoring/index.html"))
			Expect(escalationMsg).To(ContainSubstring("OpenShift Dedicated"))
			Expect(escalationMsg).To(ContainSubstring("ROSA"))
			Expect(escalationMsg).To(ContainSubstring("Please check the monitoring documentation for more details."))
		})

		It("should return proper escalation note for limited support reason", func() {
			err := &DocumentationMismatchError{
				ExpectedProduct: ProductOSD,
				DetectedProduct: ProductROSA,
				Link:            "https://docs.openshift.com/rosa/networking.html",
				Summary:         "Network configuration issue",
				Details:         "Review network settings at the provided link.",
				Kind:            documentationMessageKindLimitedSupport,
			}

			escalationMsg := err.EscalationMessage()
			Expect(escalationMsg).To(ContainSubstring("limited support reason"))
			Expect(escalationMsg).To(ContainSubstring("Network configuration issue"))
			Expect(escalationMsg).To(ContainSubstring("https://docs.openshift.com/rosa/networking.html"))
			Expect(escalationMsg).To(ContainSubstring("ROSA"))
			Expect(escalationMsg).To(ContainSubstring("OpenShift Dedicated"))
			Expect(escalationMsg).To(ContainSubstring("Review network settings at the provided link."))
		})
	})
})

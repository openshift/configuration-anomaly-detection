package analyzers

import (
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/diagnosticcollection/findings"
)

var _ = Describe("ClusterOperatorAnalyzer", func() {
	var (
		analyzer  *ClusterOperatorAnalyzer
		tempDir   string
		coDir     string
		sampleDir string
	)

	BeforeEach(func() {
		analyzer = NewClusterOperatorAnalyzer()

		var err error
		tempDir, err = os.MkdirTemp("", "coanalyzer-test-*")
		Expect(err).ToNot(HaveOccurred())

		// Create directory structure for inspect output
		coDir = filepath.Join(tempDir, "cluster-scoped-resources", "config.openshift.io", "clusteroperators")
		err = os.MkdirAll(coDir, 0755)
		Expect(err).ToNot(HaveOccurred())

		// Get absolute path to samples directory
		cwd, err := os.Getwd()
		Expect(err).ToNot(HaveOccurred())
		sampleDir = filepath.Join(cwd, "..", "testing", "samples")
	})

	AfterEach(func() {
		os.RemoveAll(tempDir)
	})

	Describe("Name", func() {
		It("should return analyzer name", func() {
			Expect(analyzer.Name()).To(Equal("ClusterOperator"))
		})
	})

	Describe("Analyze", func() {
		Context("with degraded operator", func() {
			BeforeEach(func() {
				data, err := os.ReadFile(filepath.Join(sampleDir, "clusteroperator-degraded.yaml"))
				Expect(err).ToNot(HaveOccurred())
				err = os.WriteFile(filepath.Join(coDir, "authentication.yaml"), data, 0644)
				Expect(err).ToNot(HaveOccurred())
			})

			It("should return findings", func() {
				f, err := analyzer.Analyze(tempDir)
				Expect(err).ToNot(HaveOccurred())
				Expect(f).ToNot(BeNil())
				Expect(f.IsEmpty()).To(BeFalse())
			})

			It("should report degraded operator as critical", func() {
				f, err := analyzer.Analyze(tempDir)
				Expect(err).ToNot(HaveOccurred())

				Expect(f.HasCritical()).To(BeTrue())

				allFindings := f.GetAll()
				hasDegradedOp := false
				for _, finding := range allFindings {
					if finding.Severity == findings.SeverityCritical {
						hasDegradedOp = true
						Expect(finding.Title).To(ContainSubstring("Operator Degraded"))
						Expect(finding.Title).To(ContainSubstring("authentication"))
						Expect(finding.Message).To(ContainSubstring("OAuthServerDeploymentDegraded"))
						Expect(finding.Recommendation).ToNot(BeEmpty())
						Expect(finding.Recommendation).To(ContainSubstring("openshift-authentication"))
					}
				}
				Expect(hasDegradedOp).To(BeTrue())
			})
		})

		Context("with mixed operators", func() {
			BeforeEach(func() {
				// Add degraded operator
				degradedData, err := os.ReadFile(filepath.Join(sampleDir, "clusteroperator-degraded.yaml"))
				Expect(err).ToNot(HaveOccurred())
				err = os.WriteFile(filepath.Join(coDir, "authentication.yaml"), degradedData, 0644)
				Expect(err).ToNot(HaveOccurred())

				// Add healthy operator
				healthyData, err := os.ReadFile(filepath.Join(sampleDir, "clusteroperator-healthy.yaml"))
				Expect(err).ToNot(HaveOccurred())
				err = os.WriteFile(filepath.Join(coDir, "ingress.yaml"), healthyData, 0644)
				Expect(err).ToNot(HaveOccurred())
			})

			It("should report summary of all operators", func() {
				f, err := analyzer.Analyze(tempDir)
				Expect(err).ToNot(HaveOccurred())

				allFindings := f.GetAll()
				hasSummary := false
				for _, finding := range allFindings {
					if finding.Title == "Cluster Operators Summary" {
						hasSummary = true
						Expect(finding.Severity).To(Equal(findings.SeverityInfo))
						Expect(finding.Message).To(ContainSubstring("Total: 2"))
						Expect(finding.Message).To(ContainSubstring("Degraded: 1"))
					}
				}
				Expect(hasSummary).To(BeTrue())
			})

			It("should report only degraded operators as critical", func() {
				f, err := analyzer.Analyze(tempDir)
				Expect(err).ToNot(HaveOccurred())

				criticalFindings := 0
				for _, finding := range f.GetAll() {
					if finding.Severity == findings.SeverityCritical {
						criticalFindings++
						Expect(finding.Title).To(ContainSubstring("authentication"))
					}
				}
				Expect(criticalFindings).To(Equal(1))
			})
		})

		Context("with all healthy operators", func() {
			BeforeEach(func() {
				data, err := os.ReadFile(filepath.Join(sampleDir, "clusteroperator-healthy.yaml"))
				Expect(err).ToNot(HaveOccurred())
				err = os.WriteFile(filepath.Join(coDir, "ingress.yaml"), data, 0644)
				Expect(err).ToNot(HaveOccurred())
			})

			It("should not report critical findings", func() {
				f, err := analyzer.Analyze(tempDir)
				Expect(err).ToNot(HaveOccurred())
				Expect(f.HasCritical()).To(BeFalse())
			})

			It("should report summary with all healthy", func() {
				f, err := analyzer.Analyze(tempDir)
				Expect(err).ToNot(HaveOccurred())

				allFindings := f.GetAll()
				hasSummary := false
				for _, finding := range allFindings {
					if finding.Title == "Cluster Operators Summary" {
						hasSummary = true
						Expect(finding.Message).To(ContainSubstring("Degraded: 0"))
						Expect(finding.Message).To(ContainSubstring("Unavailable: 0"))
					}
				}
				Expect(hasSummary).To(BeTrue())
			})
		})

		Context("with missing files", func() {
			It("should return error", func() {
				_, err := analyzer.Analyze(tempDir)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("no clusteroperator files found"))
			})
		})
	})

	Describe("getRecommendation", func() {
		It("should provide specific recommendations for known operators", func() {
			analyzer := NewClusterOperatorAnalyzer()

			// Test authentication operator
			rec := analyzer.getRecommendation("authentication", "SomeReason")
			Expect(rec).To(ContainSubstring("openshift-authentication"))
			Expect(rec).To(ContainSubstring("OAuth"))

			// Test ingress operator
			rec = analyzer.getRecommendation("ingress", "SomeReason")
			Expect(rec).To(ContainSubstring("openshift-ingress"))
			Expect(rec).To(ContainSubstring("router"))

			// Test machine-config operator
			rec = analyzer.getRecommendation("machine-config", "PoolDegraded")
			Expect(rec).To(ContainSubstring("mcp"))
			Expect(rec).To(ContainSubstring("nodes"))

			// Test unknown operator
			rec = analyzer.getRecommendation("unknown-operator", "SomeReason")
			Expect(rec).To(ContainSubstring("openshift-unknown-operator"))
		})
	})
})

package analyzers

import (
	"os"
	"path/filepath"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/diagnosticcollection/findings"
)

func TestAnalyzers(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Analyzers Suite")
}

var _ = Describe("ClusterVersionAnalyzer", func() {
	var (
		analyzer  *ClusterVersionAnalyzer
		tempDir   string
		cvDir     string
		sampleDir string
	)

	BeforeEach(func() {
		analyzer = NewClusterVersionAnalyzer()

		var err error
		tempDir, err = os.MkdirTemp("", "cvanalyzer-test-*")
		Expect(err).ToNot(HaveOccurred())

		// Create directory structure for inspect output
		cvDir = filepath.Join(tempDir, "cluster-scoped-resources", "config.openshift.io", "clusterversions")
		err = os.MkdirAll(cvDir, 0755)
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
			Expect(analyzer.Name()).To(Equal("ClusterVersion"))
		})
	})

	Describe("Analyze", func() {
		Context("with stuck upgrade", func() {
			BeforeEach(func() {
				data, err := os.ReadFile(filepath.Join(sampleDir, "clusterversion-stuck.yaml"))
				Expect(err).ToNot(HaveOccurred())
				err = os.WriteFile(filepath.Join(cvDir, "version.yaml"), data, 0644)
				Expect(err).ToNot(HaveOccurred())
			})

			It("should return findings", func() {
				f, err := analyzer.Analyze(tempDir)
				Expect(err).ToNot(HaveOccurred())
				Expect(f).ToNot(BeNil())
				Expect(f.IsEmpty()).To(BeFalse())
			})

			It("should report upgrade information", func() {
				f, err := analyzer.Analyze(tempDir)
				Expect(err).ToNot(HaveOccurred())

				allFindings := f.GetAll()
				hasVersionInfo := false
				for _, finding := range allFindings {
					if finding.Title == "Cluster Version Information" {
						hasVersionInfo = true
						Expect(finding.Severity).To(Equal(findings.SeverityInfo))
						// In stuck upgrade, current version is partial 4.14.15
						Expect(finding.Message).To(ContainSubstring("4.14.15"))
						Expect(finding.Message).To(ContainSubstring("Upgrading: true"))
					}
				}
				Expect(hasVersionInfo).To(BeTrue())
			})

			It("should detect stuck upgrade", func() {
				f, err := analyzer.Analyze(tempDir)
				Expect(err).ToNot(HaveOccurred())

				// Should have critical finding about stuck upgrade
				Expect(f.HasCritical()).To(BeTrue())

				allFindings := f.GetAll()
				hasStuckUpgrade := false
				for _, finding := range allFindings {
					if finding.Title == "Upgrade Stuck" {
						hasStuckUpgrade = true
						Expect(finding.Severity).To(Equal(findings.SeverityCritical))
						// In stuck upgrade, shows upgrade to 4.14.15
						Expect(finding.Message).To(ContainSubstring("4.14.15"))
						Expect(finding.Message).To(ContainSubstring("threshold: 4h"))
						Expect(finding.Recommendation).ToNot(BeEmpty())
					}
				}
				Expect(hasStuckUpgrade).To(BeTrue())
			})
		})

		Context("with healthy cluster", func() {
			BeforeEach(func() {
				data, err := os.ReadFile(filepath.Join(sampleDir, "clusterversion-healthy.yaml"))
				Expect(err).ToNot(HaveOccurred())
				err = os.WriteFile(filepath.Join(cvDir, "version.yaml"), data, 0644)
				Expect(err).ToNot(HaveOccurred())
			})

			It("should return findings without critical issues", func() {
				f, err := analyzer.Analyze(tempDir)
				Expect(err).ToNot(HaveOccurred())
				Expect(f).ToNot(BeNil())
				Expect(f.HasCritical()).To(BeFalse())
			})

			It("should report version information", func() {
				f, err := analyzer.Analyze(tempDir)
				Expect(err).ToNot(HaveOccurred())

				allFindings := f.GetAll()
				hasVersionInfo := false
				for _, finding := range allFindings {
					if finding.Title == "Cluster Version Information" {
						hasVersionInfo = true
						Expect(finding.Message).To(ContainSubstring("4.14.10"))
						Expect(finding.Message).To(ContainSubstring("Upgrading: false"))
					}
				}
				Expect(hasVersionInfo).To(BeTrue())
			})
		})

		Context("with missing files", func() {
			It("should return error", func() {
				_, err := analyzer.Analyze(tempDir)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("no clusterversion files found"))
			})
		})
	})
})

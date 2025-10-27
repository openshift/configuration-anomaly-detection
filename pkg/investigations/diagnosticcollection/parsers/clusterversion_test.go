package parsers

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	configv1 "github.com/openshift/api/config/v1"
)

func TestParsers(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Parsers Suite")
}

var _ = Describe("ClusterVersion Parser", func() {
	var tempDir string

	BeforeEach(func() {
		var err error
		tempDir, err = os.MkdirTemp("", "clusterversion-test-*")
		Expect(err).ToNot(HaveOccurred())
	})

	AfterEach(func() {
		os.RemoveAll(tempDir)
	})

	Describe("ParseClusterVersion", func() {
		Context("with stuck upgrade", func() {
			BeforeEach(func() {
				// Create directory structure that oc adm inspect would create
				cvDir := filepath.Join(tempDir, "cluster-scoped-resources", "config.openshift.io", "clusterversions")
				err := os.MkdirAll(cvDir, 0755)
				Expect(err).ToNot(HaveOccurred())

				// Copy sample file
				samplePath := "../testing/samples/clusterversion-stuck.yaml"
				data, err := os.ReadFile(samplePath)
				Expect(err).ToNot(HaveOccurred())

				err = os.WriteFile(filepath.Join(cvDir, "version.yaml"), data, 0644)
				Expect(err).ToNot(HaveOccurred())
			})

			It("should parse version information", func() {
				cvInfo, err := ParseClusterVersion(tempDir)
				Expect(err).ToNot(HaveOccurred())
				Expect(cvInfo).ToNot(BeNil())
				Expect(cvInfo.Name).To(Equal("version"))
				// In stuck upgrade, History[0] is the partial upgrade to 4.14.15
				Expect(cvInfo.CurrentVersion).To(Equal("4.14.15"))
				Expect(cvInfo.DesiredVersion).To(Equal("4.14.15"))
			})

			It("should detect upgrade in progress", func() {
				cvInfo, err := ParseClusterVersion(tempDir)
				Expect(err).ToNot(HaveOccurred())
				Expect(cvInfo.IsUpgrading).To(BeTrue())
			})

			It("should have upgrade start time", func() {
				cvInfo, err := ParseClusterVersion(tempDir)
				Expect(err).ToNot(HaveOccurred())
				Expect(cvInfo.UpgradeStartTime).ToNot(BeNil())
			})

			It("should detect stuck upgrade after threshold", func() {
				cvInfo, err := ParseClusterVersion(tempDir)
				Expect(err).ToNot(HaveOccurred())

				// The sample has upgrade started at 2024-01-15T14:00:00Z
				// which is definitely > 4 hours ago, so it should be stuck
				isStuck := cvInfo.IsUpgradeStuck(4 * time.Hour)
				Expect(isStuck).To(BeTrue())
			})

			It("should parse conditions", func() {
				cvInfo, err := ParseClusterVersion(tempDir)
				Expect(err).ToNot(HaveOccurred())
				Expect(cvInfo.Conditions).ToNot(BeEmpty())

				availableCond := cvInfo.GetCondition(configv1.OperatorAvailable)
				Expect(availableCond).ToNot(BeNil())
				Expect(availableCond.Status).To(Equal(configv1.ConditionTrue))

				progressingCond := cvInfo.GetCondition(configv1.OperatorProgressing)
				Expect(progressingCond).ToNot(BeNil())
				Expect(progressingCond.Status).To(Equal(configv1.ConditionTrue))
			})
		})

		Context("with healthy cluster", func() {
			BeforeEach(func() {
				cvDir := filepath.Join(tempDir, "cluster-scoped-resources", "config.openshift.io", "clusterversions")
				err := os.MkdirAll(cvDir, 0755)
				Expect(err).ToNot(HaveOccurred())

				samplePath := "../testing/samples/clusterversion-healthy.yaml"
				data, err := os.ReadFile(samplePath)
				Expect(err).ToNot(HaveOccurred())

				err = os.WriteFile(filepath.Join(cvDir, "version.yaml"), data, 0644)
				Expect(err).ToNot(HaveOccurred())
			})

			It("should not show upgrade in progress", func() {
				cvInfo, err := ParseClusterVersion(tempDir)
				Expect(err).ToNot(HaveOccurred())
				Expect(cvInfo.IsUpgrading).To(BeFalse())
			})

			It("should have matching current and desired versions", func() {
				cvInfo, err := ParseClusterVersion(tempDir)
				Expect(err).ToNot(HaveOccurred())
				Expect(cvInfo.CurrentVersion).To(Equal("4.14.10"))
				Expect(cvInfo.DesiredVersion).To(Equal(""))
			})

			It("should not be stuck", func() {
				cvInfo, err := ParseClusterVersion(tempDir)
				Expect(err).ToNot(HaveOccurred())
				Expect(cvInfo.IsUpgradeStuck(4 * time.Hour)).To(BeFalse())
			})
		})

		Context("with missing files", func() {
			It("should return error when no clusterversion files found", func() {
				_, err := ParseClusterVersion(tempDir)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("no clusterversion files found"))
			})
		})
	})

	Describe("GetUpgradeDuration", func() {
		It("should return 0 for non-upgrading cluster", func() {
			cvInfo := &ClusterVersionInfo{
				IsUpgrading: false,
			}
			Expect(cvInfo.GetUpgradeDuration()).To(Equal(time.Duration(0)))
		})

		It("should return 0 when no start time", func() {
			cvInfo := &ClusterVersionInfo{
				IsUpgrading:      true,
				UpgradeStartTime: nil,
			}
			Expect(cvInfo.GetUpgradeDuration()).To(Equal(time.Duration(0)))
		})
	})
})

package parsers

import (
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	configv1 "github.com/openshift/api/config/v1"
)

var _ = Describe("ClusterOperator Parser", func() {
	var tempDir string

	BeforeEach(func() {
		var err error
		tempDir, err = os.MkdirTemp("", "clusteroperator-test-*")
		Expect(err).ToNot(HaveOccurred())
	})

	AfterEach(func() {
		os.RemoveAll(tempDir)
	})

	Describe("ParseClusterOperators", func() {
		Context("with mixed operator states", func() {
			BeforeEach(func() {
				// Create directory structure
				coDir := filepath.Join(tempDir, "cluster-scoped-resources", "config.openshift.io", "clusteroperators")
				err := os.MkdirAll(coDir, 0755)
				Expect(err).ToNot(HaveOccurred())

				// Add degraded operator
				degradedData, err := os.ReadFile("../testing/samples/clusteroperator-degraded.yaml")
				Expect(err).ToNot(HaveOccurred())
				err = os.WriteFile(filepath.Join(coDir, "authentication.yaml"), degradedData, 0644)
				Expect(err).ToNot(HaveOccurred())

				// Add healthy operator
				healthyData, err := os.ReadFile("../testing/samples/clusteroperator-healthy.yaml")
				Expect(err).ToNot(HaveOccurred())
				err = os.WriteFile(filepath.Join(coDir, "ingress.yaml"), healthyData, 0644)
				Expect(err).ToNot(HaveOccurred())
			})

			It("should parse multiple operators", func() {
				operators, err := ParseClusterOperators(tempDir)
				Expect(err).ToNot(HaveOccurred())
				Expect(operators).To(HaveLen(2))
			})

			It("should identify degraded operator", func() {
				operators, err := ParseClusterOperators(tempDir)
				Expect(err).ToNot(HaveOccurred())

				// Find authentication operator
				var authOp *ClusterOperatorInfo
				for i := range operators {
					if operators[i].Name == "authentication" {
						authOp = &operators[i]
						break
					}
				}

				Expect(authOp).ToNot(BeNil())
				Expect(authOp.IsDegraded).To(BeTrue())
				Expect(authOp.IsAvailable).To(BeFalse())
				Expect(authOp.DegradedReason).To(Equal("OAuthServerDeploymentDegraded"))
				Expect(authOp.DegradedMessage).To(ContainSubstring("0/1 replicas available"))
			})

			It("should identify healthy operator", func() {
				operators, err := ParseClusterOperators(tempDir)
				Expect(err).ToNot(HaveOccurred())

				// Find ingress operator
				var ingressOp *ClusterOperatorInfo
				for i := range operators {
					if operators[i].Name == "ingress" {
						ingressOp = &operators[i]
						break
					}
				}

				Expect(ingressOp).ToNot(BeNil())
				Expect(ingressOp.IsDegraded).To(BeFalse())
				Expect(ingressOp.IsAvailable).To(BeTrue())
				Expect(ingressOp.IsProgressing).To(BeFalse())
			})

			It("should detect issues correctly", func() {
				operators, err := ParseClusterOperators(tempDir)
				Expect(err).ToNot(HaveOccurred())

				for _, op := range operators {
					if op.Name == "authentication" {
						Expect(op.HasIssues()).To(BeTrue())
					} else if op.Name == "ingress" {
						Expect(op.HasIssues()).To(BeFalse())
					}
				}
			})
		})

		Context("with missing files", func() {
			It("should return error when no clusteroperator files found", func() {
				_, err := ParseClusterOperators(tempDir)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("no clusteroperator files found"))
			})
		})
	})

	Describe("Helper functions", func() {
		var operators []ClusterOperatorInfo

		BeforeEach(func() {
			operators = []ClusterOperatorInfo{
				{
					Name:        "degraded-op",
					IsDegraded:  true,
					IsAvailable: false,
				},
				{
					Name:        "healthy-op",
					IsDegraded:  false,
					IsAvailable: true,
				},
				{
					Name:        "unavailable-op",
					IsDegraded:  false,
					IsAvailable: false,
				},
			}
		})

		Describe("GetDegradedOperators", func() {
			It("should return only degraded operators", func() {
				degraded := GetDegradedOperators(operators)
				Expect(degraded).To(HaveLen(1))
				Expect(degraded[0].Name).To(Equal("degraded-op"))
			})
		})

		Describe("GetUnavailableOperators", func() {
			It("should return unavailable operators", func() {
				unavailable := GetUnavailableOperators(operators)
				Expect(unavailable).To(HaveLen(2))

				// Should include both degraded and unavailable
				names := []string{unavailable[0].Name, unavailable[1].Name}
				Expect(names).To(ContainElement("degraded-op"))
				Expect(names).To(ContainElement("unavailable-op"))
			})
		})

		Describe("GetCondition", func() {
			It("should retrieve specific condition", func() {
				op := ClusterOperatorInfo{
					Conditions: []configv1.ClusterOperatorStatusCondition{
						{
							Type:   configv1.OperatorDegraded,
							Status: configv1.ConditionTrue,
						},
						{
							Type:   configv1.OperatorAvailable,
							Status: configv1.ConditionFalse,
						},
					},
				}

				degradedCond := op.GetCondition(configv1.OperatorDegraded)
				Expect(degradedCond).ToNot(BeNil())
				Expect(degradedCond.Status).To(Equal(configv1.ConditionTrue))

				availableCond := op.GetCondition(configv1.OperatorAvailable)
				Expect(availableCond).ToNot(BeNil())
				Expect(availableCond.Status).To(Equal(configv1.ConditionFalse))
			})

			It("should return nil for missing condition", func() {
				op := ClusterOperatorInfo{
					Conditions: []configv1.ClusterOperatorStatusCondition{},
				}

				cond := op.GetCondition(configv1.OperatorDegraded)
				Expect(cond).To(BeNil())
			})
		})
	})
})

package networkverifier_test

import (
	"errors"
	"fmt"

	"github.com/golang/mock/gomock"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v1 "github.com/openshift-online/ocm-sdk-go/clustersmgmt/v1"
	awsmock "github.com/openshift/configuration-anomaly-detection/pkg/aws/mock"
	"github.com/openshift/configuration-anomaly-detection/pkg/networkverifier"
	hivev1 "github.com/openshift/hive/apis/hive/v1"
)

var _ = Describe("RunVerifier", func() {
	Describe("AreAllInstancesRunning", func() {
		var (
			mockCtrl          *gomock.Controller
			clusterBuilder    *v1.ClusterBuilder
			clusterDeployment *hivev1.ClusterDeployment
			awsCli            *awsmock.MockClient
		)
		BeforeEach(func() {
			mockCtrl = gomock.NewController(GinkgoT())

			awsCli = awsmock.NewMockClient(mockCtrl)

			region := v1.NewCloudRegion().ID("us-east-1")

			clusterBuilder = v1.NewCluster().ID("12345").Nodes(v1.NewClusterNodes().Total(1)).Region(region)

			clusterDeployment = &hivev1.ClusterDeployment{
				Spec: hivev1.ClusterDeploymentSpec{
					ClusterMetadata: &hivev1.ClusterMetadata{
						InfraID: "infra_id",
					},
				},
			}
		})
		AfterEach(func() {
			mockCtrl.Finish()
		})
		// This test is pretty useless but illustrates what tests for networkverifier should look like
		When("Getting security group ids", func() {
			It("Should return the error failed to get SecurityGroupId", func() {
				// Finish setup
				cluster, err := clusterBuilder.Build()

				Expect(err).ToNot(HaveOccurred())

				// Arrange
				expectedError := errors.New("failed to get SecurityGroupId: errormessage")

				awsCli.EXPECT().GetSecurityGroupID(gomock.Eq(clusterDeployment.Spec.ClusterMetadata.InfraID)).Return("", expectedError)

				// Act
				result, failures, gotErr := networkverifier.Run(cluster, clusterDeployment, awsCli)
				fmt.Printf("result %v, failures %v", result, failures)

				// Assert
				Expect(gotErr).To(HaveOccurred())
				Expect(gotErr.Error()).To(ContainSubstring(expectedError.Error()))
			})
		})

		When("Checking input passed to ONV", func() {
			It("Should forward the cluster KMS key", func() {
				// Finish setup
				kmsKey := "some-KMS-key-ARN"
				clusterBuilder.AWS(v1.NewAWS().KMSKeyArn(kmsKey))

				cluster, err := clusterBuilder.Build()

				Expect(err).ToNot(HaveOccurred())

				// Arrange
				awsCli.EXPECT().GetSecurityGroupID(gomock.Eq(clusterDeployment.Spec.ClusterMetadata.InfraID)).Return(gomock.Any().String(), nil)
				awsCli.EXPECT().GetSubnetID(gomock.Eq(clusterDeployment.Spec.ClusterMetadata.InfraID)).Return([]string{"string1", "string2"}, nil)

				// Act
				input, gotErr := networkverifier.InitializeValidateEgressInput(cluster, clusterDeployment, awsCli)
				fmt.Printf("input %v", input)

				// Assert
				Expect(gotErr).ToNot(HaveOccurred())
				Expect(input.AWS.KmsKeyID).To(BeIdenticalTo(kmsKey))
			})
		})
	})
})

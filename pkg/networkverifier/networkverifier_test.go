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
			cluster           *v1.Cluster
			clusterDeployment *hivev1.ClusterDeployment
			awsCli            *awsmock.MockClient
		)
		BeforeEach(func() {
			mockCtrl = gomock.NewController(GinkgoT())

			awsCli = awsmock.NewMockClient(mockCtrl)

			var err error
			cluster, err = v1.NewCluster().ID("12345").Nodes(v1.NewClusterNodes().Total(1)).Build()

			clusterDeployment := &hivev1.ClusterDeployment{}
			clusterDeployment.Spec.ClusterMetadata.InfraID = "infra_id"

			Expect(err).ToNot(HaveOccurred())
		})
		AfterEach(func() {
			mockCtrl.Finish()
		})
		// This test is pretty useless but illustrates what tests for networkverifier should look like
		When("Getting security group ids", func() {
			It("Should return the error failed to get SecurityGroupId", func() {
				expectedError := errors.New("failed to get SecurityGroupId: errormessage")
				// Arrange
				awsCli.EXPECT().GetSecurityGroupID(gomock.Eq(clusterDeployment.Spec.ClusterMetadata.InfraID)).Return(nil, expectedError)
				// Act
				result, failures, gotErr := networkverifier.Run(cluster, clusterDeployment, awsCli)

				fmt.Printf("result %v, failures %v", result, failures)
				// Assert
				Expect(gotErr).To(HaveOccurred())
				Expect(gotErr.Error()).To(BeIdenticalTo(expectedError))
			})
		})
	})
})

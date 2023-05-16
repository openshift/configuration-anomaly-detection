package networkverifier_test

import (
	"fmt"

	"github.com/golang/mock/gomock"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v1 "github.com/openshift-online/ocm-sdk-go/clustersmgmt/v1"
	"github.com/openshift/configuration-anomaly-detection/pkg/services/networkverifier"
	mock_networkverifier "github.com/openshift/configuration-anomaly-detection/pkg/services/networkverifier/mock"
)

var _ = Describe("RunVerifier", func() {
	Describe("AreAllInstancesRunning", func() {

		// this is a var but I use it as a const
		var fakeErr = fmt.Errorf("verifier test triggered")
		var (
			mockCtrl   *gomock.Controller
			mockClient *mock_networkverifier.MockService
			isRunning  networkverifier.Client
			cluster    *v1.Cluster
			// clusterDeployment hivev1.ClusterDeployment
			// infraID           string
			// instance          ec2.Instance
			// securitygroup     ec2.SecurityGroup
		)
		BeforeEach(func() {
			mockCtrl = gomock.NewController(GinkgoT())
			mockClient = mock_networkverifier.NewMockService(mockCtrl)
			isRunning = networkverifier.Client{Service: mockClient}
			var err error
			cluster, err = v1.NewCluster().ID("12345").Nodes(v1.NewClusterNodes().Total(1)).Build()
			Expect(err).ToNot(HaveOccurred())
			// clusterDeployment = hivev1.ClusterDeployment{
			// 	Spec: hivev1.ClusterDeploymentSpec{
			// 		ClusterMetadata: &hivev1.ClusterMetadata{
			// 			InfraID: "12345",
			// 		}}}
			// infraID = clusterDeployment.Spec.ClusterMetadata.InfraID
			// instance = ec2.Instance{InstanceId: aws.String("12345")}
			// securitygroup = ec2.SecurityGroup{GroupName: aws.String("12345-worker-sg")}
		})
		AfterEach(func() {
			mockCtrl.Finish()
		})
		When("GetClusterInfo fails", func() {
			It("Should bubble up the error", func() {
				// Arrange
				mockClient.EXPECT().GetClusterInfo(gomock.Any()).Return(cluster, fakeErr)
				// Act
				result, failures, gotErr := isRunning.RunNetworkVerifier(cluster.InfraID())
				fmt.Printf("result %v, failures %v", result, failures)
				// Assert
				Expect(gotErr).To(HaveOccurred())
			})
		})
		// When("GetAwsVerifier fails", func() {
		// 	It("Should bubble up the error", func() {
		// 		// Arrange
		// 		mockClient.EXPECT().GetClusterInfo(gomock.Any()).Return(cluster, fakeErr)
		// 		mockClient.EXPECT().GetAwsVerifier(gomock.Any()).Return(nil, fakeErr)
		// 		// Act
		// 		gotErr := isRunning.RunNetworkVerifier(cluster.InfraID())
		// 		// Assert
		// 		Expect(gotErr).To(HaveOccurred())
		// 	})
		// })
	})
})

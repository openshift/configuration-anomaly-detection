package chgm_test

import (
	"fmt"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/cloudtrail"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/golang/mock/gomock"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v1 "github.com/openshift-online/ocm-sdk-go/clustersmgmt/v1"
	"github.com/openshift/configuration-anomaly-detection/pkg/services/chgm"
	"github.com/openshift/configuration-anomaly-detection/pkg/services/chgm/mock"
	hivev1 "github.com/openshift/hive/apis/hive/v1"
)

var _ = Describe("Chgm", func() {
	Describe("AreAllInstancesRunning", func() {

		// this is a var but I use it as a const
		var fakeErr = fmt.Errorf("test")
		var (
			mockCtrl          *gomock.Controller
			mockClient        *mock.MockService
			isRunning         chgm.Client
			cluster           *v1.Cluster
			clusterDeployment hivev1.ClusterDeployment
			infraID           string
			instance          ec2.Instance
		)
		BeforeEach(func() {
			mockCtrl = gomock.NewController(GinkgoT())
			mockClient = mock.NewMockService(mockCtrl)
			isRunning = chgm.Client{Service: mockClient}
			var err error
			cluster, err = v1.NewCluster().ID("12345").Nodes(v1.NewClusterNodes().Total(1)).Build()
			Expect(err).ToNot(HaveOccurred())
			clusterDeployment = hivev1.ClusterDeployment{
				Spec: hivev1.ClusterDeploymentSpec{
					ClusterMetadata: &hivev1.ClusterMetadata{
						InfraID: "12345",
					}}}
			infraID = clusterDeployment.Spec.ClusterMetadata.InfraID
			instance = ec2.Instance{InstanceId: aws.String("12345")}
		})
		AfterEach(func() {
			mockCtrl.Finish()
		})
		When("GetClusterDeployment fails", func() {
			It("Should bubble up the error", func() {
				// Arrange
				mockClient.EXPECT().GetClusterInfo(gomock.Any()).Return(nil, fakeErr)
				// Act
				_, gotErr := isRunning.InvestigateInstances("")
				// Assert
				Expect(gotErr).To(HaveOccurred())
			})
		})

		When("GetClusterDeployment fails", func() {
			It("the GetClusterDeployment should receive the correct cluster_id and bubble up the error", func() {
				// Arrange
				mockClient.EXPECT().GetClusterInfo(gomock.Any()).Return(cluster, nil)
				mockClient.EXPECT().GetClusterDeployment(gomock.Eq(cluster.ID())).Return(nil, fakeErr)
				// Act
				_, gotErr := isRunning.InvestigateInstances("")
				// Assert
				Expect(gotErr).To(HaveOccurred())
			})
		})

		When("ListNonRunningInstances fails", func() {
			It("the ListNonRunningInstances should receive the correct InfraID and bubble the error", func() {
				// Arrange
				mockClient.EXPECT().GetClusterInfo(gomock.Any()).Return(cluster, nil)
				mockClient.EXPECT().GetClusterDeployment(gomock.Eq(cluster.ID())).Return(&clusterDeployment, nil)

				mockClient.EXPECT().ListNonRunningInstances(gomock.Eq(infraID)).Return(nil, fakeErr)
				// Act
				_, gotErr := isRunning.InvestigateInstances("")
				// Assert
				Expect(gotErr).To(HaveOccurred())
			})
		})

		When("there were no stopped instances", func() {
			It("should succeed and return that no non running instances were found", func() {
				// Arrange
				mockClient.EXPECT().GetClusterInfo(gomock.Any()).Return(cluster, nil)
				mockClient.EXPECT().GetClusterDeployment(gomock.Eq(cluster.ID())).Return(&clusterDeployment, nil)
				mockClient.EXPECT().ListNonRunningInstances(gomock.Eq(infraID)).Return([]*ec2.Instance{}, nil)
				// Act
				got, gotErr := isRunning.InvestigateInstances("")
				// Assert
				Expect(gotErr).To(HaveOccurred())
				Expect(got.UserAuthorized).To(BeTrue())
			})
		})

		When("there was an error getting StopInstancesEvents", func() {
			It("should succeed and return that all instance are running", func() {
				// Arrange
				mockClient.EXPECT().GetClusterInfo(gomock.Any()).Return(cluster, nil)
				mockClient.EXPECT().GetClusterDeployment(gomock.Eq(cluster.ID())).Return(&clusterDeployment, nil)
				mockClient.EXPECT().ListNonRunningInstances(gomock.Eq(infraID)).Return([]*ec2.Instance{&instance}, nil)
				mockClient.EXPECT().PollInstanceStopEventsFor(gomock.Any(), gomock.Any()).Return(nil, fakeErr)
				// Act
				_, gotErr := isRunning.InvestigateInstances("")
				// Assert
				Expect(gotErr).To(HaveOccurred())
			})
		})

		When("there were no StopInstancesEvents", func() {
			It("the ListNonRunningInstances should receive the correct InfraID and bubble the error", func() {
				// Arrange
				mockClient.EXPECT().GetClusterInfo(gomock.Any()).Return(cluster, nil)
				mockClient.EXPECT().GetClusterDeployment(gomock.Eq(cluster.ID())).Return(&clusterDeployment, nil)
				mockClient.EXPECT().ListNonRunningInstances(gomock.Eq(infraID)).Return([]*ec2.Instance{&instance}, nil)
				mockClient.EXPECT().PollInstanceStopEventsFor(gomock.Any(), gomock.Any()).Return(nil, fakeErr)
				// Act
				_, gotErr := isRunning.InvestigateInstances("")
				// Assert
				Expect(gotErr).To(HaveOccurred())
			})
		})
		Describe("Verify User is allowed to stop instances", func() {
			var (
				event cloudtrail.Event
			)

			BeforeEach(func() {
				event = cloudtrail.Event{
					Username:        aws.String("12345"),
					CloudTrailEvent: aws.String(`{"eventVersion":"1.08"}`),
				}
			})

			When("the returned CloudTrailEvent is empty", func() {
				It("getting stopped instances events should pass but an error should bubble up", func() {
					// Arrange
					mockClient.EXPECT().GetClusterInfo(gomock.Any()).Return(cluster, nil)
					mockClient.EXPECT().GetClusterDeployment(gomock.Eq(cluster.ID())).Return(&clusterDeployment, nil)
					mockClient.EXPECT().ListNonRunningInstances(gomock.Eq(infraID)).Return([]*ec2.Instance{&instance}, nil)
					mockClient.EXPECT().PollInstanceStopEventsFor(gomock.Any(), gomock.Any()).Return([]*cloudtrail.Event{}, nil)
					// Act
					_, gotErr := isRunning.InvestigateInstances("")
					// Assert
					Expect(gotErr).To(HaveOccurred())
				})
			})

			When("the returned CloudTrailEvent is an empty string", func() {
				It("the validation should fail and bubble up the error", func() {
					// Arrange
					mockClient.EXPECT().GetClusterInfo(gomock.Any()).Return(cluster, nil)
					mockClient.EXPECT().GetClusterDeployment(gomock.Eq(cluster.ID())).Return(&clusterDeployment, nil)
					mockClient.EXPECT().ListNonRunningInstances(gomock.Eq(infraID)).Return([]*ec2.Instance{&instance}, nil)
					event.CloudTrailEvent = aws.String(``)
					mockClient.EXPECT().PollInstanceStopEventsFor(gomock.Any(), gomock.Any()).Return([]*cloudtrail.Event{&event}, nil)
					mockClient.EXPECT().GetNodeCount(clusterDeployment.Spec.ClusterMetadata.InfraID).Return(0, nil)
					// Act
					_, gotErr := isRunning.InvestigateInstances("")
					// Assert
					Expect(gotErr).To(HaveOccurred())
				})
			})

			When("the returned CloudTrailEvent is an empty json", func() {
				It("the validation should fail and bubble up the error", func() {
					// Arrange
					mockClient.EXPECT().GetClusterInfo(gomock.Any()).Return(cluster, nil)
					mockClient.EXPECT().GetClusterDeployment(gomock.Eq(cluster.ID())).Return(&clusterDeployment, nil)
					mockClient.EXPECT().ListNonRunningInstances(gomock.Eq(infraID)).Return([]*ec2.Instance{&instance}, nil)
					event.CloudTrailEvent = aws.String(`{}`)
					mockClient.EXPECT().PollInstanceStopEventsFor(gomock.Any(), gomock.Any()).Return([]*cloudtrail.Event{&event}, nil)
					mockClient.EXPECT().GetNodeCount(clusterDeployment.Spec.ClusterMetadata.InfraID).Return(0, nil)
					// Act
					_, gotErr := isRunning.InvestigateInstances("")
					// Assert
					Expect(gotErr).To(HaveOccurred())
				})
			})

			When("the returned CloudTrailEvent is an invalid json", func() {
				It("the validation should fail and bubble up the error", func() {
					// Arrange
					mockClient.EXPECT().GetClusterInfo(gomock.Any()).Return(cluster, nil)
					mockClient.EXPECT().GetClusterDeployment(gomock.Eq(cluster.ID())).Return(&clusterDeployment, nil)
					mockClient.EXPECT().ListNonRunningInstances(gomock.Eq(infraID)).Return([]*ec2.Instance{&instance}, nil)
					event.CloudTrailEvent = aws.String(`{`)
					mockClient.EXPECT().PollInstanceStopEventsFor(gomock.Any(), gomock.Any()).Return([]*cloudtrail.Event{&event}, nil)
					mockClient.EXPECT().GetNodeCount(clusterDeployment.Spec.ClusterMetadata.InfraID).Return(0, nil)
					// Act
					_, gotErr := isRunning.InvestigateInstances("")
					// Assert
					Expect(gotErr).To(HaveOccurred())
				})
			})

			When("the returned CloudTrailEvent has more than one resource", func() {
				It("it should fail and bubble up the error", func() {
					// Arrange
					mockClient.EXPECT().GetClusterInfo(gomock.Any()).Return(cluster, nil)
					mockClient.EXPECT().GetClusterDeployment(gomock.Eq(cluster.ID())).Return(&clusterDeployment, nil)
					mockClient.EXPECT().ListNonRunningInstances(gomock.Eq(infraID)).Return([]*ec2.Instance{&instance}, nil)
					event.CloudTrailEvent = aws.String(`{}`)
					cloudTrailResource := cloudtrail.Resource{ResourceName: aws.String("123456")}
					event.Resources = []*cloudtrail.Resource{&cloudTrailResource}
					mockClient.EXPECT().PollInstanceStopEventsFor(gomock.Any(), gomock.Any()).Return([]*cloudtrail.Event{&event}, nil)
					mockClient.EXPECT().GetNodeCount(clusterDeployment.Spec.ClusterMetadata.InfraID).Return(0, nil)
					// Act
					_, gotErr := isRunning.InvestigateInstances("")
					// Assert
					Expect(gotErr).To(HaveOccurred())
				})
			})

			When("the returned CloudTrailEvent has an older version of eventversion", func() {
				It("the validation should fail and bubble up  the error", func() {
					// Arrange
					mockClient.EXPECT().GetClusterInfo(gomock.Any()).Return(cluster, nil)
					mockClient.EXPECT().GetClusterDeployment(gomock.Eq(cluster.ID())).Return(&clusterDeployment, nil)
					mockClient.EXPECT().ListNonRunningInstances(gomock.Eq(infraID)).Return([]*ec2.Instance{&instance}, nil)
					event.CloudTrailEvent = aws.String(`{"eventVersion":"1.07"}`)
					mockClient.EXPECT().PollInstanceStopEventsFor(gomock.Any(), gomock.Any()).Return([]*cloudtrail.Event{&event}, nil)
					mockClient.EXPECT().GetNodeCount(clusterDeployment.Spec.ClusterMetadata.InfraID).Return(0, nil)
					// Act
					_, gotErr := isRunning.InvestigateInstances("")
					// Assert
					Expect(gotErr).To(HaveOccurred())
				})
			})

			When("the returned CloudTrailEvent has a matching valid operatorname", func() {
				It("the deletion will be marked as ok", func() {
					// Arrange
					mockClient.EXPECT().GetClusterInfo(gomock.Any()).Return(cluster, nil)
					mockClient.EXPECT().GetClusterDeployment(gomock.Eq(cluster.ID())).Return(&clusterDeployment, nil)
					mockClient.EXPECT().ListNonRunningInstances(gomock.Eq(infraID)).Return([]*ec2.Instance{&instance}, nil)
					event.Username = aws.String(fmt.Sprintf("%s-openshift-machine-api-aws-abcd", infraID))
					event.CloudTrailEvent = aws.String(`{"eventVersion":"1.08"}`)
					mockClient.EXPECT().PollInstanceStopEventsFor(gomock.Any(), gomock.Any()).Return([]*cloudtrail.Event{&event}, nil)
					mockClient.EXPECT().GetNodeCount(clusterDeployment.Spec.ClusterMetadata.InfraID).Return(0, nil)
					// Act
					got, gotErr := isRunning.InvestigateInstances("")
					// Assert
					Expect(gotErr).NotTo(HaveOccurred())
					Expect(got.UserAuthorized).To(BeTrue())
				})
			})

			When("the returned CloudTrailEvent has a matching valid operatorname", func() {
				It("the deletion will be marked as ok", func() {
					// Arrange
					mockClient.EXPECT().GetClusterInfo(gomock.Any()).Return(cluster, nil)
					mockClient.EXPECT().GetClusterDeployment(gomock.Eq(cluster.ID())).Return(&clusterDeployment, nil)
					mockClient.EXPECT().ListNonRunningInstances(gomock.Eq(infraID)).Return([]*ec2.Instance{&instance}, nil)
					event.Username = aws.String("osdManagedAdmin-abcd")
					mockClient.EXPECT().PollInstanceStopEventsFor(gomock.Any(), gomock.Any()).Return([]*cloudtrail.Event{&event}, nil)
					mockClient.EXPECT().GetNodeCount(clusterDeployment.Spec.ClusterMetadata.InfraID).Return(0, nil)
					// Act
					got, gotErr := isRunning.InvestigateInstances("")
					// Assert
					Expect(gotErr).NotTo(HaveOccurred())
					Expect(got.UserAuthorized).To(BeTrue())
				})
			})

			When("the returned CloudTrailEventRaw has no data", func() {
				It("the deletion will be marked invalid", func() {
					// Arrange
					mockClient.EXPECT().GetClusterInfo(gomock.Any()).Return(cluster, nil)
					mockClient.EXPECT().GetClusterDeployment(gomock.Eq(cluster.ID())).Return(&clusterDeployment, nil)
					mockClient.EXPECT().ListNonRunningInstances(gomock.Eq(infraID)).Return([]*ec2.Instance{&instance}, nil)
					mockClient.EXPECT().PollInstanceStopEventsFor(gomock.Any(), gomock.Any()).Return([]*cloudtrail.Event{&event}, nil)
					mockClient.EXPECT().GetNodeCount(clusterDeployment.Spec.ClusterMetadata.InfraID).Return(0, nil)
					// Act
					got, gotErr := isRunning.InvestigateInstances("")
					// Assert
					Expect(gotErr).NotTo(HaveOccurred())
					Expect(got.UserAuthorized).To(BeFalse())
				})
			})

			When("the returned CloudTrailEventRaw has an empty userIdentity", func() {
				It("the deletion will be marked invalid", func() {
					// Arrange
					mockClient.EXPECT().GetClusterInfo(gomock.Any()).Return(cluster, nil)
					mockClient.EXPECT().GetClusterDeployment(gomock.Eq(cluster.ID())).Return(&clusterDeployment, nil)
					mockClient.EXPECT().ListNonRunningInstances(gomock.Eq(infraID)).Return([]*ec2.Instance{&instance}, nil)
					event.CloudTrailEvent = aws.String(`{"eventVersion":"1.08", "userIdentity":{}}`)
					mockClient.EXPECT().PollInstanceStopEventsFor(gomock.Any(), gomock.Any()).Return([]*cloudtrail.Event{&event}, nil)
					mockClient.EXPECT().GetNodeCount(clusterDeployment.Spec.ClusterMetadata.InfraID).Return(0, nil)
					// Act
					got, gotErr := isRunning.InvestigateInstances("")
					// Assert
					Expect(gotErr).NotTo(HaveOccurred())
					Expect(got.UserAuthorized).To(BeFalse())
				})
			})

			When("the returned CloudTrailEventRaw has a userIdentity is an iam user", func() {
				It("the deletion will be marked invalid", func() {
					// Arrange
					mockClient.EXPECT().GetClusterInfo(gomock.Any()).Return(cluster, nil)
					mockClient.EXPECT().GetClusterDeployment(gomock.Eq(cluster.ID())).Return(&clusterDeployment, nil)
					mockClient.EXPECT().ListNonRunningInstances(gomock.Eq(infraID)).Return([]*ec2.Instance{&instance}, nil)
					event.CloudTrailEvent = aws.String(`{"eventVersion":"1.08", "userIdentity":{"type":"IAMUser"}}`)
					mockClient.EXPECT().PollInstanceStopEventsFor(gomock.Any(), gomock.Any()).Return([]*cloudtrail.Event{&event}, nil)
					mockClient.EXPECT().GetNodeCount(clusterDeployment.Spec.ClusterMetadata.InfraID).Return(0, nil)
					// Act
					got, gotErr := isRunning.InvestigateInstances("")
					// Assert
					Expect(gotErr).NotTo(HaveOccurred())
					Expect(got.UserAuthorized).To(BeFalse())
				})
			})

			When("the returned CloudTrailEventRaw base data is correct, but the sessionissue's role is not role", func() {
				It("the deletion will be marked invalid", func() {
					// Arrange
					mockClient.EXPECT().GetClusterInfo(gomock.Any()).Return(cluster, nil)
					mockClient.EXPECT().GetClusterDeployment(gomock.Eq(cluster.ID())).Return(&clusterDeployment, nil)
					mockClient.EXPECT().ListNonRunningInstances(gomock.Eq(infraID)).Return([]*ec2.Instance{&instance}, nil)
					event.CloudTrailEvent = aws.String(`{"eventVersion":"1.08", "userIdentity":{"type":"AssumedRole", "sessionContext":{"sessionIssuer":{"type":"test"}}}}`)
					mockClient.EXPECT().PollInstanceStopEventsFor(gomock.Any(), gomock.Any()).Return([]*cloudtrail.Event{&event}, nil)
					mockClient.EXPECT().GetNodeCount(clusterDeployment.Spec.ClusterMetadata.InfraID).Return(0, nil)
					// Act
					got, gotErr := isRunning.InvestigateInstances("")
					// Assert
					Expect(gotErr).NotTo(HaveOccurred())
					Expect(got.UserAuthorized).To(BeFalse())
				})
			})

			When("the returned CloudTrailEventRaw base data is correct, but the sessionissue's username is not the correct user", func() {
				It("the deletion will be marked invalid", func() {
					// Arrange
					mockClient.EXPECT().GetClusterInfo(gomock.Any()).Return(cluster, nil)
					mockClient.EXPECT().GetClusterDeployment(gomock.Eq(cluster.ID())).Return(&clusterDeployment, nil)
					mockClient.EXPECT().ListNonRunningInstances(gomock.Eq(infraID)).Return([]*ec2.Instance{&instance}, nil)
					event.CloudTrailEvent = aws.String(`{"eventVersion":"1.08", "userIdentity":{"type":"AssumedRole", "sessionContext":{"sessionIssuer":{"type":"Role", "userName": "654321"}}}}`)
					mockClient.EXPECT().PollInstanceStopEventsFor(gomock.Any(), gomock.Any()).Return([]*cloudtrail.Event{&event}, nil)
					mockClient.EXPECT().GetNodeCount(clusterDeployment.Spec.ClusterMetadata.InfraID).Return(0, nil)
					// Act
					got, gotErr := isRunning.InvestigateInstances("")
					// Assert
					Expect(gotErr).NotTo(HaveOccurred())
					Expect(got.UserAuthorized).To(BeFalse())
				})
			})

			When("username role is OrganizationAccountAccessRole", func() {
				It("the deletion will be marked as valid", func() {
					// Arrange
					mockClient.EXPECT().GetClusterInfo(gomock.Any()).Return(cluster, nil)
					mockClient.EXPECT().GetClusterDeployment(gomock.Eq(cluster.ID())).Return(&clusterDeployment, nil)
					mockClient.EXPECT().ListNonRunningInstances(gomock.Eq(infraID)).Return([]*ec2.Instance{&instance}, nil)
					event.CloudTrailEvent = aws.String(`{"eventVersion":"1.08", "userIdentity":{"type":"AssumedRole", "sessionContext":{"sessionIssuer":{"type":"Role", "userName": "OrganizationAccountAccessRole"}}}}`)
					mockClient.EXPECT().PollInstanceStopEventsFor(gomock.Any(), gomock.Any()).Return([]*cloudtrail.Event{&event}, nil)
					mockClient.EXPECT().GetNodeCount(clusterDeployment.Spec.ClusterMetadata.InfraID).Return(0, nil)
					// Act
					got, gotErr := isRunning.InvestigateInstances("")
					// Assert
					Expect(gotErr).NotTo(HaveOccurred())
					Expect(got.UserAuthorized).To(BeTrue())
				})
			})
		})
	})
})

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

var _ = Describe("ChgmTriggered", func() {
	Describe("AreAllInstancesRunning", func() {

		// this is a var but I use it as a const
		var fakeErr = fmt.Errorf("test triggered")
		var (
			mockCtrl          *gomock.Controller
			mockClient        *mock.MockService
			isRunning         chgm.Client
			cluster           *v1.Cluster
			clusterDeployment hivev1.ClusterDeployment
			machinePools      []*v1.MachinePool
			infraID           string
			instance          ec2.Instance
		)
		BeforeEach(func() {
			mockCtrl = gomock.NewController(GinkgoT())
			mockClient = mock.NewMockService(mockCtrl)
			isRunning = chgm.Client{Service: mockClient}
			var err error
			cluster, err = v1.NewCluster().ID("12345").Nodes(v1.NewClusterNodes().Master(1).Infra(0).Compute(0)).Build()
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
				_, gotErr := isRunning.InvestigateStoppedInstances("")
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
				_, gotErr := isRunning.InvestigateStoppedInstances("")
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
				_, gotErr := isRunning.InvestigateStoppedInstances("")
				// Assert
				Expect(gotErr).To(HaveOccurred())
			})
		})

		When("there were no stopped instances", func() {
			It("should succeed and return that no non running instances were found", func() {
				// Arrange
				mockClient.EXPECT().GetClusterInfo(gomock.Any()).Return(cluster, nil)
				mockClient.EXPECT().GetClusterDeployment(gomock.Eq(cluster.ID())).Return(&clusterDeployment, nil)
				mockClient.EXPECT().ListRunningInstances(gomock.Eq(infraID)).Return([]*ec2.Instance{&instance}, nil)
				mockClient.EXPECT().GetClusterMachinePools(gomock.Any()).Return(machinePools, nil)
				mockClient.EXPECT().ListNonRunningInstances(gomock.Eq(infraID)).Return([]*ec2.Instance{}, nil)
				// Act
				got, gotErr := isRunning.InvestigateStoppedInstances("")
				// Assert
				Expect(gotErr).ToNot(HaveOccurred())
				Expect(got.UserAuthorized).To(BeTrue())
			})
		})

		When("there was an error getting StopInstancesEvents", func() {
			It("should succeed and return that all instance are running", func() {
				// Arrange
				mockClient.EXPECT().GetClusterInfo(gomock.Any()).Return(cluster, nil)
				mockClient.EXPECT().GetClusterDeployment(gomock.Eq(cluster.ID())).Return(&clusterDeployment, nil)
				mockClient.EXPECT().ListRunningInstances(gomock.Eq(infraID)).Return([]*ec2.Instance{&instance}, nil)
				mockClient.EXPECT().GetClusterMachinePools(gomock.Any()).Return(machinePools, nil)
				mockClient.EXPECT().ListNonRunningInstances(gomock.Eq(infraID)).Return([]*ec2.Instance{&instance}, nil)
				mockClient.EXPECT().PollInstanceStopEventsFor(gomock.Any(), gomock.Any()).Return(nil, fakeErr)
				// Act
				_, gotErr := isRunning.InvestigateStoppedInstances("")
				// Assert
				Expect(gotErr).To(HaveOccurred())
			})
		})

		When("there were no StopInstancesEvents", func() {
			It("the ListNonRunningInstances should receive the correct InfraID and bubble the error", func() {
				// Arrange
				mockClient.EXPECT().GetClusterInfo(gomock.Any()).Return(cluster, nil)
				mockClient.EXPECT().GetClusterDeployment(gomock.Eq(cluster.ID())).Return(&clusterDeployment, nil)
				mockClient.EXPECT().ListRunningInstances(gomock.Eq(infraID)).Return([]*ec2.Instance{&instance}, nil)
				mockClient.EXPECT().GetClusterMachinePools(gomock.Any()).Return(machinePools, nil)
				mockClient.EXPECT().ListNonRunningInstances(gomock.Eq(infraID)).Return([]*ec2.Instance{&instance}, nil)
				mockClient.EXPECT().PollInstanceStopEventsFor(gomock.Any(), gomock.Any()).Return([]*cloudtrail.Event{}, nil)
				// Act
				_, gotErr := isRunning.InvestigateStoppedInstances("")
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
					mockClient.EXPECT().ListRunningInstances(gomock.Eq(infraID)).Return([]*ec2.Instance{&instance}, nil)
					mockClient.EXPECT().GetClusterMachinePools(gomock.Any()).Return(machinePools, nil)
					mockClient.EXPECT().ListNonRunningInstances(gomock.Eq(infraID)).Return([]*ec2.Instance{&instance}, nil)
					mockClient.EXPECT().PollInstanceStopEventsFor(gomock.Any(), gomock.Any()).Return([]*cloudtrail.Event{}, nil)
					// Act
					_, gotErr := isRunning.InvestigateStoppedInstances("")
					// Assert
					Expect(gotErr).To(HaveOccurred())
				})
			})

			When("the returned CloudTrailEvent is an empty string", func() {
				It("the validation should fail and bubble up the error", func() {
					// Arrange
					mockClient.EXPECT().GetClusterInfo(gomock.Any()).Return(cluster, nil)
					mockClient.EXPECT().GetClusterDeployment(gomock.Eq(cluster.ID())).Return(&clusterDeployment, nil)
					mockClient.EXPECT().GetClusterMachinePools(gomock.Any()).Return(machinePools, nil)
					mockClient.EXPECT().ListNonRunningInstances(gomock.Eq(infraID)).Return([]*ec2.Instance{&instance}, nil)
					mockClient.EXPECT().ListRunningInstances(gomock.Eq(infraID)).Return([]*ec2.Instance{&instance}, nil)
					event.CloudTrailEvent = aws.String(``)
					mockClient.EXPECT().PollInstanceStopEventsFor(gomock.Any(), gomock.Any()).Return([]*cloudtrail.Event{&event}, nil)

					// Act
					_, gotErr := isRunning.InvestigateStoppedInstances("")
					// Assert
					Expect(gotErr).To(HaveOccurred())
				})
			})

			When("the returned CloudTrailEvent is an empty json", func() {
				It("the validation should fail and bubble up the error", func() {
					// Arrange
					mockClient.EXPECT().GetClusterInfo(gomock.Any()).Return(cluster, nil)
					mockClient.EXPECT().GetClusterDeployment(gomock.Eq(cluster.ID())).Return(&clusterDeployment, nil)
					mockClient.EXPECT().GetClusterMachinePools(gomock.Any()).Return(machinePools, nil)
					mockClient.EXPECT().ListNonRunningInstances(gomock.Eq(infraID)).Return([]*ec2.Instance{&instance}, nil)
					mockClient.EXPECT().ListRunningInstances(gomock.Eq(infraID)).Return([]*ec2.Instance{&instance}, nil)
					event.CloudTrailEvent = aws.String(`{}`)
					mockClient.EXPECT().PollInstanceStopEventsFor(gomock.Any(), gomock.Any()).Return([]*cloudtrail.Event{&event}, nil)

					// Act
					_, gotErr := isRunning.InvestigateStoppedInstances("")
					// Assert
					Expect(gotErr).To(HaveOccurred())
				})
			})

			When("the returned CloudTrailEvent is an invalid json", func() {
				It("the validation should fail and bubble up the error", func() {
					// Arrange
					mockClient.EXPECT().GetClusterInfo(gomock.Any()).Return(cluster, nil)
					mockClient.EXPECT().GetClusterDeployment(gomock.Eq(cluster.ID())).Return(&clusterDeployment, nil)
					mockClient.EXPECT().GetClusterMachinePools(gomock.Any()).Return(machinePools, nil)
					mockClient.EXPECT().ListNonRunningInstances(gomock.Eq(infraID)).Return([]*ec2.Instance{&instance}, nil)
					mockClient.EXPECT().ListRunningInstances(gomock.Eq(infraID)).Return([]*ec2.Instance{&instance}, nil)
					event.CloudTrailEvent = aws.String(`{`)
					mockClient.EXPECT().PollInstanceStopEventsFor(gomock.Any(), gomock.Any()).Return([]*cloudtrail.Event{&event}, nil)

					// Act
					_, gotErr := isRunning.InvestigateStoppedInstances("")
					// Assert
					Expect(gotErr).To(HaveOccurred())
				})
			})

			When("the returned CloudTrailEvent has more than one resource", func() {
				It("it should fail and bubble up the error", func() {
					// Arrange
					mockClient.EXPECT().GetClusterInfo(gomock.Any()).Return(cluster, nil)
					mockClient.EXPECT().GetClusterDeployment(gomock.Eq(cluster.ID())).Return(&clusterDeployment, nil)
					mockClient.EXPECT().GetClusterMachinePools(gomock.Any()).Return(machinePools, nil)
					mockClient.EXPECT().ListNonRunningInstances(gomock.Eq(infraID)).Return([]*ec2.Instance{&instance}, nil)
					mockClient.EXPECT().ListRunningInstances(gomock.Eq(infraID)).Return([]*ec2.Instance{&instance}, nil)
					event.CloudTrailEvent = aws.String(`{}`)
					cloudTrailResource := cloudtrail.Resource{ResourceName: aws.String("123456")}
					event.Resources = []*cloudtrail.Resource{&cloudTrailResource}
					mockClient.EXPECT().PollInstanceStopEventsFor(gomock.Any(), gomock.Any()).Return([]*cloudtrail.Event{&event}, nil)

					// Act
					_, gotErr := isRunning.InvestigateStoppedInstances("")
					// Assert
					Expect(gotErr).To(HaveOccurred())
				})
			})

			When("the returned CloudTrailEvent has an older version of eventversion", func() {
				It("the validation should fail and bubble up  the error", func() {
					// Arrange
					mockClient.EXPECT().GetClusterInfo(gomock.Any()).Return(cluster, nil)
					mockClient.EXPECT().GetClusterDeployment(gomock.Eq(cluster.ID())).Return(&clusterDeployment, nil)
					mockClient.EXPECT().GetClusterMachinePools(gomock.Any()).Return(machinePools, nil)
					mockClient.EXPECT().ListNonRunningInstances(gomock.Eq(infraID)).Return([]*ec2.Instance{&instance}, nil)
					mockClient.EXPECT().ListRunningInstances(gomock.Eq(infraID)).Return([]*ec2.Instance{&instance}, nil)
					event.CloudTrailEvent = aws.String(`{"eventVersion":"1.07"}`)
					mockClient.EXPECT().PollInstanceStopEventsFor(gomock.Any(), gomock.Any()).Return([]*cloudtrail.Event{&event}, nil)

					// Act
					_, gotErr := isRunning.InvestigateStoppedInstances("")
					// Assert
					Expect(gotErr).To(HaveOccurred())
				})
			})

			When("the returned CloudTrailEvent has a matching valid operatorname", func() {
				It("the deletion will be marked as ok", func() {
					// Arrange
					mockClient.EXPECT().GetClusterInfo(gomock.Any()).Return(cluster, nil)
					mockClient.EXPECT().GetClusterDeployment(gomock.Eq(cluster.ID())).Return(&clusterDeployment, nil)
					mockClient.EXPECT().GetClusterMachinePools(gomock.Any()).Return(machinePools, nil)
					mockClient.EXPECT().ListNonRunningInstances(gomock.Eq(infraID)).Return([]*ec2.Instance{&instance}, nil)
					mockClient.EXPECT().ListRunningInstances(gomock.Eq(infraID)).Return([]*ec2.Instance{&instance}, nil)
					event.Username = aws.String(fmt.Sprintf("%s-openshift-machine-api-aws-abcd", infraID))
					event.CloudTrailEvent = aws.String(`{"eventVersion":"1.08"}`)
					mockClient.EXPECT().PollInstanceStopEventsFor(gomock.Any(), gomock.Any()).Return([]*cloudtrail.Event{&event}, nil)

					// Act
					got, gotErr := isRunning.InvestigateStoppedInstances("")
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
					mockClient.EXPECT().GetClusterMachinePools(gomock.Any()).Return(machinePools, nil)
					mockClient.EXPECT().ListNonRunningInstances(gomock.Eq(infraID)).Return([]*ec2.Instance{&instance}, nil)
					mockClient.EXPECT().ListRunningInstances(gomock.Eq(infraID)).Return([]*ec2.Instance{&instance}, nil)
					event.Username = aws.String("osdManagedAdmin-abcd")
					mockClient.EXPECT().PollInstanceStopEventsFor(gomock.Any(), gomock.Any()).Return([]*cloudtrail.Event{&event}, nil)

					// Act
					got, gotErr := isRunning.InvestigateStoppedInstances("")
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
					mockClient.EXPECT().GetClusterMachinePools(gomock.Any()).Return(machinePools, nil)
					mockClient.EXPECT().ListNonRunningInstances(gomock.Eq(infraID)).Return([]*ec2.Instance{&instance}, nil)
					mockClient.EXPECT().ListRunningInstances(gomock.Eq(infraID)).Return([]*ec2.Instance{&instance}, nil)
					mockClient.EXPECT().PollInstanceStopEventsFor(gomock.Any(), gomock.Any()).Return([]*cloudtrail.Event{&event}, nil)

					// Act
					got, gotErr := isRunning.InvestigateStoppedInstances("")
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
					mockClient.EXPECT().GetClusterMachinePools(gomock.Any()).Return(machinePools, nil)
					mockClient.EXPECT().ListNonRunningInstances(gomock.Eq(infraID)).Return([]*ec2.Instance{&instance}, nil)
					mockClient.EXPECT().ListRunningInstances(gomock.Eq(infraID)).Return([]*ec2.Instance{&instance}, nil)
					event.CloudTrailEvent = aws.String(`{"eventVersion":"1.08", "userIdentity":{}}`)
					mockClient.EXPECT().PollInstanceStopEventsFor(gomock.Any(), gomock.Any()).Return([]*cloudtrail.Event{&event}, nil)

					// Act
					got, gotErr := isRunning.InvestigateStoppedInstances("")
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
					mockClient.EXPECT().GetClusterMachinePools(gomock.Any()).Return(machinePools, nil)
					mockClient.EXPECT().ListNonRunningInstances(gomock.Eq(infraID)).Return([]*ec2.Instance{&instance}, nil)
					mockClient.EXPECT().ListRunningInstances(gomock.Eq(infraID)).Return([]*ec2.Instance{&instance}, nil)
					event.CloudTrailEvent = aws.String(`{"eventVersion":"1.08", "userIdentity":{"type":"IAMUser"}}`)
					mockClient.EXPECT().PollInstanceStopEventsFor(gomock.Any(), gomock.Any()).Return([]*cloudtrail.Event{&event}, nil)

					// Act
					got, gotErr := isRunning.InvestigateStoppedInstances("")
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
					mockClient.EXPECT().GetClusterMachinePools(gomock.Any()).Return(machinePools, nil)
					mockClient.EXPECT().ListNonRunningInstances(gomock.Eq(infraID)).Return([]*ec2.Instance{&instance}, nil)
					mockClient.EXPECT().ListRunningInstances(gomock.Eq(infraID)).Return([]*ec2.Instance{&instance}, nil)
					event.CloudTrailEvent = aws.String(`{"eventVersion":"1.08", "userIdentity":{"type":"AssumedRole", "sessionContext":{"sessionIssuer":{"type":"test"}}}}`)
					mockClient.EXPECT().PollInstanceStopEventsFor(gomock.Any(), gomock.Any()).Return([]*cloudtrail.Event{&event}, nil)

					// Act
					got, gotErr := isRunning.InvestigateStoppedInstances("")
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
					mockClient.EXPECT().GetClusterMachinePools(gomock.Any()).Return(machinePools, nil)
					mockClient.EXPECT().ListNonRunningInstances(gomock.Eq(infraID)).Return([]*ec2.Instance{&instance}, nil)
					mockClient.EXPECT().ListRunningInstances(gomock.Eq(infraID)).Return([]*ec2.Instance{&instance}, nil)
					event.CloudTrailEvent = aws.String(`{"eventVersion":"1.08", "userIdentity":{"type":"AssumedRole", "sessionContext":{"sessionIssuer":{"type":"Role", "userName": "654321"}}}}`)
					mockClient.EXPECT().PollInstanceStopEventsFor(gomock.Any(), gomock.Any()).Return([]*cloudtrail.Event{&event}, nil)

					// Act
					got, gotErr := isRunning.InvestigateStoppedInstances("")
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
					mockClient.EXPECT().GetClusterMachinePools(gomock.Any()).Return(machinePools, nil)
					mockClient.EXPECT().ListNonRunningInstances(gomock.Eq(infraID)).Return([]*ec2.Instance{&instance}, nil)
					mockClient.EXPECT().ListRunningInstances(gomock.Eq(infraID)).Return([]*ec2.Instance{&instance}, nil)
					event.CloudTrailEvent = aws.String(`{"eventVersion":"1.08", "userIdentity":{"type":"AssumedRole", "sessionContext":{"sessionIssuer":{"type":"Role", "userName": "OrganizationAccountAccessRole"}}}}`)
					mockClient.EXPECT().PollInstanceStopEventsFor(gomock.Any(), gomock.Any()).Return([]*cloudtrail.Event{&event}, nil)

					// Act
					got, gotErr := isRunning.InvestigateStoppedInstances("")
					// Assert
					Expect(gotErr).NotTo(HaveOccurred())
					Expect(got.UserAuthorized).To(BeTrue())
				})
			})

			When("issuer user is authorized (ManagedOpenShift-Installer-Role)", func() {
				It("the deletion will be marked as valid", func() {
					// Arrange
					mockClient.EXPECT().GetClusterInfo(gomock.Any()).Return(cluster, nil)
					mockClient.EXPECT().GetClusterDeployment(gomock.Eq(cluster.ID())).Return(&clusterDeployment, nil)
					mockClient.EXPECT().GetClusterMachinePools(gomock.Any()).Return(machinePools, nil)
					mockClient.EXPECT().ListNonRunningInstances(gomock.Eq(infraID)).Return([]*ec2.Instance{&instance}, nil)
					mockClient.EXPECT().ListRunningInstances(gomock.Eq(infraID)).Return([]*ec2.Instance{&instance}, nil)
					event.CloudTrailEvent = aws.String(`{"eventVersion":"1.08","userIdentity":{"type":"AssumedRole","principalId":"redacted:1234567","arn":"arn:aws:sts::1234567:assumed-role/ManagedOpenShift-Installer-Role/1234567","accountId":"1234567","accessKeyId":"redacted","sessionContext":{"sessionIssuer":{"type":"Role","principalId":"redacted","arn":"arn:aws:iam::1234567:role/ManagedOpenShift-Installer-Role","accountId":"1234567","userName":"ManagedOpenShift-Installer-Role"},"webIdFederationData":{},"attributes":{"creationDate":"2023-02-21T04:33:06Z","mfaAuthenticated":"false"}}},"eventTime":"2023-02-21T04:33:09Z","eventSource":"ec2.amazonaws.com","eventName":"TerminateInstances","awsRegion":"ap-southeast-1","sourceIPAddress":"192.0.0.1","userAgent":"APN/1.0 HashiCorp/1.0 Terraform/1.0.11 (+https://www.terraform.io) terraform-provider-aws/dev (+https://registry.terraform.io/providers/hashicorp/aws) aws-sdk-go/1.43.9 (go1.18.7; linux; amd64) HashiCorp-terraform-exec/0.16.1","requestParameters":{"instancesSet":{"items":[{"instanceId":"i-0c123456"}]}},"responseElements":{"requestId":"bd3900cb-1234567","instancesSet":{"items":[{"instanceId":"i-0c123456","currentState":{"code":32,"name":"shutting-down"},"previousState":{"code":16,"name":"running"}}]}},"requestID":"bd3900cb-1234567","eventID":"7064eae0-1234567","readOnly":false,"eventType":"AwsApiCall","managementEvent":true,"recipientAccountId":"1234","eventCategory":"Management","tlsDetails":{"tlsVersion":"TLSv1.2","cipherSuite":"ECDHE-RSA-AES128-GCM-SHA256","clientProvidedHostHeader":"ec2.ap-southeast-1.amazonaws.com"}}`)
					mockClient.EXPECT().PollInstanceStopEventsFor(gomock.Any(), gomock.Any()).Return([]*cloudtrail.Event{&event}, nil)

					// Act
					got, gotErr := isRunning.InvestigateStoppedInstances("")
					// Assert
					Expect(gotErr).NotTo(HaveOccurred())
					Expect(got.UserAuthorized).To(BeTrue())
				})
			})

			When("issuer user is unauthorized (testuser assumed role)", func() {
				It("the deletion will be marked as invalid", func() {
					// Arrange
					mockClient.EXPECT().GetClusterInfo(gomock.Any()).Return(cluster, nil)
					mockClient.EXPECT().GetClusterDeployment(gomock.Eq(cluster.ID())).Return(&clusterDeployment, nil)
					mockClient.EXPECT().GetClusterMachinePools(gomock.Any()).Return(machinePools, nil)
					mockClient.EXPECT().ListNonRunningInstances(gomock.Eq(infraID)).Return([]*ec2.Instance{&instance}, nil)
					mockClient.EXPECT().ListRunningInstances(gomock.Eq(infraID)).Return([]*ec2.Instance{&instance}, nil)
					event.CloudTrailEvent = aws.String(`{"eventVersion":"1.08","userIdentity":{"type":"AssumedRole","principalId":"REDACTED:OCM","arn":"arn:aws:sts::1234:assumed-role/testuser/OCM","accountId":"1234","accessKeyId":"REDACTED","sessionContext":{"sessionIssuer":{"type":"Role","principalId":"REDACTED","arn":"arn:aws:iam::1234:role/testuser","accountId":"1234","userName":"testuser"},"webIdFederationData":{},"attributes":{"creationDate":"2023-02-21T04:08:01Z","mfaAuthenticated":"false"}}},"eventTime":"2023-02-21T04:10:40Z","eventSource":"ec2.amazonaws.com","eventName":"TerminateInstances","awsRegion":"ap-southeast-1","sourceIPAddress":"192.168.0.0","userAgent":"aws-sdk-go-v2/1.17.3 os/linux lang/go/1.19.5 md/GOOS/linux md/GOARCH/amd64 api/ec2/1.25.0","requestParameters":{"instancesSet":{"items":[{"instanceId":"i-00c1f1234567"}]}},"responseElements":{"requestId":"credacted","instancesSet":{"items":[{"instanceId":"i-00c1f1234567","currentState":{"code":32,"name":"shutting-down"},"previousState":{"code":16,"name":"running"}}]}},"requestID":"credacted","eventID":"e55a8a64-9949-47a9-9fff-12345678","readOnly":false,"eventType":"AwsApiCall","managementEvent":true,"recipientAccountId":"1234","eventCategory":"Management","tlsDetails":{"tlsVersion":"TLSv1.2","cipherSuite":"ECDHE-RSA-AES128-GCM-SHA256","clientProvidedHostHeader":"ec2.ap-southeast-1.amazonaws.com"}}`)
					mockClient.EXPECT().PollInstanceStopEventsFor(gomock.Any(), gomock.Any()).Return([]*cloudtrail.Event{&event}, nil)

					// Act
					got, gotErr := isRunning.InvestigateStoppedInstances("")
					// Assert
					Expect(gotErr).NotTo(HaveOccurred())
					Expect(got.UserAuthorized).To(BeFalse())
				})
			})
			When("issuer user is authorized (openshift-machine-api-aws)", func() {
				It("the deletion will be marked as valid", func() {
					// Arrange
					mockClient.EXPECT().GetClusterInfo(gomock.Any()).Return(cluster, nil)
					mockClient.EXPECT().GetClusterDeployment(gomock.Eq(cluster.ID())).Return(&clusterDeployment, nil)
					mockClient.EXPECT().GetClusterMachinePools(gomock.Any()).Return(machinePools, nil)
					mockClient.EXPECT().ListNonRunningInstances(gomock.Eq(infraID)).Return([]*ec2.Instance{&instance}, nil)
					mockClient.EXPECT().ListRunningInstances(gomock.Eq(infraID)).Return([]*ec2.Instance{&instance}, nil)
					event.CloudTrailEvent = aws.String(`{"eventVersion":"1.08","userIdentity":{"type":"AssumedRole","principalId":"PRINCIPALID_REDACTED:1234567789","arn":"arn:aws:sts::1234:assumed-role/cluster-name-n9o7-openshift-machine-api-aws-cloud-credentials/1234567789","accountId":"1234","accessKeyId":"REDACTED","sessionContext":{"sessionIssuer":{"type":"Role","principalId":"PRINCIPALID_REDACTED","arn":"arn:aws:iam::1234:role/cluster-name-n9o7-openshift-machine-api-aws-cloud-credentials","accountId":"1234","userName":"cluster-name-n9o7-openshift-machine-api-aws-cloud-credentials"},"webIdFederationData":{"federatedProvider":"arn:aws:iam::1234:oidc-provider/rh-oidc.s3.us-east-1.amazonaws.com/redacted","attributes":{}},"attributes":{"creationDate":"2023-02-21T04:54:56Z","mfaAuthenticated":"false"}}},"eventTime":"2023-02-21T04:54:56Z","eventSource":"ec2.amazonaws.com","eventName":"TerminateInstances","awsRegion":"ap-southeast-1","sourceIPAddress":"192.168.0.0","userAgent":"aws-sdk-go/1.43.20 (go1.18.7; linux; amd64) openshift.io cluster-api-provider-aws/4.11.0-202301051515.p0.ga796a77.assembly.stream","requestParameters":{"instancesSet":{"items":[{"instanceId":"i-08020c19123456789"}]}},"responseElements":{"requestId":"b8c78d9a-51de-4910-123456789","instancesSet":{"items":[{"instanceId":"i-08020c19123456789","currentState":{"code":32,"name":"shutting-down"},"previousState":{"code":32,"name":"shutting-down"}}]}},"requestID":"b8c78d9a-51de-4910-123456789","eventID":"5455f882-a4db-4505-bea6-123456789","readOnly":false,"eventType":"AwsApiCall","managementEvent":true,"recipientAccountId":"1234","eventCategory":"Management","tlsDetails":{"tlsVersion":"TLSv1.2","cipherSuite":"ECDHE-RSA-AES128-GCM-SHA256","clientProvidedHostHeader":"ec2.ap-southeast-1.amazonaws.com"}}`)
					event.Username = aws.String("1234567789") // ID of the initial jumprole account
					mockClient.EXPECT().PollInstanceStopEventsFor(gomock.Any(), gomock.Any()).Return([]*cloudtrail.Event{&event}, nil)

					// Act
					got, gotErr := isRunning.InvestigateStoppedInstances("")
					// Assert
					Expect(gotErr).NotTo(HaveOccurred())
					Expect(got.UserAuthorized).To(BeTrue())
				})
			})
		})
	})
})

var _ = Describe("ChgmResolved", func() {
	Describe("AreAllInstancesRunning", func() {

		var fakeErr = fmt.Errorf("test resolved")
		var (
			mockCtrl          *gomock.Controller
			mockClient        *mock.MockService
			isRunning         chgm.Client
			cluster           *v1.Cluster
			clusterDeployment hivev1.ClusterDeployment
			machinePools      []*v1.MachinePool
			infraID           string

			masterInstance    ec2.Instance
			masterInstanceTag ec2.Tag
			infraInstance     ec2.Instance
			infraInstanceTag  ec2.Tag
		)
		BeforeEach(func() {
			mockCtrl = gomock.NewController(GinkgoT())
			mockClient = mock.NewMockService(mockCtrl)
			isRunning = chgm.Client{Service: mockClient}
			var err error
			// Must explicitly set all node types for GetNodeCount() to work in these tests
			cluster, err = v1.NewCluster().Nodes(v1.NewClusterNodes().Compute(0).Master(1).Infra(1)).State(v1.ClusterStateReady).Build()
			Expect(err).ToNot(HaveOccurred())
			clusterDeployment = hivev1.ClusterDeployment{
				Spec: hivev1.ClusterDeploymentSpec{
					ClusterMetadata: &hivev1.ClusterMetadata{
						InfraID: "12345",
					},
				},
			}
			infraID = clusterDeployment.Spec.ClusterMetadata.InfraID

			// Setup mock cluster instances
			masterInstanceTag.SetKey("Name")
			masterInstanceTag.SetValue("cluter-test-gzq47-master-0")
			masterInstance = ec2.Instance{
				InstanceId: aws.String("12345"),
				Tags:       []*ec2.Tag{&masterInstanceTag},
			}

			infraInstanceTag.SetKey("Name")
			infraInstanceTag.SetValue("cluster-test-gzq47-infra-0")
			infraInstance = ec2.Instance{
				InstanceId: aws.String("67890"),
				Tags:       []*ec2.Tag{&infraInstanceTag},
			}
		})
		AfterEach(func() {
			mockCtrl.Finish()
		})
		When("the cluster state is undefined", func() {
			It("should return an error", func() {
				statelessCluster, err := v1.NewCluster().ID("statelessCluster").Build()
				Expect(err).ToNot(HaveOccurred())
				statelessDeployment := hivev1.ClusterDeployment{
					Spec: hivev1.ClusterDeploymentSpec{
						ClusterMetadata: &hivev1.ClusterMetadata{
							InfraID:   "statelessCluster",
							ClusterID: "statelessCluster",
						},
					},
				}
				mockClient.EXPECT().GetClusterInfo(gomock.Any()).Return(statelessCluster, nil)
				mockClient.EXPECT().GetClusterDeployment(gomock.Eq(statelessCluster.ID())).Return(&statelessDeployment, nil)

				_, gotErr := isRunning.InvestigateStartedInstances("")
				Expect(gotErr).To(HaveOccurred())
			})
		})
		When("the cluster is uninstalling", func() {
			It("should not investigate the cluster", func() {
				uninstallingCluster, err := v1.NewCluster().ID("uninstallingCluster").State(v1.ClusterStateUninstalling).Build()
				Expect(err).ToNot(HaveOccurred())
				uninstallingClusterDeployment := hivev1.ClusterDeployment{
					Spec: hivev1.ClusterDeploymentSpec{
						ClusterMetadata: &hivev1.ClusterMetadata{
							InfraID:   "uninstallingCluster",
							ClusterID: "uninstallingCluster",
						},
					},
				}

				mockClient.EXPECT().GetClusterInfo(gomock.Any()).Return(uninstallingCluster, nil)
				mockClient.EXPECT().GetClusterDeployment(gomock.Eq(uninstallingCluster.ID())).Return(&uninstallingClusterDeployment, nil)

				got, gotErr := isRunning.InvestigateStartedInstances("uninstallingCluster")
				Expect(gotErr).ToNot(HaveOccurred())
				Expect(got.ClusterNotEvaluated).To(BeTrue())
				Expect(got.ClusterState).To(Equal(string(v1.ClusterStateUninstalling)))
			})
		})
		When("the cluster is in limited support for an unrelated reason", func() {
			It("should not investigate the cluster", func() {
				// Arrange
				mockClient.EXPECT().GetClusterInfo(gomock.Any()).Return(cluster, nil)
				mockClient.EXPECT().GetClusterDeployment(gomock.Eq(cluster.ID())).Return(&clusterDeployment, nil)
				mockClient.EXPECT().NonCADLimitedSupportExists(gomock.Eq(cluster.ID())).Return(true, nil)
				// Act
				got, gotErr := isRunning.InvestigateStartedInstances("lsCluster")
				// Assert
				Expect(gotErr).ToNot(HaveOccurred())
				Expect(got.ClusterNotEvaluated).To(BeTrue())
				Expect(string(got.ClusterState)).To(ContainSubstring("unrelated limited support reasons present on cluster"))
			})
		})
		When("NonCADLimitedSupportExists fails", func() {
			It("should receive the correct internal ID and bubble the error", func() {
				// Arrange
				mockClient.EXPECT().GetClusterInfo(gomock.Any()).Return(cluster, nil)
				mockClient.EXPECT().GetClusterDeployment(gomock.Eq(cluster.ID())).Return(&clusterDeployment, nil)
				mockClient.EXPECT().NonCADLimitedSupportExists(gomock.Eq(cluster.ID())).Return(false, fakeErr)
				// Act
				_, gotErr := isRunning.InvestigateStartedInstances("")
				// Assert
				Expect(gotErr).To(HaveOccurred())
			})
		})
		When("ListRunningInstances fails", func() {
			It("should receive the correct InfraID and bubble the error", func() {
				// Arrange
				mockClient.EXPECT().GetClusterInfo(gomock.Any()).Return(cluster, nil)
				mockClient.EXPECT().GetClusterDeployment(gomock.Eq(cluster.ID())).Return(&clusterDeployment, nil)
				mockClient.EXPECT().NonCADLimitedSupportExists(gomock.Eq(cluster.ID())).Return(false, nil)
				mockClient.EXPECT().ListRunningInstances(gomock.Eq(infraID)).Return(nil, fakeErr)
				// Act
				_, gotErr := isRunning.InvestigateStartedInstances("")
				// Assert
				Expect(gotErr).To(HaveOccurred())
			})
		})
		When("the machine count does not equal the expected node count", func() {
			It("should complete and return that insufficient machines were found", func() {
				// Arrange
				mockClient.EXPECT().GetClusterInfo(gomock.Any()).Return(cluster, nil)
				mockClient.EXPECT().GetClusterDeployment(gomock.Eq(cluster.ID())).Return(&clusterDeployment, nil)
				mockClient.EXPECT().GetClusterMachinePools(gomock.Any()).Return(machinePools, nil)
				mockClient.EXPECT().NonCADLimitedSupportExists(gomock.Eq(cluster.ID())).Return(false, nil)
				mockClient.EXPECT().ListRunningInstances(gomock.Eq(infraID)).Return([]*ec2.Instance{}, nil)
				// Act
				got, gotErr := isRunning.InvestigateStartedInstances("")
				// Assert
				Expect(gotErr).ToNot(HaveOccurred())
				Expect(got.Error).ToNot(BeEmpty())
				Expect(got.UserAuthorized).To(BeTrue())
			})
		})
		When("the cluster appears to be healthy again", func() {
			It("should complete and return that no issues were found", func() {
				// Arrange
				mockClient.EXPECT().GetClusterInfo(gomock.Any()).Return(cluster, nil)
				mockClient.EXPECT().GetClusterDeployment(gomock.Eq(cluster.ID())).Return(&clusterDeployment, nil)
				mockClient.EXPECT().GetClusterMachinePools(gomock.Any()).Return(machinePools, nil)
				mockClient.EXPECT().NonCADLimitedSupportExists(gomock.Eq(cluster.ID())).Return(false, nil)
				mockClient.EXPECT().ListRunningInstances(gomock.Eq(infraID)).Return([]*ec2.Instance{&masterInstance, &infraInstance}, nil)
				// Act
				got, gotErr := isRunning.InvestigateStartedInstances("")
				// Assert
				Expect(gotErr).ToNot(HaveOccurred())
				Expect(got.Error).To(BeEmpty())
				Expect(got.UserAuthorized).To(BeTrue())
				Expect(got.ExpectedInstances.Infra).To(Equal(got.RunningInstances.Infra))
				Expect(got.ExpectedInstances.Master).To(Equal(got.RunningInstances.Master))
			})
		})
	})
})

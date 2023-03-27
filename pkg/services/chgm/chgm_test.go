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
	"github.com/openshift/configuration-anomaly-detection/pkg/ocm"
	"github.com/openshift/configuration-anomaly-detection/pkg/services/chgm"
	"github.com/openshift/configuration-anomaly-detection/pkg/services/chgm/mock"
	hivev1 "github.com/openshift/hive/apis/hive/v1"
)

var _ = Describe("chgm", func() {
	// this is a var but I use it as a const
	var fakeErr = fmt.Errorf("test triggered")
	var (
		mockCtrl           *gomock.Controller
		mockClient         *mock.MockService
		isRunning          chgm.Client
		cluster            *v1.Cluster
		clusterDeployment  hivev1.ClusterDeployment
		machinePools       []*v1.MachinePool
		infraID            string
		instance           ec2.Instance
		chgmLimitedSupport ocm.LimitedSupportReason
		masterInstance     ec2.Instance
		masterInstanceTag  ec2.Tag
		infraInstance      ec2.Instance
		infraInstanceTag   ec2.Tag
		event              cloudtrail.Event
	)
	BeforeEach(func() {
		mockCtrl = gomock.NewController(GinkgoT())
		mockClient = mock.NewMockService(mockCtrl)

		chgmLimitedSupport = ocm.LimitedSupportReason{
			Summary: "Cluster not checking in",
			Details: "Your cluster is no longer checking in with Red Hat OpenShift Cluster Manager. Possible causes include stopped instances or a networking misconfiguration. If you have stopped the cluster instances, please start them again - stopping instances is not supported. If you intended to terminate this cluster then please delete the cluster in the Red Hat console",
		}

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
		instance = ec2.Instance{InstanceId: aws.String("12345")}

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

		event = cloudtrail.Event{
			Username:        aws.String("12345"),
			CloudTrailEvent: aws.String(`{"eventVersion":"1.08"}`),
		}

		isRunning = chgm.Client{
			Service:           mockClient,
			Cluster:           cluster,
			ClusterDeployment: &clusterDeployment,
		}
	})
	AfterEach(func() {
		mockCtrl.Finish()
	})
	Describe("Triggered", func() {
		When("Triggered finds instances stopped by the customer", func() {
			It("should put the cluster into limited support", func() {
				event := cloudtrail.Event{
					Username:        aws.String("12345"),
					CloudTrailEvent: aws.String(`{"eventVersion":"1.08", "userIdentity":{"type":"AssumedRole", "sessionContext":{"sessionIssuer":{"type":"Role", "userName": "654321"}}}}`),
				}
				mockClient.EXPECT().ListNonRunningInstances(gomock.Eq(infraID)).Return([]*ec2.Instance{&infraInstance}, nil)
				mockClient.EXPECT().ListRunningInstances(gomock.Eq(infraID)).Return([]*ec2.Instance{&masterInstance, &infraInstance}, nil)
				mockClient.EXPECT().GetClusterMachinePools(gomock.Any()).Return(machinePools, nil)
				mockClient.EXPECT().PollInstanceStopEventsFor(gomock.Any(), gomock.Any()).Return([]*cloudtrail.Event{&event}, nil)
				mockClient.EXPECT().IsInLimitedSupport(gomock.Eq(cluster.ID())).Return(false, nil)
				mockClient.EXPECT().PostLimitedSupportReason(gomock.Eq(chgmLimitedSupport), gomock.Eq(cluster.ID())).Return(nil)
				// TODO discuss to which degree we want to mock
				mockClient.EXPECT().SilenceAlert(gomock.Any())

				gotErr := isRunning.Triggered()

				Expect(gotErr).NotTo(HaveOccurred())
			})
		})
		When("Triggered errors", func() {
			It("should update the incident notes and escalate to primary", func() {
				mockClient.EXPECT().ListNonRunningInstances(gomock.Any()).Return(nil, fakeErr)
				mockClient.EXPECT().UpdateAndEscalateAlert(gomock.Any()).Return(nil)

				gotErr := isRunning.Triggered()

				Expect(gotErr).NotTo(HaveOccurred())
			})
		})
		When("there were no stopped instances", func() {
			It("should update and escalate to primary", func() {
				mockClient.EXPECT().ListNonRunningInstances(gomock.Eq(infraID)).Return([]*ec2.Instance{}, nil)
				mockClient.EXPECT().ListRunningInstances(gomock.Eq(infraID)).Return([]*ec2.Instance{&masterInstance, &infraInstance}, nil)
				mockClient.EXPECT().GetClusterMachinePools(gomock.Any()).Return(machinePools, nil)
				mockClient.EXPECT().IsInLimitedSupport(gomock.Eq(cluster.ID())).Return(false, nil)
				mockClient.EXPECT().UpdateAndEscalateAlert(gomock.Any()).Return(nil)
				gotErr := isRunning.Triggered()
				// Assert
				Expect(gotErr).ToNot(HaveOccurred())
			})
		})
		When("there was an error getting StopInstancesEvents", func() {
			It("should update and escalate to primary", func() {
				mockClient.EXPECT().ListNonRunningInstances(gomock.Eq(infraID)).Return([]*ec2.Instance{&instance}, nil)
				mockClient.EXPECT().ListRunningInstances(gomock.Eq(infraID)).Return([]*ec2.Instance{&instance}, nil)
				mockClient.EXPECT().GetClusterMachinePools(gomock.Any()).Return(machinePools, nil)
				mockClient.EXPECT().PollInstanceStopEventsFor(gomock.Any(), gomock.Any()).Return(nil, fakeErr)

				mockClient.EXPECT().UpdateAndEscalateAlert(gomock.Any()).Return(nil)

				gotErr := isRunning.Triggered()
				Expect(gotErr).ToNot(HaveOccurred())
			})
		})
		When("there were no StopInstancesEvents", func() {
			It("should update and escalate to primary", func() {
				// Arrange
				mockClient.EXPECT().ListRunningInstances(gomock.Eq(infraID)).Return([]*ec2.Instance{&instance}, nil)
				mockClient.EXPECT().GetClusterMachinePools(gomock.Any()).Return(machinePools, nil)
				mockClient.EXPECT().ListNonRunningInstances(gomock.Eq(infraID)).Return([]*ec2.Instance{&instance}, nil)
				mockClient.EXPECT().PollInstanceStopEventsFor(gomock.Any(), gomock.Any()).Return([]*cloudtrail.Event{}, nil)
				mockClient.EXPECT().UpdateAndEscalateAlert(gomock.Any()).Return(nil)
				// Act
				gotErr := isRunning.Triggered()
				Expect(gotErr).ToNot(HaveOccurred())
			})
		})
		When("the returned CloudTrailEventRaw base data is correct, but the sessionissue's username is not an authorized user", func() {
			It("should be put into limited support", func() {
				mockClient.EXPECT().GetClusterMachinePools(gomock.Any()).Return(machinePools, nil)
				mockClient.EXPECT().ListNonRunningInstances(gomock.Eq(infraID)).Return([]*ec2.Instance{&instance}, nil)
				mockClient.EXPECT().ListRunningInstances(gomock.Eq(infraID)).Return([]*ec2.Instance{&instance}, nil)
				event.CloudTrailEvent = aws.String(`{"eventVersion":"1.08", "userIdentity":{"type":"AssumedRole", "sessionContext":{"sessionIssuer":{"type":"Role", "userName": "654321"}}}}`)
				mockClient.EXPECT().PollInstanceStopEventsFor(gomock.Any(), gomock.Any()).Return([]*cloudtrail.Event{&event}, nil)
				mockClient.EXPECT().IsInLimitedSupport(gomock.Eq(cluster.ID())).Return(false, nil)
				mockClient.EXPECT().PostLimitedSupportReason(gomock.Eq(chgmLimitedSupport), gomock.Eq(cluster.ID())).Return(nil)
				mockClient.EXPECT().SilenceAlert(gomock.Any()).Return(nil)

				// Act
				gotErr := isRunning.Triggered()
				// Assert
				Expect(gotErr).NotTo(HaveOccurred())
			})
		})
		When("issuer user is authorized (openshift-machine-api-aws)", func() {
			It("should update and escalate to primary", func() {
				mockClient.EXPECT().GetClusterMachinePools(gomock.Any()).Return(machinePools, nil)
				mockClient.EXPECT().ListNonRunningInstances(gomock.Eq(infraID)).Return([]*ec2.Instance{&instance}, nil)
				mockClient.EXPECT().ListRunningInstances(gomock.Eq(infraID)).Return([]*ec2.Instance{&instance}, nil)
				event.CloudTrailEvent = aws.String(`{"eventVersion":"1.08","userIdentity":{"type":"AssumedRole","principalId":"PRINCIPALID_REDACTED:1234567789","arn":"arn:aws:sts::1234:assumed-role/cluster-name-n9o7-openshift-machine-api-aws-cloud-credentials/1234567789","accountId":"1234","accessKeyId":"REDACTED","sessionContext":{"sessionIssuer":{"type":"Role","principalId":"PRINCIPALID_REDACTED","arn":"arn:aws:iam::1234:role/cluster-name-n9o7-openshift-machine-api-aws-cloud-credentials","accountId":"1234","userName":"cluster-name-n9o7-openshift-machine-api-aws-cloud-credentials"},"webIdFederationData":{"federatedProvider":"arn:aws:iam::1234:oidc-provider/rh-oidc.s3.us-east-1.amazonaws.com/redacted","attributes":{}},"attributes":{"creationDate":"2023-02-21T04:54:56Z","mfaAuthenticated":"false"}}},"eventTime":"2023-02-21T04:54:56Z","eventSource":"ec2.amazonaws.com","eventName":"TerminateInstances","awsRegion":"ap-southeast-1","sourceIPAddress":"192.168.0.0","userAgent":"aws-sdk-go/1.43.20 (go1.18.7; linux; amd64) openshift.io cluster-api-provider-aws/4.11.0-202301051515.p0.ga796a77.assembly.stream","requestParameters":{"instancesSet":{"items":[{"instanceId":"i-08020c19123456789"}]}},"responseElements":{"requestId":"b8c78d9a-51de-4910-123456789","instancesSet":{"items":[{"instanceId":"i-08020c19123456789","currentState":{"code":32,"name":"shutting-down"},"previousState":{"code":32,"name":"shutting-down"}}]}},"requestID":"b8c78d9a-51de-4910-123456789","eventID":"5455f882-a4db-4505-bea6-123456789","readOnly":false,"eventType":"AwsApiCall","managementEvent":true,"recipientAccountId":"1234","eventCategory":"Management","tlsDetails":{"tlsVersion":"TLSv1.2","cipherSuite":"ECDHE-RSA-AES128-GCM-SHA256","clientProvidedHostHeader":"ec2.ap-southeast-1.amazonaws.com"}}`)
				event.Username = aws.String("1234567789") // ID of the initial jumprole account
				mockClient.EXPECT().PollInstanceStopEventsFor(gomock.Any(), gomock.Any()).Return([]*cloudtrail.Event{&event}, nil)
				mockClient.EXPECT().IsInLimitedSupport(gomock.Eq(cluster.ID())).Return(false, nil)
				mockClient.EXPECT().UpdateAndEscalateAlert(gomock.Any()).Return(nil)

				gotErr := isRunning.Triggered()
				Expect(gotErr).NotTo(HaveOccurred())
			})
		})
		When("username role is OrganizationAccountAccessRole", func() {
			It("should update and escalate to primary", func() {
				mockClient.EXPECT().GetClusterMachinePools(gomock.Any()).Return(machinePools, nil)
				mockClient.EXPECT().ListNonRunningInstances(gomock.Eq(infraID)).Return([]*ec2.Instance{&instance}, nil)
				mockClient.EXPECT().ListRunningInstances(gomock.Eq(infraID)).Return([]*ec2.Instance{&instance}, nil)
				event.CloudTrailEvent = aws.String(`{"eventVersion":"1.08", "userIdentity":{"type":"AssumedRole", "sessionContext":{"sessionIssuer":{"type":"Role", "userName": "OrganizationAccountAccessRole"}}}}`)
				mockClient.EXPECT().PollInstanceStopEventsFor(gomock.Any(), gomock.Any()).Return([]*cloudtrail.Event{&event}, nil)
				mockClient.EXPECT().IsInLimitedSupport(gomock.Eq(cluster.ID())).Return(false, nil)
				mockClient.EXPECT().UpdateAndEscalateAlert(gomock.Any()).Return(nil)

				gotErr := isRunning.Triggered()
				Expect(gotErr).NotTo(HaveOccurred())
			})
		})

		When("issuer user is authorized (ManagedOpenShift-Installer-Role)", func() {
			It("should update and escalate to primary", func() {
				mockClient.EXPECT().GetClusterMachinePools(gomock.Any()).Return(machinePools, nil)
				mockClient.EXPECT().ListNonRunningInstances(gomock.Eq(infraID)).Return([]*ec2.Instance{&instance}, nil)
				mockClient.EXPECT().ListRunningInstances(gomock.Eq(infraID)).Return([]*ec2.Instance{&instance}, nil)
				event.CloudTrailEvent = aws.String(`{"eventVersion":"1.08","userIdentity":{"type":"AssumedRole","principalId":"redacted:1234567","arn":"arn:aws:sts::1234567:assumed-role/ManagedOpenShift-Installer-Role/1234567","accountId":"1234567","accessKeyId":"redacted","sessionContext":{"sessionIssuer":{"type":"Role","principalId":"redacted","arn":"arn:aws:iam::1234567:role/ManagedOpenShift-Installer-Role","accountId":"1234567","userName":"ManagedOpenShift-Installer-Role"},"webIdFederationData":{},"attributes":{"creationDate":"2023-02-21T04:33:06Z","mfaAuthenticated":"false"}}},"eventTime":"2023-02-21T04:33:09Z","eventSource":"ec2.amazonaws.com","eventName":"TerminateInstances","awsRegion":"ap-southeast-1","sourceIPAddress":"192.0.0.1","userAgent":"APN/1.0 HashiCorp/1.0 Terraform/1.0.11 (+https://www.terraform.io) terraform-provider-aws/dev (+https://registry.terraform.io/providers/hashicorp/aws) aws-sdk-go/1.43.9 (go1.18.7; linux; amd64) HashiCorp-terraform-exec/0.16.1","requestParameters":{"instancesSet":{"items":[{"instanceId":"i-0c123456"}]}},"responseElements":{"requestId":"bd3900cb-1234567","instancesSet":{"items":[{"instanceId":"i-0c123456","currentState":{"code":32,"name":"shutting-down"},"previousState":{"code":16,"name":"running"}}]}},"requestID":"bd3900cb-1234567","eventID":"7064eae0-1234567","readOnly":false,"eventType":"AwsApiCall","managementEvent":true,"recipientAccountId":"1234","eventCategory":"Management","tlsDetails":{"tlsVersion":"TLSv1.2","cipherSuite":"ECDHE-RSA-AES128-GCM-SHA256","clientProvidedHostHeader":"ec2.ap-southeast-1.amazonaws.com"}}`)
				mockClient.EXPECT().PollInstanceStopEventsFor(gomock.Any(), gomock.Any()).Return([]*cloudtrail.Event{&event}, nil)
				mockClient.EXPECT().IsInLimitedSupport(gomock.Eq(cluster.ID())).Return(false, nil)
				mockClient.EXPECT().UpdateAndEscalateAlert(gomock.Any()).Return(nil)

				gotErr := isRunning.Triggered()
				Expect(gotErr).NotTo(HaveOccurred())
			})
		})
		When("the returned CloudTrailEvent has a matching valid operatorname", func() {
			It("should update and escalate to primary", func() {
				mockClient.EXPECT().GetClusterMachinePools(gomock.Any()).Return(machinePools, nil)
				mockClient.EXPECT().ListNonRunningInstances(gomock.Eq(infraID)).Return([]*ec2.Instance{&instance}, nil)
				mockClient.EXPECT().ListRunningInstances(gomock.Eq(infraID)).Return([]*ec2.Instance{&instance}, nil)
				event.Username = aws.String("osdManagedAdmin-abcd")
				mockClient.EXPECT().PollInstanceStopEventsFor(gomock.Any(), gomock.Any()).Return([]*cloudtrail.Event{&event}, nil)
				mockClient.EXPECT().IsInLimitedSupport(gomock.Eq(cluster.ID())).Return(false, nil)
				mockClient.EXPECT().UpdateAndEscalateAlert(gomock.Any()).Return(nil)

				gotErr := isRunning.Triggered()
				Expect(gotErr).NotTo(HaveOccurred())
			})
		})
		When("the returned CloudTrailEventRaw has an empty userIdentity", func() {
			It("should be put into limited support", func() {
				mockClient.EXPECT().GetClusterMachinePools(gomock.Any()).Return(machinePools, nil)
				mockClient.EXPECT().ListNonRunningInstances(gomock.Eq(infraID)).Return([]*ec2.Instance{&instance}, nil)
				mockClient.EXPECT().ListRunningInstances(gomock.Eq(infraID)).Return([]*ec2.Instance{&instance}, nil)
				event.CloudTrailEvent = aws.String(`{"eventVersion":"1.08", "userIdentity":{}}`)
				mockClient.EXPECT().PollInstanceStopEventsFor(gomock.Any(), gomock.Any()).Return([]*cloudtrail.Event{&event}, nil)
				mockClient.EXPECT().IsInLimitedSupport(gomock.Eq(cluster.ID())).Return(false, nil)
				mockClient.EXPECT().PostLimitedSupportReason(gomock.Eq(chgmLimitedSupport), gomock.Eq(cluster.ID())).Return(nil)
				mockClient.EXPECT().SilenceAlert(gomock.Any()).Return(nil)

				gotErr := isRunning.Triggered()
				Expect(gotErr).NotTo(HaveOccurred())
			})
		})
		When("issuer user is unauthorized (testuser assumed role)", func() {
			It("should be put into limited support", func() {
				mockClient.EXPECT().GetClusterMachinePools(gomock.Any()).Return(machinePools, nil)
				mockClient.EXPECT().ListNonRunningInstances(gomock.Eq(infraID)).Return([]*ec2.Instance{&instance}, nil)
				mockClient.EXPECT().ListRunningInstances(gomock.Eq(infraID)).Return([]*ec2.Instance{&instance}, nil)
				event.CloudTrailEvent = aws.String(`{"eventVersion":"1.08","userIdentity":{"type":"AssumedRole","principalId":"REDACTED:OCM","arn":"arn:aws:sts::1234:assumed-role/testuser/OCM","accountId":"1234","accessKeyId":"REDACTED","sessionContext":{"sessionIssuer":{"type":"Role","principalId":"REDACTED","arn":"arn:aws:iam::1234:role/testuser","accountId":"1234","userName":"testuser"},"webIdFederationData":{},"attributes":{"creationDate":"2023-02-21T04:08:01Z","mfaAuthenticated":"false"}}},"eventTime":"2023-02-21T04:10:40Z","eventSource":"ec2.amazonaws.com","eventName":"TerminateInstances","awsRegion":"ap-southeast-1","sourceIPAddress":"192.168.0.0","userAgent":"aws-sdk-go-v2/1.17.3 os/linux lang/go/1.19.5 md/GOOS/linux md/GOARCH/amd64 api/ec2/1.25.0","requestParameters":{"instancesSet":{"items":[{"instanceId":"i-00c1f1234567"}]}},"responseElements":{"requestId":"credacted","instancesSet":{"items":[{"instanceId":"i-00c1f1234567","currentState":{"code":32,"name":"shutting-down"},"previousState":{"code":16,"name":"running"}}]}},"requestID":"credacted","eventID":"e55a8a64-9949-47a9-9fff-12345678","readOnly":false,"eventType":"AwsApiCall","managementEvent":true,"recipientAccountId":"1234","eventCategory":"Management","tlsDetails":{"tlsVersion":"TLSv1.2","cipherSuite":"ECDHE-RSA-AES128-GCM-SHA256","clientProvidedHostHeader":"ec2.ap-southeast-1.amazonaws.com"}}`)
				mockClient.EXPECT().PollInstanceStopEventsFor(gomock.Any(), gomock.Any()).Return([]*cloudtrail.Event{&event}, nil)
				mockClient.EXPECT().IsInLimitedSupport(gomock.Eq(cluster.ID())).Return(false, nil)
				mockClient.EXPECT().PostLimitedSupportReason(gomock.Eq(chgmLimitedSupport), gomock.Eq(cluster.ID())).Return(nil)
				mockClient.EXPECT().SilenceAlert(gomock.Any()).Return(nil)

				gotErr := isRunning.Triggered()
				Expect(gotErr).NotTo(HaveOccurred())
			})
		})
		When("the returned CloudTrailEventRaw base data is correct, but the sessionissue's role is not role", func() {
			It("should be put into limited support", func() {
				mockClient.EXPECT().GetClusterMachinePools(gomock.Any()).Return(machinePools, nil)
				mockClient.EXPECT().ListNonRunningInstances(gomock.Eq(infraID)).Return([]*ec2.Instance{&instance}, nil)
				mockClient.EXPECT().ListRunningInstances(gomock.Eq(infraID)).Return([]*ec2.Instance{&instance}, nil)
				event.CloudTrailEvent = aws.String(`{"eventVersion":"1.08", "userIdentity":{"type":"AssumedRole", "sessionContext":{"sessionIssuer":{"type":"test"}}}}`)
				mockClient.EXPECT().PollInstanceStopEventsFor(gomock.Any(), gomock.Any()).Return([]*cloudtrail.Event{&event}, nil)
				mockClient.EXPECT().IsInLimitedSupport(gomock.Eq(cluster.ID())).Return(false, nil)
				mockClient.EXPECT().PostLimitedSupportReason(gomock.Eq(chgmLimitedSupport), gomock.Eq(cluster.ID())).Return(nil)
				mockClient.EXPECT().SilenceAlert(gomock.Any()).Return(nil)

				gotErr := isRunning.Triggered()
				Expect(gotErr).NotTo(HaveOccurred())
			})
		})
		When("the returned CloudTrailEventRaw has no data", func() {
			It("should be put into limited support", func() {
				mockClient.EXPECT().GetClusterMachinePools(gomock.Any()).Return(machinePools, nil)
				mockClient.EXPECT().ListNonRunningInstances(gomock.Eq(infraID)).Return([]*ec2.Instance{&instance}, nil)
				mockClient.EXPECT().ListRunningInstances(gomock.Eq(infraID)).Return([]*ec2.Instance{&instance}, nil)
				mockClient.EXPECT().PollInstanceStopEventsFor(gomock.Any(), gomock.Any()).Return([]*cloudtrail.Event{&event}, nil)
				mockClient.EXPECT().IsInLimitedSupport(gomock.Eq(cluster.ID())).Return(false, nil)
				mockClient.EXPECT().PostLimitedSupportReason(gomock.Eq(chgmLimitedSupport), gomock.Eq(cluster.ID())).Return(nil)
				mockClient.EXPECT().SilenceAlert(gomock.Any()).Return(nil)

				gotErr := isRunning.Triggered()
				Expect(gotErr).NotTo(HaveOccurred())
			})
		})

		When("the returned CloudTrailEventRaw has an empty userIdentity", func() {
			It("should be put into limited support", func() {
				mockClient.EXPECT().GetClusterMachinePools(gomock.Any()).Return(machinePools, nil)
				mockClient.EXPECT().ListNonRunningInstances(gomock.Eq(infraID)).Return([]*ec2.Instance{&instance}, nil)
				mockClient.EXPECT().ListRunningInstances(gomock.Eq(infraID)).Return([]*ec2.Instance{&instance}, nil)
				event.CloudTrailEvent = aws.String(`{"eventVersion":"1.08", "userIdentity":{}}`)
				mockClient.EXPECT().PollInstanceStopEventsFor(gomock.Any(), gomock.Any()).Return([]*cloudtrail.Event{&event}, nil)
				mockClient.EXPECT().IsInLimitedSupport(gomock.Eq(cluster.ID())).Return(false, nil)
				mockClient.EXPECT().PostLimitedSupportReason(gomock.Eq(chgmLimitedSupport), gomock.Eq(cluster.ID())).Return(nil)
				mockClient.EXPECT().SilenceAlert(gomock.Any()).Return(nil)

				gotErr := isRunning.Triggered()
				Expect(gotErr).NotTo(HaveOccurred())
			})
		})

		When("the returned CloudTrailEventRaw has a userIdentity is an iam user", func() {
			It("should be put into limited support", func() {
				mockClient.EXPECT().GetClusterMachinePools(gomock.Any()).Return(machinePools, nil)
				mockClient.EXPECT().ListNonRunningInstances(gomock.Eq(infraID)).Return([]*ec2.Instance{&instance}, nil)
				mockClient.EXPECT().ListRunningInstances(gomock.Eq(infraID)).Return([]*ec2.Instance{&instance}, nil)
				event.CloudTrailEvent = aws.String(`{"eventVersion":"1.08", "userIdentity":{"type":"IAMUser"}}`)
				mockClient.EXPECT().PollInstanceStopEventsFor(gomock.Any(), gomock.Any()).Return([]*cloudtrail.Event{&event}, nil)
				mockClient.EXPECT().IsInLimitedSupport(gomock.Eq(cluster.ID())).Return(false, nil)
				mockClient.EXPECT().PostLimitedSupportReason(gomock.Eq(chgmLimitedSupport), gomock.Eq(cluster.ID())).Return(nil)
				mockClient.EXPECT().SilenceAlert(gomock.Any()).Return(nil)

				gotErr := isRunning.Triggered()
				Expect(gotErr).NotTo(HaveOccurred())
			})
		})
		When("the returned CloudTrailEvent has more than one resource", func() {
			It("it should fail, add notes to the incident and escalate to primary", func() {
				mockClient.EXPECT().GetClusterMachinePools(gomock.Any()).Return(machinePools, nil)
				mockClient.EXPECT().ListNonRunningInstances(gomock.Eq(infraID)).Return([]*ec2.Instance{&instance}, nil)
				mockClient.EXPECT().ListRunningInstances(gomock.Eq(infraID)).Return([]*ec2.Instance{&instance}, nil)
				event.CloudTrailEvent = aws.String(`{}`)
				cloudTrailResource := cloudtrail.Resource{ResourceName: aws.String("123456")}
				event.Resources = []*cloudtrail.Resource{&cloudTrailResource}
				mockClient.EXPECT().PollInstanceStopEventsFor(gomock.Any(), gomock.Any()).Return([]*cloudtrail.Event{&event}, nil)
				mockClient.EXPECT().UpdateAndEscalateAlert(gomock.Any()).Return(nil)

				gotErr := isRunning.Triggered()
				Expect(gotErr).NotTo(HaveOccurred())
			})
		})
		When("the returned CloudTrailEvent is empty", func() {
			It("it should fail, add notes to the incident and escalate to primary", func() {
				mockClient.EXPECT().GetClusterMachinePools(gomock.Any()).Return(machinePools, nil)
				mockClient.EXPECT().ListNonRunningInstances(gomock.Eq(infraID)).Return([]*ec2.Instance{&instance}, nil)
				mockClient.EXPECT().ListRunningInstances(gomock.Eq(infraID)).Return([]*ec2.Instance{&instance}, nil)
				event.CloudTrailEvent = aws.String(`{}`)
				cloudTrailResource := cloudtrail.Resource{ResourceName: aws.String("123456")}
				event.Resources = []*cloudtrail.Resource{&cloudTrailResource}
				mockClient.EXPECT().PollInstanceStopEventsFor(gomock.Any(), gomock.Any()).Return([]*cloudtrail.Event{}, nil)
				mockClient.EXPECT().UpdateAndEscalateAlert(gomock.Any()).Return(nil)

				gotErr := isRunning.Triggered()
				Expect(gotErr).NotTo(HaveOccurred())
			})
		})
		When("the returned CloudTrailEvent is an empty string", func() {
			It("it should fail, add notes to the incident and escalate to primary", func() {
				mockClient.EXPECT().GetClusterMachinePools(gomock.Any()).Return(machinePools, nil)
				mockClient.EXPECT().ListNonRunningInstances(gomock.Eq(infraID)).Return([]*ec2.Instance{&instance}, nil)
				mockClient.EXPECT().ListRunningInstances(gomock.Eq(infraID)).Return([]*ec2.Instance{&instance}, nil)
				event.CloudTrailEvent = aws.String(``)
				cloudTrailResource := cloudtrail.Resource{ResourceName: aws.String("123456")}
				event.Resources = []*cloudtrail.Resource{&cloudTrailResource}
				mockClient.EXPECT().PollInstanceStopEventsFor(gomock.Any(), gomock.Any()).Return([]*cloudtrail.Event{&event}, nil)
				mockClient.EXPECT().UpdateAndEscalateAlert(gomock.Any()).Return(nil)

				gotErr := isRunning.Triggered()
				Expect(gotErr).NotTo(HaveOccurred())
			})
		})
		When("the returned CloudTrailEvent is an empty json", func() {
			It("it should fail, add notes to the incident and escalate to primary", func() {
				mockClient.EXPECT().GetClusterMachinePools(gomock.Any()).Return(machinePools, nil)
				mockClient.EXPECT().ListNonRunningInstances(gomock.Eq(infraID)).Return([]*ec2.Instance{&instance}, nil)
				mockClient.EXPECT().ListRunningInstances(gomock.Eq(infraID)).Return([]*ec2.Instance{&instance}, nil)
				event.CloudTrailEvent = aws.String(`{}`)
				cloudTrailResource := cloudtrail.Resource{ResourceName: aws.String("123456")}
				event.Resources = []*cloudtrail.Resource{&cloudTrailResource}
				mockClient.EXPECT().PollInstanceStopEventsFor(gomock.Any(), gomock.Any()).Return([]*cloudtrail.Event{&event}, nil)
				mockClient.EXPECT().UpdateAndEscalateAlert(gomock.Any()).Return(nil)

				gotErr := isRunning.Triggered()
				Expect(gotErr).NotTo(HaveOccurred())
			})
		})
		When("the returned CloudTrailEvent is an invalid json", func() {
			It("it should fail, add notes to the incident and escalate to primary", func() {
				mockClient.EXPECT().GetClusterMachinePools(gomock.Any()).Return(machinePools, nil)
				mockClient.EXPECT().ListNonRunningInstances(gomock.Eq(infraID)).Return([]*ec2.Instance{&instance}, nil)
				mockClient.EXPECT().ListRunningInstances(gomock.Eq(infraID)).Return([]*ec2.Instance{&instance}, nil)
				event.CloudTrailEvent = aws.String(`{`)
				cloudTrailResource := cloudtrail.Resource{ResourceName: aws.String("123456")}
				event.Resources = []*cloudtrail.Resource{&cloudTrailResource}
				mockClient.EXPECT().PollInstanceStopEventsFor(gomock.Any(), gomock.Any()).Return([]*cloudtrail.Event{&event}, nil)
				mockClient.EXPECT().UpdateAndEscalateAlert(gomock.Any()).Return(nil)

				gotErr := isRunning.Triggered()
				Expect(gotErr).NotTo(HaveOccurred())
			})
		})

	})
	Describe("Resolved", func() {
		var err error
		When("the cluster is uninstalling", func() {
			It("should not investigate the cluster", func() {
				isRunning.Cluster, err = v1.NewCluster().ID("uninstallingCluster").State(v1.ClusterStateUninstalling).Build()
				Expect(err).ToNot(HaveOccurred())
				isRunning.ClusterDeployment = &hivev1.ClusterDeployment{
					Spec: hivev1.ClusterDeploymentSpec{
						ClusterMetadata: &hivev1.ClusterMetadata{
							InfraID:   "uninstallingCluster",
							ClusterID: "uninstallingCluster",
						},
					},
				}
				mockClient.EXPECT().LimitedSupportReasonExists(gomock.Eq(chgmLimitedSupport), gomock.Eq("uninstallingCluster")).Return(true, nil)
				mockClient.EXPECT().AddNote(gomock.Any()).Return(nil)
				gotErr := isRunning.Resolved()
				Expect(gotErr).ToNot(HaveOccurred())
			})
		})
		When("the cluster is in limited support for an unrelated reason", func() {
			It("should not investigate the cluster", func() {
				// Arrange
				mockClient.EXPECT().LimitedSupportReasonExists(gomock.Eq(chgmLimitedSupport), gomock.Eq(cluster.ID())).Return(true, nil)
				mockClient.EXPECT().UnrelatedLimitedSupportExists(gomock.Eq(chgmLimitedSupport), gomock.Eq(cluster.ID())).Return(true, nil)
				mockClient.EXPECT().AddNote(gomock.Any()).Return(nil)
				// Act
				gotErr := isRunning.Resolved()
				// Assert
				Expect(gotErr).ToNot(HaveOccurred())
			})
		})
		When("UnrelatedLimitedSupportReasonExists fails", func() {
			It("should alert primary for an investigation failure", func() {
				// Arrange
				mockClient.EXPECT().LimitedSupportReasonExists(gomock.Eq(chgmLimitedSupport), gomock.Eq(cluster.ID())).Return(true, nil)
				mockClient.EXPECT().UnrelatedLimitedSupportExists(gomock.Eq(chgmLimitedSupport), gomock.Eq(cluster.ID())).Return(false, fakeErr)
				// Should we mock the alerts here?
				mockClient.EXPECT().AddNote(gomock.Any()).Return(nil)
				mockClient.EXPECT().GetServiceID().Return("")
				mockClient.EXPECT().CreateNewAlert(gomock.Any(), gomock.Any()).Return(nil)
				// Act
				gotErr := isRunning.Resolved()
				// Assert
				Expect(gotErr).To(HaveOccurred())
			})
		})
		When("ListRunningInstances fails", func() {
			It("should alert primary for an investigation failure", func() {
				// Arrange
				mockClient.EXPECT().LimitedSupportReasonExists(gomock.Eq(chgmLimitedSupport), gomock.Eq(cluster.ID())).Return(true, nil)
				mockClient.EXPECT().UnrelatedLimitedSupportExists(gomock.Eq(chgmLimitedSupport), gomock.Eq(cluster.ID())).Return(false, nil)
				mockClient.EXPECT().ListRunningInstances(gomock.Eq(infraID)).Return(nil, fakeErr)
				mockClient.EXPECT().AddNote(gomock.Any()).Return(nil)
				mockClient.EXPECT().GetServiceID().Return("")
				mockClient.EXPECT().CreateNewAlert(gomock.Any(), gomock.Any()).Return(nil)
				// Act
				gotErr := isRunning.Resolved()
				// Assert
				Expect(gotErr).To(HaveOccurred())
			})
		})
		When("the cluster appears to be healthy again", func() {
			It("should complete and remove the chgm limited support reason", func() {
				// Arrange
				mockClient.EXPECT().GetClusterMachinePools(gomock.Any()).Return(machinePools, nil)
				mockClient.EXPECT().LimitedSupportReasonExists(gomock.Eq(chgmLimitedSupport), gomock.Eq(cluster.ID())).Return(true, nil)
				mockClient.EXPECT().UnrelatedLimitedSupportExists(gomock.Eq(chgmLimitedSupport), gomock.Eq(cluster.ID())).Return(false, nil)
				mockClient.EXPECT().ListRunningInstances(gomock.Eq(infraID)).Return([]*ec2.Instance{&masterInstance, &infraInstance}, nil)
				mockClient.EXPECT().DeleteLimitedSupportReasons(chgmLimitedSupport, "")
				// Act
				gotErr := isRunning.Resolved()
				// Assert
				Expect(gotErr).ToNot(HaveOccurred())
			})
		})
	})
})

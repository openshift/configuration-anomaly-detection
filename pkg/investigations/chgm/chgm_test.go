package chgm

import (
	"fmt"

	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	cloudtrailv2types "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	ec2v2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	cmv1 "github.com/openshift-online/ocm-sdk-go/clustersmgmt/v1"
	servicelogsv1 "github.com/openshift-online/ocm-sdk-go/servicelogs/v1"
	awsmock "github.com/openshift/configuration-anomaly-detection/pkg/aws/mock"
	investigation "github.com/openshift/configuration-anomaly-detection/pkg/investigations/investigation"
	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
	ocmmock "github.com/openshift/configuration-anomaly-detection/pkg/ocm/mock"
	pdmock "github.com/openshift/configuration-anomaly-detection/pkg/pagerduty/mock"
	hivev1 "github.com/openshift/hive/apis/hive/v1"
	"go.uber.org/mock/gomock"
)

var _ = Describe("chgm", func() {
	// this is a var but I use it as a const
	fakeErr := fmt.Errorf("test triggered")
	var (
		r                 *investigation.Resources
		mockCtrl          *gomock.Controller
		cluster           *cmv1.Cluster
		clusterDeployment *hivev1.ClusterDeployment
		machinePools      []*cmv1.MachinePool
		infraID           string
		instance          ec2v2types.Instance
		masterInstance    ec2v2types.Instance
		masterInstanceTag ec2v2types.Tag
		infraInstance     ec2v2types.Instance
		infraInstanceTag  ec2v2types.Tag
		event             cloudtrailv2types.Event
	)
	BeforeEach(func() {
		logging.InitLogger("fatal", "", "") // Mute logger for the tests
		mockCtrl = gomock.NewController(GinkgoT())

		var err error

		region := cmv1.NewCloudRegion().Name("us-east-1")

		// Must explicitly set all node types for GetNodeCount() to work in these tests
		cluster, err = cmv1.NewCluster().Nodes(cmv1.NewClusterNodes().Compute(0).Master(1).Infra(1)).State(cmv1.ClusterStateReady).Region(region).Build()
		Expect(err).ToNot(HaveOccurred())
		clusterDeployment = &hivev1.ClusterDeployment{
			Spec: hivev1.ClusterDeploymentSpec{
				ClusterMetadata: &hivev1.ClusterMetadata{
					InfraID: "12345",
				},
			},
		}
		infraID = clusterDeployment.Spec.ClusterMetadata.InfraID
		instance = ec2v2types.Instance{InstanceId: awsv2.String("12345")}

		// Setup mock cluster instances
		masterInstanceTag.Key = awsv2.String("Name")
		masterInstanceTag.Value = awsv2.String("cluter-test-gzq47-master-0")
		masterInstance = ec2v2types.Instance{
			InstanceId: awsv2.String("12345"),
			Tags:       []ec2v2types.Tag{masterInstanceTag},
		}

		infraInstanceTag.Key = awsv2.String("Name")
		infraInstanceTag.Value = awsv2.String("cluster-test-gzq47-infra-0")
		infraInstance = ec2v2types.Instance{
			InstanceId: awsv2.String("67890"),
			Tags:       []ec2v2types.Tag{infraInstanceTag},
		}

		event = cloudtrailv2types.Event{
			Username:        awsv2.String("12345"),
			CloudTrailEvent: awsv2.String(`{"eventVersion":"1.08"}`),
		}

		r = &investigation.Resources{}

		r.Cluster = cluster
		r.ClusterDeployment = clusterDeployment
		r.AwsClient = awsmock.NewMockClient(mockCtrl)
		r.OcmClient = ocmmock.NewMockClient(mockCtrl)
		r.PdClient = pdmock.NewMockClient(mockCtrl)

		fmt.Println(instance, event)
	})
	AfterEach(func() {
		mockCtrl.Finish()
	})

	inv := Investiation{}

	Describe("Triggered", func() {
		When("Triggered finds instances stopped by the customer", func() {
			It("should put the cluster on limited support", func() {
				event := cloudtrailv2types.Event{
					Username:        awsv2.String("12345"),
					CloudTrailEvent: awsv2.String(`{"eventVersion":"1.08", "userIdentity":{"type":"AssumedRole", "sessionContext":{"sessionIssuer":{"type":"Role", "userName": "654321"}}}}`),
				}
				// We need to cast it to the mock client, as the investigationResources are unaware the underlying functions are mocks
				r.AwsClient.(*awsmock.MockClient).EXPECT().ListNonRunningInstances(gomock.Eq(infraID)).Return([]ec2v2types.Instance{infraInstance}, nil)
				r.AwsClient.(*awsmock.MockClient).EXPECT().ListRunningInstances(gomock.Eq(infraID)).Return([]ec2v2types.Instance{masterInstance, infraInstance}, nil)
				r.OcmClient.(*ocmmock.MockClient).EXPECT().GetClusterMachinePools(gomock.Any()).Return(machinePools, nil)
				r.AwsClient.(*awsmock.MockClient).EXPECT().PollInstanceStopEventsFor(gomock.Any(), gomock.Any()).Return([]cloudtrailv2types.Event{event}, nil)
				r.OcmClient.(*ocmmock.MockClient).EXPECT().PostLimitedSupportReason(gomock.Eq(&stoppedInfraLS), gomock.Eq(cluster.ID())).Return(nil)
				r.PdClient.(*pdmock.MockClient).EXPECT().SilenceIncidentWithNote(gomock.Any())

				result, gotErr := inv.Run(r)

				Expect(gotErr).NotTo(HaveOccurred())
				Expect(result.ServiceLogPrepared.Performed).To(BeFalse())
				Expect(result.ServiceLogSent.Performed).To(BeFalse())
				Expect(result.LimitedSupportSet.Performed).To(BeTrue())
			})
		})
		When("Triggered finds instances stopped by the customer with CloudTrail eventVersion 1.99", func() {
			It("should still put the cluster on limited support", func() {
				event := cloudtrailv2types.Event{
					Username:        awsv2.String("12345"),
					CloudTrailEvent: awsv2.String(`{"eventVersion":"1.99", "userIdentity":{"type":"AssumedRole", "sessionContext":{"sessionIssuer":{"type":"Role", "userName": "654321"}}}}`),
				}
				// We need to cast it to the mock client, as the investigationResources are unaware the underlying functions are mocks
				r.AwsClient.(*awsmock.MockClient).EXPECT().ListNonRunningInstances(gomock.Eq(infraID)).Return([]ec2v2types.Instance{infraInstance}, nil)
				r.AwsClient.(*awsmock.MockClient).EXPECT().ListRunningInstances(gomock.Eq(infraID)).Return([]ec2v2types.Instance{masterInstance, infraInstance}, nil)
				r.OcmClient.(*ocmmock.MockClient).EXPECT().GetClusterMachinePools(gomock.Any()).Return(machinePools, nil)
				r.AwsClient.(*awsmock.MockClient).EXPECT().PollInstanceStopEventsFor(gomock.Any(), gomock.Any()).Return([]cloudtrailv2types.Event{event}, nil)
				r.OcmClient.(*ocmmock.MockClient).EXPECT().PostLimitedSupportReason(gomock.Eq(&stoppedInfraLS), gomock.Eq(cluster.ID())).Return(nil)
				r.PdClient.(*pdmock.MockClient).EXPECT().SilenceIncidentWithNote(gomock.Any())

				result, gotErr := inv.Run(r)

				Expect(gotErr).NotTo(HaveOccurred())
				Expect(result.ServiceLogPrepared.Performed).To(BeFalse())
				Expect(result.ServiceLogSent.Performed).To(BeFalse())
				Expect(result.LimitedSupportSet.Performed).To(BeTrue())
			})
		})
		When("Triggered errors", func() {
			It("should update the incident notes and escalate to primary", func() {
				r.AwsClient.(*awsmock.MockClient).EXPECT().ListNonRunningInstances(gomock.Any()).Return(nil, fakeErr)
				r.PdClient.(*pdmock.MockClient).EXPECT().EscalateIncidentWithNote(gomock.Any()).Return(nil)

				result, gotErr := inv.Run(r)

				Expect(gotErr).NotTo(HaveOccurred())
				Expect(result.ServiceLogPrepared.Performed).To(BeFalse())
				Expect(result.ServiceLogSent.Performed).To(BeFalse())
				Expect(result.LimitedSupportSet.Performed).To(BeFalse())
			})
		})
		When("there were no stopped instances", func() {
			It("should update and escalate to primary", func() {
				r.AwsClient.(*awsmock.MockClient).EXPECT().ListNonRunningInstances(gomock.Eq(infraID)).Return([]ec2v2types.Instance{}, nil)
				r.AwsClient.(*awsmock.MockClient).EXPECT().ListRunningInstances(gomock.Eq(infraID)).Return([]ec2v2types.Instance{masterInstance, infraInstance}, nil)
				r.OcmClient.(*ocmmock.MockClient).EXPECT().GetClusterMachinePools(gomock.Any()).Return(machinePools, nil)
				r.AwsClient.(*awsmock.MockClient).EXPECT().GetSecurityGroupID(gomock.Eq(infraID)).Return(gomock.Any().String(), nil)
				r.AwsClient.(*awsmock.MockClient).EXPECT().GetBaseConfig().Return(&awsv2.Config{})
				r.AwsClient.(*awsmock.MockClient).EXPECT().GetSubnetID(gomock.Eq(infraID)).Return([]string{"string1", "string2"}, nil)
				r.PdClient.(*pdmock.MockClient).EXPECT().EscalateIncidentWithNote(gomock.Any()).Return(nil)
				r.OcmClient.(*ocmmock.MockClient).EXPECT().GetServiceLog(gomock.Eq(cluster), gomock.Eq("log_type='cluster-state-updates'")).Return(&servicelogsv1.ClusterLogsUUIDListResponse{}, nil)
				result, gotErr := inv.Run(r)
				// Assert
				Expect(gotErr).ToNot(HaveOccurred())
				Expect(result.ServiceLogPrepared.Performed).To(BeFalse())
				Expect(result.ServiceLogSent.Performed).To(BeFalse())
				Expect(result.LimitedSupportSet.Performed).To(BeFalse())
			})
		})
		When("there was an error getting StopInstancesEvents", func() {
			It("should update and escalate to primary", func() {
				r.AwsClient.(*awsmock.MockClient).EXPECT().ListNonRunningInstances(gomock.Eq(infraID)).Return([]ec2v2types.Instance{instance}, nil)
				r.AwsClient.(*awsmock.MockClient).EXPECT().ListRunningInstances(gomock.Eq(infraID)).Return([]ec2v2types.Instance{instance}, nil)
				r.OcmClient.(*ocmmock.MockClient).EXPECT().GetClusterMachinePools(gomock.Any()).Return(machinePools, nil)
				r.AwsClient.(*awsmock.MockClient).EXPECT().PollInstanceStopEventsFor(gomock.Any(), gomock.Any()).Return(nil, fakeErr)

				r.PdClient.(*pdmock.MockClient).EXPECT().EscalateIncidentWithNote(gomock.Any()).Return(nil)

				result, gotErr := inv.Run(r)
				Expect(gotErr).ToNot(HaveOccurred())
				Expect(result.ServiceLogPrepared.Performed).To(BeFalse())
				Expect(result.ServiceLogSent.Performed).To(BeFalse())
				Expect(result.LimitedSupportSet.Performed).To(BeFalse())
			})
		})
		When("there were no StopInstancesEvents", func() {
			It("should update and escalate to primary", func() {
				// Arrange
				r.AwsClient.(*awsmock.MockClient).EXPECT().ListRunningInstances(gomock.Eq(infraID)).Return([]ec2v2types.Instance{instance}, nil)
				r.OcmClient.(*ocmmock.MockClient).EXPECT().GetClusterMachinePools(gomock.Any()).Return(machinePools, nil)
				r.AwsClient.(*awsmock.MockClient).EXPECT().ListNonRunningInstances(gomock.Eq(infraID)).Return([]ec2v2types.Instance{instance}, nil)
				r.AwsClient.(*awsmock.MockClient).EXPECT().PollInstanceStopEventsFor(gomock.Any(), gomock.Any()).Return([]cloudtrailv2types.Event{}, nil)
				r.PdClient.(*pdmock.MockClient).EXPECT().EscalateIncidentWithNote(gomock.Any()).Return(nil)

				// Act
				result, gotErr := inv.Run(r)
				Expect(gotErr).ToNot(HaveOccurred())
				Expect(result.ServiceLogPrepared.Performed).To(BeFalse())
				Expect(result.ServiceLogSent.Performed).To(BeFalse())
				Expect(result.LimitedSupportSet.Performed).To(BeFalse())
			})
		})
		When("the returned CloudTrailEventRaw base data is correct, but the sessionissue's username is not an authorized user", func() {
			It("should put the cluster on limited support", func() {
				r.OcmClient.(*ocmmock.MockClient).EXPECT().GetClusterMachinePools(gomock.Any()).Return(machinePools, nil)
				r.AwsClient.(*awsmock.MockClient).EXPECT().ListNonRunningInstances(gomock.Eq(infraID)).Return([]ec2v2types.Instance{instance}, nil)
				r.AwsClient.(*awsmock.MockClient).EXPECT().ListRunningInstances(gomock.Eq(infraID)).Return([]ec2v2types.Instance{instance}, nil)
				event.CloudTrailEvent = awsv2.String(`{"eventVersion":"1.08", "userIdentity":{"type":"AssumedRole", "sessionContext":{"sessionIssuer":{"type":"Role", "userName": "654321"}}}}`)
				r.AwsClient.(*awsmock.MockClient).EXPECT().PollInstanceStopEventsFor(gomock.Any(), gomock.Any()).Return([]cloudtrailv2types.Event{event}, nil)
				r.OcmClient.(*ocmmock.MockClient).EXPECT().PostLimitedSupportReason(gomock.Eq(&stoppedInfraLS), gomock.Eq(cluster.ID())).Return(nil)
				r.PdClient.(*pdmock.MockClient).EXPECT().SilenceIncidentWithNote(gomock.Any()).Return(nil)
				// Act
				result, gotErr := inv.Run(r)
				// Assert
				Expect(gotErr).NotTo(HaveOccurred())
				Expect(result.ServiceLogPrepared.Performed).To(BeFalse())
				Expect(result.ServiceLogSent.Performed).To(BeFalse())
				Expect(result.LimitedSupportSet.Performed).To(BeTrue())
			})
		})
		When("issuer user is authorized (openshift-machine-api-aws)", func() {
			It("should update and escalate to primary", func() {
				r.OcmClient.(*ocmmock.MockClient).EXPECT().GetClusterMachinePools(gomock.Any()).Return(machinePools, nil)
				r.AwsClient.(*awsmock.MockClient).EXPECT().ListNonRunningInstances(gomock.Eq(infraID)).Return([]ec2v2types.Instance{instance}, nil)
				r.AwsClient.(*awsmock.MockClient).EXPECT().ListRunningInstances(gomock.Eq(infraID)).Return([]ec2v2types.Instance{instance}, nil)
				event.CloudTrailEvent = awsv2.String(`{"eventVersion":"1.08","userIdentity":{"type":"AssumedRole","principalId":"PRINCIPALID_REDACTED:1234567789","arn":"arn:aws:sts::1234:assumed-role/cluster-name-n9o7-openshift-machine-api-aws-cloud-credentials/1234567789","accountId":"1234","accessKeyId":"REDACTED","sessionContext":{"sessionIssuer":{"type":"Role","principalId":"PRINCIPALID_REDACTED","arn":"arn:aws:iam::1234:role/cluster-name-n9o7-openshift-machine-api-aws-cloud-credentials","accountId":"1234","userName":"cluster-name-n9o7-openshift-machine-api-aws-cloud-credentials"},"webIdFederationData":{"federatedProvider":"arn:aws:iam::1234:oidc-provider/rh-oidc.s3.us-east-1.amazonawsv2.com/redacted","attributes":{}},"attributes":{"creationDate":"2023-02-21T04:54:56Z","mfaAuthenticated":"false"}}},"eventTime":"2023-02-21T04:54:56Z","eventSource":"ec2v2types.amazonawsv2.com","eventName":"TerminateInstances","awsRegion":"ap-southeast-1","sourceIPAddress":"192.168.0.0","userAgent":"aws-sdk-go/1.43.20 (go1.18.7; linux; amd64) openshift.io cluster-api-provider-aws/4.11.0-202301051515.p0.ga796a77.assembly.stream","requestParameters":{"instancesSet":{"items":[{"instanceId":"i-08020c19123456789"}]}},"responseElements":{"requestId":"b8c78d9a-51de-4910-123456789","instancesSet":{"items":[{"instanceId":"i-08020c19123456789","currentState":{"code":32,"name":"shutting-down"},"previousState":{"code":32,"name":"shutting-down"}}]}},"requestID":"b8c78d9a-51de-4910-123456789","eventID":"5455f882-a4db-4505-bea6-123456789","readOnly":false,"eventType":"AwsApiCall","managementEvent":true,"recipientAccountId":"1234","eventCategory":"Management","tlsDetails":{"tlsVersion":"TLSv1.2","cipherSuite":"ECDHE-RSA-AES128-GCM-SHA256","clientProvidedHostHeader":"ec2v2types.ap-southeast-1.amazonawsv2.com"}}`)
				event.Username = awsv2.String("1234567789") // ID of the initial jumprole account
				r.AwsClient.(*awsmock.MockClient).EXPECT().PollInstanceStopEventsFor(gomock.Any(), gomock.Any()).Return([]cloudtrailv2types.Event{event}, nil)
				r.AwsClient.(*awsmock.MockClient).EXPECT().GetSecurityGroupID(gomock.Eq(infraID)).Return(gomock.Any().String(), nil)
				r.AwsClient.(*awsmock.MockClient).EXPECT().GetBaseConfig().Return(&awsv2.Config{})
				r.AwsClient.(*awsmock.MockClient).EXPECT().GetSubnetID(gomock.Eq(infraID)).Return([]string{"string1", "string2"}, nil)
				r.PdClient.(*pdmock.MockClient).EXPECT().EscalateIncidentWithNote(gomock.Any()).Return(nil)
				r.OcmClient.(*ocmmock.MockClient).EXPECT().GetServiceLog(gomock.Eq(cluster), gomock.Eq("log_type='cluster-state-updates'")).Return(&servicelogsv1.ClusterLogsUUIDListResponse{}, nil)

				result, gotErr := inv.Run(r)
				Expect(gotErr).NotTo(HaveOccurred())
				Expect(result.ServiceLogPrepared.Performed).To(BeFalse())
				Expect(result.ServiceLogSent.Performed).To(BeFalse())
				Expect(result.LimitedSupportSet.Performed).To(BeFalse())
			})
		})
		When("username role is OrganizationAccountAccessRole on a non CCS cluster", func() {
			It("should update and escalate to primary", func() {
				r.OcmClient.(*ocmmock.MockClient).EXPECT().GetClusterMachinePools(gomock.Any()).Return(machinePools, nil)
				r.AwsClient.(*awsmock.MockClient).EXPECT().ListNonRunningInstances(gomock.Eq(infraID)).Return([]ec2v2types.Instance{instance}, nil)
				r.AwsClient.(*awsmock.MockClient).EXPECT().ListRunningInstances(gomock.Eq(infraID)).Return([]ec2v2types.Instance{instance}, nil)
				event.CloudTrailEvent = awsv2.String(`{"eventVersion":"1.08", "userIdentity":{"type":"AssumedRole", "sessionContext":{"sessionIssuer":{"type":"Role", "userName": "OrganizationAccountAccessRole"}}}}`)
				r.AwsClient.(*awsmock.MockClient).EXPECT().PollInstanceStopEventsFor(gomock.Any(), gomock.Any()).Return([]cloudtrailv2types.Event{event}, nil)
				r.AwsClient.(*awsmock.MockClient).EXPECT().GetSecurityGroupID(gomock.Eq(infraID)).Return(gomock.Any().String(), nil)
				r.AwsClient.(*awsmock.MockClient).EXPECT().GetBaseConfig().Return(&awsv2.Config{})
				r.AwsClient.(*awsmock.MockClient).EXPECT().GetSubnetID(gomock.Eq(infraID)).Return([]string{"string1", "string2"}, nil)
				r.PdClient.(*pdmock.MockClient).EXPECT().EscalateIncidentWithNote(gomock.Any()).Return(nil)
				r.OcmClient.(*ocmmock.MockClient).EXPECT().GetServiceLog(gomock.Eq(cluster), gomock.Eq("log_type='cluster-state-updates'")).Return(&servicelogsv1.ClusterLogsUUIDListResponse{}, nil)

				result, gotErr := inv.Run(r)
				Expect(gotErr).NotTo(HaveOccurred())
				Expect(result.ServiceLogPrepared.Performed).To(BeFalse())
				Expect(result.ServiceLogSent.Performed).To(BeFalse())
				Expect(result.LimitedSupportSet.Performed).To(BeFalse())
			})
		})

		When("username role is OrganizationAccountAccessRole on a CCS cluster", func() {
			It("should send a service log and silence the alert", func() {
				r.OcmClient.(*ocmmock.MockClient).EXPECT().GetClusterMachinePools(gomock.Any()).Return(machinePools, nil)
				r.AwsClient.(*awsmock.MockClient).EXPECT().ListNonRunningInstances(gomock.Eq(infraID)).Return([]ec2v2types.Instance{instance}, nil)
				r.AwsClient.(*awsmock.MockClient).EXPECT().ListRunningInstances(gomock.Eq(infraID)).Return([]ec2v2types.Instance{instance}, nil)
				event.CloudTrailEvent = awsv2.String(`{"eventVersion":"1.08", "userIdentity":{"type":"AssumedRole", "sessionContext":{"sessionIssuer":{"type":"Role", "userName": "OrganizationAccountAccessRole"}}}}`)
				r.AwsClient.(*awsmock.MockClient).EXPECT().PollInstanceStopEventsFor(gomock.Any(), gomock.Any()).Return([]cloudtrailv2types.Event{event}, nil)
				r.AwsClient.(*awsmock.MockClient).EXPECT().GetSecurityGroupID(gomock.Eq(infraID)).Return(gomock.Any().String(), nil)
				r.AwsClient.(*awsmock.MockClient).EXPECT().GetBaseConfig().Return(&awsv2.Config{})
				r.AwsClient.(*awsmock.MockClient).EXPECT().GetSubnetID(gomock.Eq(infraID)).Return([]string{"string1", "string2"}, nil)
				r.PdClient.(*pdmock.MockClient).EXPECT().EscalateIncidentWithNote(gomock.Any()).Return(nil)
				r.OcmClient.(*ocmmock.MockClient).EXPECT().GetServiceLog(gomock.Any(), gomock.Eq("log_type='cluster-state-updates'")).Return(&servicelogsv1.ClusterLogsUUIDListResponse{}, nil)

				result, gotErr := inv.Run(r)
				Expect(gotErr).NotTo(HaveOccurred())
				Expect(result.ServiceLogPrepared.Performed).To(BeFalse())
				Expect(result.ServiceLogSent.Performed).To(BeFalse())
				Expect(result.LimitedSupportSet.Performed).To(BeFalse())
			})
		})

		When("issuer user is authorized (ManagedOpenShift-Installer-Role)", func() {
			It("should update and escalate to primary", func() {
				r.OcmClient.(*ocmmock.MockClient).EXPECT().GetClusterMachinePools(gomock.Any()).Return(machinePools, nil)
				r.AwsClient.(*awsmock.MockClient).EXPECT().ListNonRunningInstances(gomock.Eq(infraID)).Return([]ec2v2types.Instance{instance}, nil)
				r.AwsClient.(*awsmock.MockClient).EXPECT().ListRunningInstances(gomock.Eq(infraID)).Return([]ec2v2types.Instance{instance}, nil)
				event.CloudTrailEvent = awsv2.String(`{"eventVersion":"1.08","userIdentity":{"type":"AssumedRole","principalId":"redacted:1234567","arn":"arn:aws:sts::1234567:assumed-role/ManagedOpenShift-Installer-Role/1234567","accountId":"1234567","accessKeyId":"redacted","sessionContext":{"sessionIssuer":{"type":"Role","principalId":"redacted","arn":"arn:aws:iam::1234567:role/ManagedOpenShift-Installer-Role","accountId":"1234567","userName":"ManagedOpenShift-Installer-Role"},"webIdFederationData":{},"attributes":{"creationDate":"2023-02-21T04:33:06Z","mfaAuthenticated":"false"}}},"eventTime":"2023-02-21T04:33:09Z","eventSource":"ec2v2types.amazonawsv2.com","eventName":"TerminateInstances","awsRegion":"ap-southeast-1","sourceIPAddress":"192.0.0.1","userAgent":"APN/1.0 HashiCorp/1.0 Terraform/1.0.11 (+https://www.terraform.io) terraform-provider-aws/dev (+https://registry.terraform.io/providers/hashicorp/aws) aws-sdk-go/1.43.9 (go1.18.7; linux; amd64) HashiCorp-terraform-exec/0.16.1","requestParameters":{"instancesSet":{"items":[{"instanceId":"i-0c123456"}]}},"responseElements":{"requestId":"bd3900cb-1234567","instancesSet":{"items":[{"instanceId":"i-0c123456","currentState":{"code":32,"name":"shutting-down"},"previousState":{"code":16,"name":"running"}}]}},"requestID":"bd3900cb-1234567","eventID":"7064eae0-1234567","readOnly":false,"eventType":"AwsApiCall","managementEvent":true,"recipientAccountId":"1234","eventCategory":"Management","tlsDetails":{"tlsVersion":"TLSv1.2","cipherSuite":"ECDHE-RSA-AES128-GCM-SHA256","clientProvidedHostHeader":"ec2v2types.ap-southeast-1.amazonawsv2.com"}}`)
				r.AwsClient.(*awsmock.MockClient).EXPECT().PollInstanceStopEventsFor(gomock.Any(), gomock.Any()).Return([]cloudtrailv2types.Event{event}, nil)
				r.AwsClient.(*awsmock.MockClient).EXPECT().GetSecurityGroupID(gomock.Eq(infraID)).Return(gomock.Any().String(), nil)
				r.AwsClient.(*awsmock.MockClient).EXPECT().GetBaseConfig().Return(&awsv2.Config{})
				r.AwsClient.(*awsmock.MockClient).EXPECT().GetSubnetID(gomock.Eq(infraID)).Return([]string{"string1", "string2"}, nil)
				r.PdClient.(*pdmock.MockClient).EXPECT().EscalateIncidentWithNote(gomock.Any()).Return(nil)
				r.OcmClient.(*ocmmock.MockClient).EXPECT().GetServiceLog(gomock.Eq(cluster), gomock.Eq("log_type='cluster-state-updates'")).Return(&servicelogsv1.ClusterLogsUUIDListResponse{}, nil)

				result, gotErr := inv.Run(r)
				Expect(gotErr).NotTo(HaveOccurred())
				Expect(result.ServiceLogPrepared.Performed).To(BeFalse())
				Expect(result.ServiceLogSent.Performed).To(BeFalse())
				Expect(result.LimitedSupportSet.Performed).To(BeFalse())
			})
		})
		When("issuer user is authorized (customprefix-Installer-Role)", func() {
			It("should update and escalate to primary", func() {
				r.OcmClient.(*ocmmock.MockClient).EXPECT().GetClusterMachinePools(gomock.Any()).Return(machinePools, nil)
				r.AwsClient.(*awsmock.MockClient).EXPECT().ListNonRunningInstances(gomock.Eq(infraID)).Return([]ec2v2types.Instance{instance}, nil)
				r.AwsClient.(*awsmock.MockClient).EXPECT().ListRunningInstances(gomock.Eq(infraID)).Return([]ec2v2types.Instance{instance}, nil)
				event.CloudTrailEvent = awsv2.String(`{"eventVersion":"1.08","userIdentity":{"type":"AssumedRole","principalId":"redacted:1234567","arn":"arn:aws:sts::1234567:assumed-role/customprefix-Installer-Role/1234567","accountId":"1234567","accessKeyId":"redacted","sessionContext":{"sessionIssuer":{"type":"Role","principalId":"redacted","arn":"arn:aws:iam::1234567:role/customprefix-Installer-Role","accountId":"1234567","userName":"customprefix-Installer-Role"},"webIdFederationData":{},"attributes":{"creationDate":"2023-02-21T04:33:06Z","mfaAuthenticated":"false"}}},"eventTime":"2023-02-21T04:33:09Z","eventSource":"ec2v2types.amazonawsv2.com","eventName":"TerminateInstances","awsRegion":"ap-southeast-1","sourceIPAddress":"192.0.0.1","userAgent":"APN/1.0 HashiCorp/1.0 Terraform/1.0.11 (+https://www.terraform.io) terraform-provider-aws/dev (+https://registry.terraform.io/providers/hashicorp/aws) aws-sdk-go/1.43.9 (go1.18.7; linux; amd64) HashiCorp-terraform-exec/0.16.1","requestParameters":{"instancesSet":{"items":[{"instanceId":"i-0c123456"}]}},"responseElements":{"requestId":"bd3900cb-1234567","instancesSet":{"items":[{"instanceId":"i-0c123456","currentState":{"code":32,"name":"shutting-down"},"previousState":{"code":16,"name":"running"}}]}},"requestID":"bd3900cb-1234567","eventID":"7064eae0-1234567","readOnly":false,"eventType":"AwsApiCall","managementEvent":true,"recipientAccountId":"1234","eventCategory":"Management","tlsDetails":{"tlsVersion":"TLSv1.2","cipherSuite":"ECDHE-RSA-AES128-GCM-SHA256","clientProvidedHostHeader":"ec2v2types.ap-southeast-1.amazonawsv2.com"}}`)
				r.AwsClient.(*awsmock.MockClient).EXPECT().PollInstanceStopEventsFor(gomock.Any(), gomock.Any()).Return([]cloudtrailv2types.Event{event}, nil)
				r.AwsClient.(*awsmock.MockClient).EXPECT().GetSecurityGroupID(gomock.Eq(infraID)).Return(gomock.Any().String(), nil)
				r.AwsClient.(*awsmock.MockClient).EXPECT().GetBaseConfig().Return(&awsv2.Config{})
				r.AwsClient.(*awsmock.MockClient).EXPECT().GetSubnetID(gomock.Eq(infraID)).Return([]string{"string1", "string2"}, nil)
				r.PdClient.(*pdmock.MockClient).EXPECT().EscalateIncidentWithNote(gomock.Any()).Return(nil)
				r.OcmClient.(*ocmmock.MockClient).EXPECT().GetServiceLog(gomock.Eq(cluster), gomock.Eq("log_type='cluster-state-updates'")).Return(&servicelogsv1.ClusterLogsUUIDListResponse{}, nil)

				result, gotErr := inv.Run(r)
				Expect(gotErr).NotTo(HaveOccurred())
				Expect(result.ServiceLogPrepared.Performed).To(BeFalse())
				Expect(result.ServiceLogSent.Performed).To(BeFalse())
				Expect(result.LimitedSupportSet.Performed).To(BeFalse())
			})
		})
		When("issuer user is authorized (ManagedOpenShift-Support-.*)", func() {
			It("should update and escalate to primary", func() {
				r.OcmClient.(*ocmmock.MockClient).EXPECT().GetClusterMachinePools(gomock.Any()).Return(machinePools, nil)
				r.AwsClient.(*awsmock.MockClient).EXPECT().ListNonRunningInstances(gomock.Eq(infraID)).Return([]ec2v2types.Instance{instance}, nil)
				r.AwsClient.(*awsmock.MockClient).EXPECT().ListRunningInstances(gomock.Eq(infraID)).Return([]ec2v2types.Instance{instance}, nil)
				event.CloudTrailEvent = awsv2.String(`{"eventVersion":"1.08","userIdentity":{"type":"AssumedRole","principalId":"redacted:1234567","arn":"arn:aws:sts::1234567:assumed-role/ManagedOpenShift-Support-v3218/1234567","accountId":"1234567","accessKeyId":"redacted","sessionContext":{"sessionIssuer":{"type":"Role","principalId":"redacted","arn":"arn:aws:iam::1234567:role/ManagedOpenShift-Support-v3218","accountId":"1234567","userName":"ManagedOpenShift-Support-v3218"},"webIdFederationData":{},"attributes":{"creationDate":"2023-02-21T04:33:06Z","mfaAuthenticated":"false"}}},"eventTime":"2023-02-21T04:33:09Z","eventSource":"ec2v2types.amazonawsv2.com","eventName":"TerminateInstances","awsRegion":"ap-southeast-1","sourceIPAddress":"192.0.0.1","userAgent":"APN/1.0 HashiCorp/1.0 Terraform/1.0.11 (+https://www.terraform.io) terraform-provider-aws/dev (+https://registry.terraform.io/providers/hashicorp/aws) aws-sdk-go/1.43.9 (go1.18.7; linux; amd64) HashiCorp-terraform-exec/0.16.1","requestParameters":{"instancesSet":{"items":[{"instanceId":"i-0c123456"}]}},"responseElements":{"requestId":"bd3900cb-1234567","instancesSet":{"items":[{"instanceId":"i-0c123456","currentState":{"code":32,"name":"shutting-down"},"previousState":{"code":16,"name":"running"}}]}},"requestID":"bd3900cb-1234567","eventID":"7064eae0-1234567","readOnly":false,"eventType":"AwsApiCall","managementEvent":true,"recipientAccountId":"1234","eventCategory":"Management","tlsDetails":{"tlsVersion":"TLSv1.2","cipherSuite":"ECDHE-RSA-AES128-GCM-SHA256","clientProvidedHostHeader":"ec2v2types.ap-southeast-1.amazonawsv2.com"}}`)
				r.AwsClient.(*awsmock.MockClient).EXPECT().PollInstanceStopEventsFor(gomock.Any(), gomock.Any()).Return([]cloudtrailv2types.Event{event}, nil)
				r.AwsClient.(*awsmock.MockClient).EXPECT().GetSecurityGroupID(gomock.Eq(infraID)).Return(gomock.Any().String(), nil)
				r.AwsClient.(*awsmock.MockClient).EXPECT().GetBaseConfig().Return(&awsv2.Config{})
				r.AwsClient.(*awsmock.MockClient).EXPECT().GetSubnetID(gomock.Eq(infraID)).Return([]string{"string1", "string2"}, nil)
				r.PdClient.(*pdmock.MockClient).EXPECT().EscalateIncidentWithNote(gomock.Any()).Return(nil)
				r.OcmClient.(*ocmmock.MockClient).EXPECT().GetServiceLog(gomock.Eq(cluster), gomock.Eq("log_type='cluster-state-updates'")).Return(&servicelogsv1.ClusterLogsUUIDListResponse{}, nil)

				result, gotErr := inv.Run(r)
				Expect(gotErr).NotTo(HaveOccurred())
				Expect(result.ServiceLogPrepared.Performed).To(BeFalse())
				Expect(result.ServiceLogSent.Performed).To(BeFalse())
				Expect(result.LimitedSupportSet.Performed).To(BeFalse())
			})
		})
		When("issuer user is authorized (.*-Support-Role)", func() {
			It("should update and escalate to primary", func() {
				r.OcmClient.(*ocmmock.MockClient).EXPECT().GetClusterMachinePools(gomock.Any()).Return(machinePools, nil)
				r.AwsClient.(*awsmock.MockClient).EXPECT().ListNonRunningInstances(gomock.Eq(infraID)).Return([]ec2v2types.Instance{instance}, nil)
				r.AwsClient.(*awsmock.MockClient).EXPECT().ListRunningInstances(gomock.Eq(infraID)).Return([]ec2v2types.Instance{instance}, nil)
				event.CloudTrailEvent = awsv2.String(`{"eventVersion":"1.08","userIdentity":{"type":"AssumedRole","principalId":"redacted:1234567","arn":"arn:aws:sts::1234567:assumed-role/johnnycustom-Support-Role/1234567","accountId":"1234567","accessKeyId":"redacted","sessionContext":{"sessionIssuer":{"type":"Role","principalId":"redacted","arn":"arn:aws:iam::1234567:role/johnnycustom-Support-Role","accountId":"1234567","userName":"johnnycustom-Support-Role"},"webIdFederationData":{},"attributes":{"creationDate":"2023-02-21T04:33:06Z","mfaAuthenticated":"false"}}},"eventTime":"2023-02-21T04:33:09Z","eventSource":"ec2v2types.amazonawsv2.com","eventName":"TerminateInstances","awsRegion":"ap-southeast-1","sourceIPAddress":"192.0.0.1","userAgent":"APN/1.0 HashiCorp/1.0 Terraform/1.0.11 (+https://www.terraform.io) terraform-provider-aws/dev (+https://registry.terraform.io/providers/hashicorp/aws) aws-sdk-go/1.43.9 (go1.18.7; linux; amd64) HashiCorp-terraform-exec/0.16.1","requestParameters":{"instancesSet":{"items":[{"instanceId":"i-0c123456"}]}},"responseElements":{"requestId":"bd3900cb-1234567","instancesSet":{"items":[{"instanceId":"i-0c123456","currentState":{"code":32,"name":"shutting-down"},"previousState":{"code":16,"name":"running"}}]}},"requestID":"bd3900cb-1234567","eventID":"7064eae0-1234567","readOnly":false,"eventType":"AwsApiCall","managementEvent":true,"recipientAccountId":"1234","eventCategory":"Management","tlsDetails":{"tlsVersion":"TLSv1.2","cipherSuite":"ECDHE-RSA-AES128-GCM-SHA256","clientProvidedHostHeader":"ec2v2types.ap-southeast-1.amazonawsv2.com"}}`)
				r.AwsClient.(*awsmock.MockClient).EXPECT().PollInstanceStopEventsFor(gomock.Any(), gomock.Any()).Return([]cloudtrailv2types.Event{event}, nil)
				r.AwsClient.(*awsmock.MockClient).EXPECT().GetSecurityGroupID(gomock.Eq(infraID)).Return(gomock.Any().String(), nil)
				r.AwsClient.(*awsmock.MockClient).EXPECT().GetBaseConfig().Return(&awsv2.Config{})
				r.AwsClient.(*awsmock.MockClient).EXPECT().GetSubnetID(gomock.Eq(infraID)).Return([]string{"string1", "string2"}, nil)
				r.PdClient.(*pdmock.MockClient).EXPECT().EscalateIncidentWithNote(gomock.Any()).Return(nil)
				r.OcmClient.(*ocmmock.MockClient).EXPECT().GetServiceLog(gomock.Eq(cluster), gomock.Eq("log_type='cluster-state-updates'")).Return(&servicelogsv1.ClusterLogsUUIDListResponse{}, nil)

				result, gotErr := inv.Run(r)
				Expect(gotErr).NotTo(HaveOccurred())
				Expect(result.ServiceLogPrepared.Performed).To(BeFalse())
				Expect(result.ServiceLogSent.Performed).To(BeFalse())
				Expect(result.LimitedSupportSet.Performed).To(BeFalse())
			})
		})
		When("the returned CloudTrailEvent has a matching whitelisted user (osdManagedAdmin-.*)", func() {
			It("should update and escalate to primary", func() {
				r.OcmClient.(*ocmmock.MockClient).EXPECT().GetClusterMachinePools(gomock.Any()).Return(machinePools, nil)
				r.AwsClient.(*awsmock.MockClient).EXPECT().ListNonRunningInstances(gomock.Eq(infraID)).Return([]ec2v2types.Instance{instance}, nil)
				r.AwsClient.(*awsmock.MockClient).EXPECT().ListRunningInstances(gomock.Eq(infraID)).Return([]ec2v2types.Instance{instance}, nil)
				event.Username = awsv2.String("osdManagedAdmin-abcd")
				r.AwsClient.(*awsmock.MockClient).EXPECT().PollInstanceStopEventsFor(gomock.Any(), gomock.Any()).Return([]cloudtrailv2types.Event{event}, nil)
				r.AwsClient.(*awsmock.MockClient).EXPECT().GetSecurityGroupID(gomock.Eq(infraID)).Return(gomock.Any().String(), nil)
				r.AwsClient.(*awsmock.MockClient).EXPECT().GetBaseConfig().Return(&awsv2.Config{})
				r.AwsClient.(*awsmock.MockClient).EXPECT().GetSubnetID(gomock.Eq(infraID)).Return([]string{"string1", "string2"}, nil)
				r.PdClient.(*pdmock.MockClient).EXPECT().EscalateIncidentWithNote(gomock.Any()).Return(nil)
				r.OcmClient.(*ocmmock.MockClient).EXPECT().GetServiceLog(gomock.Eq(cluster), gomock.Eq("log_type='cluster-state-updates'")).Return(&servicelogsv1.ClusterLogsUUIDListResponse{}, nil)

				result, gotErr := inv.Run(r)
				Expect(gotErr).NotTo(HaveOccurred())
				Expect(result.ServiceLogPrepared.Performed).To(BeFalse())
				Expect(result.ServiceLogSent.Performed).To(BeFalse())
				Expect(result.LimitedSupportSet.Performed).To(BeFalse())
			})
		})
		When("the returned CloudTrailEvent has a matching whitelisted user (osdCcsAdmin)", func() {
			It("should update and escalate to primary", func() {
				r.OcmClient.(*ocmmock.MockClient).EXPECT().GetClusterMachinePools(gomock.Any()).Return(machinePools, nil)
				r.AwsClient.(*awsmock.MockClient).EXPECT().ListNonRunningInstances(gomock.Eq(infraID)).Return([]ec2v2types.Instance{instance}, nil)
				r.AwsClient.(*awsmock.MockClient).EXPECT().ListRunningInstances(gomock.Eq(infraID)).Return([]ec2v2types.Instance{instance}, nil)
				event.Username = awsv2.String("osdCcsAdmin")
				r.AwsClient.(*awsmock.MockClient).EXPECT().PollInstanceStopEventsFor(gomock.Any(), gomock.Any()).Return([]cloudtrailv2types.Event{event}, nil)
				r.AwsClient.(*awsmock.MockClient).EXPECT().GetSecurityGroupID(gomock.Eq(infraID)).Return(gomock.Any().String(), nil)
				r.AwsClient.(*awsmock.MockClient).EXPECT().GetBaseConfig().Return(&awsv2.Config{})
				r.AwsClient.(*awsmock.MockClient).EXPECT().GetSubnetID(gomock.Eq(infraID)).Return([]string{"string1", "string2"}, nil)
				r.PdClient.(*pdmock.MockClient).EXPECT().EscalateIncidentWithNote(gomock.Any()).Return(nil)
				r.OcmClient.(*ocmmock.MockClient).EXPECT().GetServiceLog(gomock.Eq(cluster), gomock.Eq("log_type='cluster-state-updates'")).Return(&servicelogsv1.ClusterLogsUUIDListResponse{}, nil)

				result, gotErr := inv.Run(r)
				Expect(gotErr).NotTo(HaveOccurred())
				Expect(result.ServiceLogPrepared.Performed).To(BeFalse())
				Expect(result.ServiceLogSent.Performed).To(BeFalse())
				Expect(result.LimitedSupportSet.Performed).To(BeFalse())
			})
		})
		When("the returned CloudTrailEvent has a matching whitelisted user (.*openshift-machine-api-awsv2.*)", func() {
			It("should update and escalate to primary", func() {
				r.OcmClient.(*ocmmock.MockClient).EXPECT().GetClusterMachinePools(gomock.Any()).Return(machinePools, nil)
				r.AwsClient.(*awsmock.MockClient).EXPECT().ListNonRunningInstances(gomock.Eq(infraID)).Return([]ec2v2types.Instance{instance}, nil)
				r.AwsClient.(*awsmock.MockClient).EXPECT().ListRunningInstances(gomock.Eq(infraID)).Return([]ec2v2types.Instance{instance}, nil)
				event.Username = awsv2.String("test-openshift-machine-api-aws-test")
				r.AwsClient.(*awsmock.MockClient).EXPECT().PollInstanceStopEventsFor(gomock.Any(), gomock.Any()).Return([]cloudtrailv2types.Event{event}, nil)
				r.AwsClient.(*awsmock.MockClient).EXPECT().GetSecurityGroupID(gomock.Eq(infraID)).Return(gomock.Any().String(), nil)
				r.AwsClient.(*awsmock.MockClient).EXPECT().GetBaseConfig().Return(&awsv2.Config{})
				r.AwsClient.(*awsmock.MockClient).EXPECT().GetSubnetID(gomock.Eq(infraID)).Return([]string{"string1", "string2"}, nil)
				r.PdClient.(*pdmock.MockClient).EXPECT().EscalateIncidentWithNote(gomock.Any()).Return(nil)
				r.OcmClient.(*ocmmock.MockClient).EXPECT().GetServiceLog(gomock.Eq(cluster), gomock.Eq("log_type='cluster-state-updates'")).Return(&servicelogsv1.ClusterLogsUUIDListResponse{}, nil)

				result, gotErr := inv.Run(r)
				Expect(gotErr).NotTo(HaveOccurred())
				Expect(result.ServiceLogPrepared.Performed).To(BeFalse())
				Expect(result.ServiceLogSent.Performed).To(BeFalse())
				Expect(result.LimitedSupportSet.Performed).To(BeFalse())
			})
		})
		When("the returned CloudTrailEventRaw has an empty userIdentity", func() {
			It("should put the cluster on limited support", func() {
				r.OcmClient.(*ocmmock.MockClient).EXPECT().GetClusterMachinePools(gomock.Any()).Return(machinePools, nil)
				r.AwsClient.(*awsmock.MockClient).EXPECT().ListNonRunningInstances(gomock.Eq(infraID)).Return([]ec2v2types.Instance{instance}, nil)
				r.AwsClient.(*awsmock.MockClient).EXPECT().ListRunningInstances(gomock.Eq(infraID)).Return([]ec2v2types.Instance{instance}, nil)
				event.CloudTrailEvent = awsv2.String(`{"eventVersion":"1.08", "userIdentity":{}}`)
				r.AwsClient.(*awsmock.MockClient).EXPECT().PollInstanceStopEventsFor(gomock.Any(), gomock.Any()).Return([]cloudtrailv2types.Event{event}, nil)
				r.OcmClient.(*ocmmock.MockClient).EXPECT().PostLimitedSupportReason(gomock.Eq(&stoppedInfraLS), gomock.Eq(cluster.ID())).Return(nil)
				r.PdClient.(*pdmock.MockClient).EXPECT().SilenceIncidentWithNote(gomock.Any()).Return(nil)

				result, gotErr := inv.Run(r)
				Expect(gotErr).NotTo(HaveOccurred())
				Expect(result.ServiceLogPrepared.Performed).To(BeFalse())
				Expect(result.ServiceLogSent.Performed).To(BeFalse())
				Expect(result.LimitedSupportSet.Performed).To(BeTrue())
			})
		})
		When("issuer user is unauthorized (testuser assumed role)", func() {
			It("should put the cluster on limited support", func() {
				r.OcmClient.(*ocmmock.MockClient).EXPECT().GetClusterMachinePools(gomock.Any()).Return(machinePools, nil)
				r.AwsClient.(*awsmock.MockClient).EXPECT().ListNonRunningInstances(gomock.Eq(infraID)).Return([]ec2v2types.Instance{instance}, nil)
				r.AwsClient.(*awsmock.MockClient).EXPECT().ListRunningInstances(gomock.Eq(infraID)).Return([]ec2v2types.Instance{instance}, nil)
				event.CloudTrailEvent = awsv2.String(`{"eventVersion":"1.08","userIdentity":{"type":"AssumedRole","principalId":"REDACTED:OCM","arn":"arn:aws:sts::1234:assumed-role/testuser/OCM","accountId":"1234","accessKeyId":"REDACTED","sessionContext":{"sessionIssuer":{"type":"Role","principalId":"REDACTED","arn":"arn:aws:iam::1234:role/testuser","accountId":"1234","userName":"testuser"},"webIdFederationData":{},"attributes":{"creationDate":"2023-02-21T04:08:01Z","mfaAuthenticated":"false"}}},"eventTime":"2023-02-21T04:10:40Z","eventSource":"ec2v2types.amazonawsv2.com","eventName":"TerminateInstances","awsRegion":"ap-southeast-1","sourceIPAddress":"192.168.0.0","userAgent":"aws-sdk-go-v2/1.17.3 os/linux lang/go/1.19.5 md/GOOS/linux md/GOARCH/amd64 api/ec2/1.25.0","requestParameters":{"instancesSet":{"items":[{"instanceId":"i-00c1f1234567"}]}},"responseElements":{"requestId":"credacted","instancesSet":{"items":[{"instanceId":"i-00c1f1234567","currentState":{"code":32,"name":"shutting-down"},"previousState":{"code":16,"name":"running"}}]}},"requestID":"credacted","eventID":"e55a8a64-9949-47a9-9fff-12345678","readOnly":false,"eventType":"AwsApiCall","managementEvent":true,"recipientAccountId":"1234","eventCategory":"Management","tlsDetails":{"tlsVersion":"TLSv1.2","cipherSuite":"ECDHE-RSA-AES128-GCM-SHA256","clientProvidedHostHeader":"ec2v2types.ap-southeast-1.amazonawsv2.com"}}`)
				r.AwsClient.(*awsmock.MockClient).EXPECT().PollInstanceStopEventsFor(gomock.Any(), gomock.Any()).Return([]cloudtrailv2types.Event{event}, nil)
				r.OcmClient.(*ocmmock.MockClient).EXPECT().PostLimitedSupportReason(gomock.Eq(&stoppedInfraLS), gomock.Eq(cluster.ID())).Return(nil)
				r.PdClient.(*pdmock.MockClient).EXPECT().SilenceIncidentWithNote(gomock.Any()).Return(nil)

				result, gotErr := inv.Run(r)
				Expect(gotErr).NotTo(HaveOccurred())
				Expect(result.ServiceLogPrepared.Performed).To(BeFalse())
				Expect(result.ServiceLogSent.Performed).To(BeFalse())
				Expect(result.LimitedSupportSet.Performed).To(BeTrue())
			})
		})
		When("the returned CloudTrailEventRaw base data is correct, but the sessionissue's role is not role", func() {
			It("should put the cluster on limited support", func() {
				r.OcmClient.(*ocmmock.MockClient).EXPECT().GetClusterMachinePools(gomock.Any()).Return(machinePools, nil)
				r.AwsClient.(*awsmock.MockClient).EXPECT().ListNonRunningInstances(gomock.Eq(infraID)).Return([]ec2v2types.Instance{instance}, nil)
				r.AwsClient.(*awsmock.MockClient).EXPECT().ListRunningInstances(gomock.Eq(infraID)).Return([]ec2v2types.Instance{instance}, nil)
				event.CloudTrailEvent = awsv2.String(`{"eventVersion":"1.08", "userIdentity":{"type":"AssumedRole", "sessionContext":{"sessionIssuer":{"type":"test"}}}}`)
				r.AwsClient.(*awsmock.MockClient).EXPECT().PollInstanceStopEventsFor(gomock.Any(), gomock.Any()).Return([]cloudtrailv2types.Event{event}, nil)
				r.OcmClient.(*ocmmock.MockClient).EXPECT().PostLimitedSupportReason(gomock.Eq(&stoppedInfraLS), gomock.Eq(cluster.ID())).Return(nil)
				r.PdClient.(*pdmock.MockClient).EXPECT().SilenceIncidentWithNote(gomock.Any()).Return(nil)

				result, gotErr := inv.Run(r)
				Expect(gotErr).NotTo(HaveOccurred())
				Expect(result.ServiceLogPrepared.Performed).To(BeFalse())
				Expect(result.ServiceLogSent.Performed).To(BeFalse())
				Expect(result.LimitedSupportSet.Performed).To(BeTrue())
			})
		})
		When("the returned CloudTrailEventRaw has no data", func() {
			It("should put the cluster on limited support", func() {
				r.OcmClient.(*ocmmock.MockClient).EXPECT().GetClusterMachinePools(gomock.Any()).Return(machinePools, nil)
				r.AwsClient.(*awsmock.MockClient).EXPECT().ListNonRunningInstances(gomock.Eq(infraID)).Return([]ec2v2types.Instance{instance}, nil)
				r.AwsClient.(*awsmock.MockClient).EXPECT().ListRunningInstances(gomock.Eq(infraID)).Return([]ec2v2types.Instance{instance}, nil)
				r.AwsClient.(*awsmock.MockClient).EXPECT().PollInstanceStopEventsFor(gomock.Any(), gomock.Any()).Return([]cloudtrailv2types.Event{event}, nil)
				r.OcmClient.(*ocmmock.MockClient).EXPECT().PostLimitedSupportReason(gomock.Eq(&stoppedInfraLS), gomock.Eq(cluster.ID())).Return(nil)
				r.PdClient.(*pdmock.MockClient).EXPECT().SilenceIncidentWithNote(gomock.Any()).Return(nil)

				result, gotErr := inv.Run(r)
				Expect(gotErr).NotTo(HaveOccurred())
				Expect(result.ServiceLogPrepared.Performed).To(BeFalse())
				Expect(result.ServiceLogSent.Performed).To(BeFalse())
				Expect(result.LimitedSupportSet.Performed).To(BeTrue())
			})
		})

		When("the returned CloudTrailEventRaw has an empty userIdentity", func() {
			It("should put the cluster on limited support", func() {
				r.OcmClient.(*ocmmock.MockClient).EXPECT().GetClusterMachinePools(gomock.Any()).Return(machinePools, nil)
				r.AwsClient.(*awsmock.MockClient).EXPECT().ListNonRunningInstances(gomock.Eq(infraID)).Return([]ec2v2types.Instance{instance}, nil)
				r.AwsClient.(*awsmock.MockClient).EXPECT().ListRunningInstances(gomock.Eq(infraID)).Return([]ec2v2types.Instance{instance}, nil)
				event.CloudTrailEvent = awsv2.String(`{"eventVersion":"1.08", "userIdentity":{}}`)
				r.AwsClient.(*awsmock.MockClient).EXPECT().PollInstanceStopEventsFor(gomock.Any(), gomock.Any()).Return([]cloudtrailv2types.Event{event}, nil)
				r.OcmClient.(*ocmmock.MockClient).EXPECT().PostLimitedSupportReason(gomock.Eq(&stoppedInfraLS), gomock.Eq(cluster.ID())).Return(nil)
				r.PdClient.(*pdmock.MockClient).EXPECT().SilenceIncidentWithNote(gomock.Any()).Return(nil)

				result, gotErr := inv.Run(r)
				Expect(gotErr).NotTo(HaveOccurred())
				Expect(result.ServiceLogPrepared.Performed).To(BeFalse())
				Expect(result.ServiceLogSent.Performed).To(BeFalse())
				Expect(result.LimitedSupportSet.Performed).To(BeTrue())
			})
		})

		When("the returned CloudTrailEventRaw has a userIdentity is an iam user", func() {
			It("should put the cluster on limited support", func() {
				r.OcmClient.(*ocmmock.MockClient).EXPECT().GetClusterMachinePools(gomock.Any()).Return(machinePools, nil)
				r.AwsClient.(*awsmock.MockClient).EXPECT().ListNonRunningInstances(gomock.Eq(infraID)).Return([]ec2v2types.Instance{instance}, nil)
				r.AwsClient.(*awsmock.MockClient).EXPECT().ListRunningInstances(gomock.Eq(infraID)).Return([]ec2v2types.Instance{instance}, nil)
				event.CloudTrailEvent = awsv2.String(`{"eventVersion":"1.08", "userIdentity":{"type":"IAMUser"}}`)
				r.AwsClient.(*awsmock.MockClient).EXPECT().PollInstanceStopEventsFor(gomock.Any(), gomock.Any()).Return([]cloudtrailv2types.Event{event}, nil)
				r.OcmClient.(*ocmmock.MockClient).EXPECT().PostLimitedSupportReason(gomock.Eq(&stoppedInfraLS), gomock.Eq(cluster.ID())).Return(nil)
				r.PdClient.(*pdmock.MockClient).EXPECT().SilenceIncidentWithNote(gomock.Any()).Return(nil)

				result, gotErr := inv.Run(r)
				Expect(gotErr).NotTo(HaveOccurred())
				Expect(result.ServiceLogPrepared.Performed).To(BeFalse())
				Expect(result.ServiceLogSent.Performed).To(BeFalse())
				Expect(result.LimitedSupportSet.Performed).To(BeTrue())
			})
		})
		When("the returned CloudTrailEvent has more than one resource", func() {
			It("it should fail, add notes to the incident and escalate to primary", func() {
				r.OcmClient.(*ocmmock.MockClient).EXPECT().GetClusterMachinePools(gomock.Any()).Return(machinePools, nil)
				r.AwsClient.(*awsmock.MockClient).EXPECT().ListNonRunningInstances(gomock.Eq(infraID)).Return([]ec2v2types.Instance{instance}, nil)
				r.AwsClient.(*awsmock.MockClient).EXPECT().ListRunningInstances(gomock.Eq(infraID)).Return([]ec2v2types.Instance{instance}, nil)
				event.CloudTrailEvent = awsv2.String(`{}`)
				cloudTrailResource := cloudtrailv2types.Resource{ResourceName: awsv2.String("123456")}
				event.Resources = []cloudtrailv2types.Resource{cloudTrailResource}
				r.AwsClient.(*awsmock.MockClient).EXPECT().PollInstanceStopEventsFor(gomock.Any(), gomock.Any()).Return([]cloudtrailv2types.Event{event}, nil)
				r.PdClient.(*pdmock.MockClient).EXPECT().EscalateIncidentWithNote(gomock.Any()).Return(nil)

				result, gotErr := inv.Run(r)
				Expect(gotErr).NotTo(HaveOccurred())
				Expect(result.ServiceLogPrepared.Performed).To(BeFalse())
				Expect(result.ServiceLogSent.Performed).To(BeFalse())
				Expect(result.LimitedSupportSet.Performed).To(BeFalse())
			})
		})
		When("the returned CloudTrailEvent is empty", func() {
			It("it should fail, add notes to the incident and escalate to primary", func() {
				r.OcmClient.(*ocmmock.MockClient).EXPECT().GetClusterMachinePools(gomock.Any()).Return(machinePools, nil)
				r.AwsClient.(*awsmock.MockClient).EXPECT().ListNonRunningInstances(gomock.Eq(infraID)).Return([]ec2v2types.Instance{instance}, nil)
				r.AwsClient.(*awsmock.MockClient).EXPECT().ListRunningInstances(gomock.Eq(infraID)).Return([]ec2v2types.Instance{instance}, nil)
				event.CloudTrailEvent = awsv2.String(`{}`)
				cloudTrailResource := cloudtrailv2types.Resource{ResourceName: awsv2.String("123456")}
				event.Resources = []cloudtrailv2types.Resource{cloudTrailResource}
				r.AwsClient.(*awsmock.MockClient).EXPECT().PollInstanceStopEventsFor(gomock.Any(), gomock.Any()).Return([]cloudtrailv2types.Event{}, nil)
				r.PdClient.(*pdmock.MockClient).EXPECT().EscalateIncidentWithNote(gomock.Any()).Return(nil)

				result, gotErr := inv.Run(r)
				Expect(gotErr).NotTo(HaveOccurred())
				Expect(result.ServiceLogPrepared.Performed).To(BeFalse())
				Expect(result.ServiceLogSent.Performed).To(BeFalse())
				Expect(result.LimitedSupportSet.Performed).To(BeFalse())
			})
		})
		When("the returned CloudTrailEvent is an empty string", func() {
			It("it should fail, add notes to the incident and escalate to primary", func() {
				r.OcmClient.(*ocmmock.MockClient).EXPECT().GetClusterMachinePools(gomock.Any()).Return(machinePools, nil)
				r.AwsClient.(*awsmock.MockClient).EXPECT().ListNonRunningInstances(gomock.Eq(infraID)).Return([]ec2v2types.Instance{instance}, nil)
				r.AwsClient.(*awsmock.MockClient).EXPECT().ListRunningInstances(gomock.Eq(infraID)).Return([]ec2v2types.Instance{instance}, nil)
				event.CloudTrailEvent = awsv2.String(``)
				cloudTrailResource := cloudtrailv2types.Resource{ResourceName: awsv2.String("123456")}
				event.Resources = []cloudtrailv2types.Resource{cloudTrailResource}
				r.AwsClient.(*awsmock.MockClient).EXPECT().PollInstanceStopEventsFor(gomock.Any(), gomock.Any()).Return([]cloudtrailv2types.Event{event}, nil)
				r.PdClient.(*pdmock.MockClient).EXPECT().EscalateIncidentWithNote(gomock.Any()).Return(nil)

				result, gotErr := inv.Run(r)
				Expect(gotErr).NotTo(HaveOccurred())
				Expect(result.ServiceLogPrepared.Performed).To(BeFalse())
				Expect(result.ServiceLogSent.Performed).To(BeFalse())
				Expect(result.LimitedSupportSet.Performed).To(BeFalse())
			})
		})
		When("the returned CloudTrailEvent is an empty json", func() {
			It("it should fail, add notes to the incident and escalate to primary", func() {
				r.OcmClient.(*ocmmock.MockClient).EXPECT().GetClusterMachinePools(gomock.Any()).Return(machinePools, nil)
				r.AwsClient.(*awsmock.MockClient).EXPECT().ListNonRunningInstances(gomock.Eq(infraID)).Return([]ec2v2types.Instance{instance}, nil)
				r.AwsClient.(*awsmock.MockClient).EXPECT().ListRunningInstances(gomock.Eq(infraID)).Return([]ec2v2types.Instance{instance}, nil)
				event.CloudTrailEvent = awsv2.String(`{}`)
				cloudTrailResource := cloudtrailv2types.Resource{ResourceName: awsv2.String("123456")}
				event.Resources = []cloudtrailv2types.Resource{cloudTrailResource}
				r.AwsClient.(*awsmock.MockClient).EXPECT().PollInstanceStopEventsFor(gomock.Any(), gomock.Any()).Return([]cloudtrailv2types.Event{event}, nil)
				r.PdClient.(*pdmock.MockClient).EXPECT().EscalateIncidentWithNote(gomock.Any()).Return(nil)

				result, gotErr := inv.Run(r)
				Expect(gotErr).NotTo(HaveOccurred())
				Expect(result.ServiceLogPrepared.Performed).To(BeFalse())
				Expect(result.ServiceLogSent.Performed).To(BeFalse())
				Expect(result.LimitedSupportSet.Performed).To(BeFalse())
			})
		})
		When("the returned CloudTrailEvent is an invalid json", func() {
			It("it should fail, add notes to the incident and escalate to primary", func() {
				r.OcmClient.(*ocmmock.MockClient).EXPECT().GetClusterMachinePools(gomock.Any()).Return(machinePools, nil)
				r.AwsClient.(*awsmock.MockClient).EXPECT().ListNonRunningInstances(gomock.Eq(infraID)).Return([]ec2v2types.Instance{instance}, nil)
				r.AwsClient.(*awsmock.MockClient).EXPECT().ListRunningInstances(gomock.Eq(infraID)).Return([]ec2v2types.Instance{instance}, nil)
				event.CloudTrailEvent = awsv2.String(`{`)
				cloudTrailResource := cloudtrailv2types.Resource{ResourceName: awsv2.String("123456")}
				event.Resources = []cloudtrailv2types.Resource{cloudTrailResource}
				r.AwsClient.(*awsmock.MockClient).EXPECT().PollInstanceStopEventsFor(gomock.Any(), gomock.Any()).Return([]cloudtrailv2types.Event{event}, nil)
				r.PdClient.(*pdmock.MockClient).EXPECT().EscalateIncidentWithNote(gomock.Any()).Return(nil)

				result, gotErr := inv.Run(r)
				Expect(gotErr).NotTo(HaveOccurred())
				Expect(result.ServiceLogPrepared.Performed).To(BeFalse())
				Expect(result.ServiceLogSent.Performed).To(BeFalse())
				Expect(result.LimitedSupportSet.Performed).To(BeFalse())
			})
		})
	})
})

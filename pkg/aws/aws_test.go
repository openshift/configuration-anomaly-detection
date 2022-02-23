package aws_test

import (
	"errors"

	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/sts"

	"github.com/golang/mock/gomock"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	awsSDK "github.com/aws/aws-sdk-go/aws"
	aws "github.com/openshift/configuration-anomaly-detection/pkg/aws"
	mocks "github.com/openshift/configuration-anomaly-detection/pkg/aws/mock"
)

var _ = Describe("Aws", func() {
	var (
		mockCtrl         *gomock.Controller
		client           *aws.AwsClient
		mockSdkStsClient *mocks.MockSTSAPI
	)
	BeforeEach(func() {
		mockCtrl = gomock.NewController(GinkgoT())
		mockSdkStsClient = mocks.NewMockSTSAPI(mockCtrl)
		client = &aws.AwsClient{
			Region:    "us-east-1",
			StsClient: mockSdkStsClient,
		}
	})
	Describe("When assuming a Role", func() {
		var (
			roleARN string
		)
		BeforeEach(func() {
			roleARN = "aws:iam:sts:231254123:test-acc"
		})
		When("the client is allowed to do so", func() {
			It("return a new client by using the right credentials", func() {
				mockSdkStsClient.EXPECT().AssumeRole(gomock.Any()).Return(
					&sts.AssumeRoleOutput{
						Credentials: &sts.Credentials{
							AccessKeyId:     awsSDK.String("testId"),
							SecretAccessKey: awsSDK.String("testSec"),
							SessionToken:    awsSDK.String("token")},
					}, nil).Times(1)
				c, err := client.AssumeRole(roleARN, "eu-west-1")
				Expect(err).ShouldNot(HaveOccurred())
				Expect(c).ShouldNot(Equal(aws.AwsClient{}))
			})
		})
		When("the client fails for arbitary reason", func() {
			It("the error is propagated and empty client returned", func() {
				errOcc := errors.New("something happend")
				mockSdkStsClient.EXPECT().AssumeRole(gomock.Any()).Return(
					&sts.AssumeRoleOutput{}, errOcc).Times(1).Do(
					func(input *sts.AssumeRoleInput) {
						Expect(*input.RoleArn).To(Equal(roleARN))
					})
				c, err := client.AssumeRole(roleARN, "eu-west-1")
				Expect(err).Should(HaveOccurred())
				Expect(err).Should(Equal(errOcc))
				Expect(c).Should(Equal(aws.AwsClient{}))
			})
		})
	})
	Describe("When listing EC2 Instances", func() {
		var (
			mockCtrl            *gomock.Controller
			client              *aws.AwsClient
			mockSdkEc2Client    *mocks.MockEC2API
			describeInstanceOut *ec2.DescribeInstancesOutput
		)
		BeforeEach(func() {
			mockCtrl = gomock.NewController(GinkgoT())
			mockSdkEc2Client = mocks.NewMockEC2API(mockCtrl)
			client = &aws.AwsClient{
				Region:    "us-east-1",
				Ec2Client: mockSdkEc2Client,
			}
			describeInstanceOut = &ec2.DescribeInstancesOutput{
				Reservations: []*ec2.Reservation{
					{
						Instances: []*ec2.Instance{
							{
								InstanceId: awsSDK.String("i-test"),
							},
						},
					},
				},
			}
		})
		When("the a the resource is listed on several pages", func() {
			It("makes several calls to get all pages", func() {
				nrPages := 10
				token := awsSDK.String("pointerToNext")
				describeInstanceOut.NextToken = token
				i := 1
				mockSdkEc2Client.EXPECT().DescribeInstances(gomock.Any()).DoAndReturn(
					func(input *ec2.DescribeInstancesInput) (*ec2.DescribeInstancesOutput, error) {
						if i == nrPages {
							describeInstanceOut.NextToken = nil
						}
						i += 1
						return describeInstanceOut, nil
					}).Times(nrPages)

				c, err := client.ListInstances("cluster-s3v21l")
				Expect(err).ShouldNot(HaveOccurred())
				Expect(len(c)).Should(Equal(nrPages))
			})
		})
		When("the full list is on one page", func() {
			It("the values are returned and the ec2 api is called just once", func() {
				mockSdkEc2Client.EXPECT().DescribeInstances(gomock.Any()).Return(describeInstanceOut, nil).Times(1)
				c, err := client.ListInstances("cluster-s3v21l")
				Expect(err).ShouldNot(HaveOccurred())
				Expect(len(c)).Should(Equal(1))
			})
		})
		When("the client fails with an arbitary error", func() {
			It("the error is propagated and nothing is returned", func() {
				errOcc := errors.New("something happend")
				mockSdkEc2Client.EXPECT().DescribeInstances(gomock.Any()).Return(describeInstanceOut, errOcc).Times(1)
				c, err := client.ListInstances("cluster-s3v21l")
				Expect(err).Should(HaveOccurred())
				Expect(err).Should(Equal(errOcc))
				Expect(len(c)).Should(Equal(0))
			})
		})
	})
})

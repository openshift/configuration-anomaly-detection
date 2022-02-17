package aws

import (
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	awsP "github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/golang/mock/gomock"
	awsv1alpha1 "github.com/openshift/aws-account-operator/pkg/apis/aws/v1alpha1"
	awsconfig "github.com/openshift/configuration-anomaly-detection/pkg/cloudclient/aws/config"
	mocks "github.com/openshift/configuration-anomaly-detection/pkg/utils/mocks"
	hivev1 "github.com/openshift/hive/apis/hive/v1"
	hivev1aws "github.com/openshift/hive/apis/hive/v1/aws"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var _ = Describe("Aws", func() {

	var (
		mockCtrl       *gomock.Controller
		ocmMock        *mocks.MockOcmClient
		cd             *hivev1.ClusterDeployment
		awsMock        *mocks.MockAwsClient
		awsBuilderMock *mocks.MockBuilderIface
		clusterID      string = "1234567890abcdefghijklm"
	)

	BeforeEach(func() {
		mockCtrl = gomock.NewController(GinkgoT())
		ocmMock = mocks.NewMockOcmClient(mockCtrl)
		awsMock = mocks.NewMockAwsClient(mockCtrl)
		awsBuilderMock = mocks.NewMockBuilderIface(mockCtrl)
		singletonClient.awsClientBuilder = nil
		singletonClient.fileReader = func(string) ([]byte, error) {
			return []byte("keyvalue"), nil
		}
		cd = &hivev1.ClusterDeployment{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test-cluster",
				Labels: map[string]string{
					"api.openshift.com/id": clusterID,
				},
			},
		}
	})

	Context("When Building the CloudClient", func() {
		Context("Should Error when the secret is malformed", func() {
			It("Should fail when aws_access_key_id is missing", func() {
				singletonClient.fileReader = func(string) ([]byte, error) {
					return []byte{}, fmt.Errorf("some error")
				}
				_, err := NewCloudClient(awsconfig.Config{CredentialsDir: "/test/directory/"}, ocmMock, cd)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("/test/directory"))
				Expect(err.Error()).To(ContainSubstring("aws_access_key_id"))
			})
			It("Should fail when aws_secret_access_key is missing", func() {
				singletonClient.fileReader = func(s string) ([]byte, error) {
					if s == "/test/directory/aws_access_key_id" {
						return []byte("aws_access key id"), nil
					}
					return []byte{}, fmt.Errorf("some error")
				}
				_, err := NewCloudClient(awsconfig.Config{CredentialsDir: "/test/directory/"}, ocmMock, cd)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("aws_secret_access_key"))
				Expect(err.Error()).To(ContainSubstring("/test/directory"))
			})
		})
		It("Should Error when it cannot create the AWS Client", func() {
			awsBuilderMock.EXPECT().New(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, fmt.Errorf("Some error"))
			singletonClient.awsClientBuilder = awsBuilderMock
			_, err := NewCloudClient(awsconfig.Config{CredentialsDir: "/test/directory/"}, ocmMock, cd)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("Some error"))
		})
		It("Should Error if it cannot find the ClusterID in the ClusterDeployment", func() {
			cd := &hivev1.ClusterDeployment{}
			_, err := NewCloudClient(awsconfig.Config{CredentialsDir: "/test/directory/"}, ocmMock, cd)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("ClusterID"))
		})
		It("Should Successfully create a new cloud client", func() {
			cc, err := NewCloudClient(awsconfig.Config{CredentialsDir: "/test/directory/"}, ocmMock, cd)
			Expect(err).NotTo(HaveOccurred())
			Expect(cc).NotTo(BeNil())
		})
		It("Should overwrite the default region when one is provided in the CD", func() {
			cd.Spec = hivev1.ClusterDeploymentSpec{
				Platform: hivev1.Platform{
					AWS: &hivev1aws.Platform{
						Region: "me-south-1",
					},
				},
			}
			cc, err := NewCloudClient(awsconfig.Config{CredentialsDir: "/test/directory/"}, ocmMock, cd)
			Expect(err).NotTo(HaveOccurred())
			Expect(cc.region).To(Equal("me-south-1"))
		})
	})

	Context("When Testing the CloudClient Interface", func() {
		var (
			aws          *CloudClient
			accountClaim *awsv1alpha1.AccountClaim
		)

		BeforeEach(func() {
			aws = &CloudClient{
				clusterDeployment: cd,
				awsClient:         awsMock,
				ocmClient:         ocmMock,
				awsConfig: awsconfig.Config{
					JumpRole: "arn:aws:123456789012::iam:role/JumpRoleForAccess",
				},
				region: "us-east-1",
			}

			accountClaim = &awsv1alpha1.AccountClaim{
				Spec: awsv1alpha1.AccountClaimSpec{
					SupportRoleARN: "arn:aws:111222333444::iam:role/SupportRoleArn",
				},
			}
		})

		Context("When assuming the support role", func() {

			It("Should throw an UpstreamError when AccountClaim cannot be found due to an error", func() {
				ocmMock.EXPECT().GetAWSAccountClaim(gomock.Any()).Return(&awsv1alpha1.AccountClaim{}, fmt.Errorf("some error"))
				out, err := aws.AssumeSupportRole()
				Expect(err.Error()).To(ContainSubstring("accountclaim"))
				Expect(out).To(BeNil())
			})
			It("Should throw an UpstreamError when AccountClaim is returned and nil", func() {
				ocmMock.EXPECT().GetAWSAccountClaim(gomock.Any()).Return(nil, nil)
				out, err := aws.AssumeSupportRole()
				Expect(err.Error()).To(ContainSubstring("accountclaim"))
				Expect(out).To(BeNil())
			})
			It("Should throw a ValidationError when AccountClaim is invalid", func() {
				ocmMock.EXPECT().GetAWSAccountClaim(gomock.Any()).Return(&awsv1alpha1.AccountClaim{}, nil)
				out, err := aws.AssumeSupportRole()
				Expect(err.Error()).To(ContainSubstring("invalid"))
				Expect(out).To(BeNil())
			})
			It("Should throw an UpstreamError when the JumpRole client cannot be created due to error", func() {
				ocmMock.EXPECT().GetAWSAccountClaim(gomock.Any()).Return(accountClaim, nil)
				awsMock.EXPECT().AssumeRole(gomock.Any()).Return(nil, fmt.Errorf("There was an error"))
				out, err := aws.AssumeSupportRole()
				Expect(err.Error()).To(ContainSubstring("There was an error"))
				Expect(out).To(BeNil())
			})
			It("Should throw an UpstreamError when the JumpRole assume returns nil creds", func() {
				ocmMock.EXPECT().GetAWSAccountClaim(gomock.Any()).Return(accountClaim, nil)
				awsMock.EXPECT().AssumeRole(gomock.Any()).Return(&sts.AssumeRoleOutput{}, nil)
				out, err := aws.AssumeSupportRole()
				Expect(err.Error()).To(ContainSubstring("empty credentials"))
				Expect(out).To(BeNil())
			})
			It("Should throw a UpstreamError when the JumpRole client cannot be created due to an aws error", func() {
				ocmMock.EXPECT().GetAWSAccountClaim(gomock.Any()).Return(accountClaim, nil)
				awsMock.EXPECT().AssumeRole(gomock.Any()).Return(&sts.AssumeRoleOutput{Credentials: &sts.Credentials{
					AccessKeyId:     awsP.String("accesskey"),
					SecretAccessKey: awsP.String("secret"),
					SessionToken:    awsP.String("sessionToken"),
				}}, nil)
				awsBuilderMock.EXPECT().New("accesskey", "secret", "sessionToken", gomock.Any()).Return(nil, fmt.Errorf("Some error"))
				aws.awsClientBuilder = awsBuilderMock
				aws.region = "us-east-1"
				out, err := aws.AssumeSupportRole()
				Expect(err.Error()).To(ContainSubstring("Some error"))
				Expect(out).To(BeNil())
			})
			It("Should throw a RequestError when the customer's account fails to let us assume the role", func() {
				ocmMock.EXPECT().GetAWSAccountClaim(gomock.Any()).Return(accountClaim, nil)
				awsMock.EXPECT().AssumeRole(gomock.Any()).Return(&sts.AssumeRoleOutput{Credentials: &sts.Credentials{
					AccessKeyId:     awsP.String("accesskey"),
					SecretAccessKey: awsP.String("secret"),
					SessionToken:    awsP.String("sessionToken"),
				}}, nil)
				jrAwsMock := mocks.NewMockAwsClient(mockCtrl)
				awsBuilderMock.EXPECT().New(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(jrAwsMock, nil)
				jrAwsMock.EXPECT().AssumeRole(gomock.Any()).Return(nil, fmt.Errorf("Some AWS Error"))
				aws.awsClientBuilder = awsBuilderMock
				aws.region = "us-east-1"
				out, err := aws.AssumeSupportRole()
				Expect(err.Error()).To(ContainSubstring("Some AWS Error"))
				Expect(out).To(BeNil())
			})
			It("Should successfully return customer credentials", func() {
				ocmMock.EXPECT().GetAWSAccountClaim(gomock.Any()).Return(accountClaim, nil)
				awsMock.EXPECT().AssumeRole(gomock.Any()).Return(&sts.AssumeRoleOutput{Credentials: &sts.Credentials{
					AccessKeyId:     awsP.String("accesskey"),
					SecretAccessKey: awsP.String("secret"),
					SessionToken:    awsP.String("sessionToken"),
				}}, nil)
				jrAwsMock := mocks.NewMockAwsClient(mockCtrl)
				awsBuilderMock.EXPECT().New("accesskey", "secret", "sessionToken", gomock.Any()).Return(jrAwsMock, nil)
				jrAwsMock.EXPECT().AssumeRole(gomock.Any()).Return(&sts.AssumeRoleOutput{Credentials: &sts.Credentials{
					AccessKeyId:     awsP.String("customerKey"),
					SecretAccessKey: awsP.String("customerSecret"),
					SessionToken:    awsP.String("customerToken"),
				}}, nil)
				aws.awsClientBuilder = awsBuilderMock
				aws.region = "us-east-1"
				out, err := aws.AssumeSupportRole()
				Expect(err).To(BeNil())
				Expect(out).NotTo(BeNil())
				Expect(*out.AccessKeyId).To(Equal("customerKey"))
			})
		})

	})
})

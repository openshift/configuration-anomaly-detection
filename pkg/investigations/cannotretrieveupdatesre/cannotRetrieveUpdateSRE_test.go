package cannotretrieveupdatesre

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	cmv1 "github.com/openshift-online/ocm-sdk-go/clustersmgmt/v1"
	configv1 "github.com/openshift/api/config/v1"
	awsmock "github.com/openshift/configuration-anomaly-detection/pkg/aws/mock"
	investigation "github.com/openshift/configuration-anomaly-detection/pkg/investigations/investigation"
	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
	pdmock "github.com/openshift/configuration-anomaly-detection/pkg/pagerduty/mock"
	hivev1 "github.com/openshift/hive/apis/hive/v1"
	"go.uber.org/mock/gomock"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

var _ = Describe("CannotRetrieveUpdatesSRE Investigation", func() {
	var (
		mockCtrl          *gomock.Controller
		clusterBuilder    *cmv1.ClusterBuilder
		cluster           *cmv1.Cluster
		clusterDeployment *hivev1.ClusterDeployment
		pdClient          *pdmock.MockClient
		awsCli            *awsmock.MockClient
		fakeClient        client.Client
		scheme            *runtime.Scheme
		inv               *Investigation
		resources         *investigation.Resources
	)

	BeforeEach(func() {
		logging.InitLogger("fatal", "")

		mockCtrl = gomock.NewController(GinkgoT())
		pdClient = pdmock.NewMockClient(mockCtrl)
		awsCli = awsmock.NewMockClient(mockCtrl)

		clusterBuilder = cmv1.NewCluster().ID("test-cluster")
		var err error
		cluster, err = clusterBuilder.Build()
		Expect(err).ToNot(HaveOccurred())

		clusterDeployment = &hivev1.ClusterDeployment{
			Spec: hivev1.ClusterDeploymentSpec{
				ClusterMetadata: &hivev1.ClusterMetadata{
					InfraID: "infra_id",
				},
			},
		}

		scheme = runtime.NewScheme()
		Expect(configv1.AddToScheme(scheme)).To(Succeed())
		fakeClient = fake.NewClientBuilder().WithScheme(scheme).Build()

		inv = &Investigation{
			kclient: fakeClient,
		}
		resources = &investigation.Resources{
			Cluster:           cluster,
			ClusterDeployment: clusterDeployment,
			PdClient:          pdClient,
			AwsClient:         awsCli,
			Name:              remediationName,
		}
	})

	AfterEach(func() {
		mockCtrl.Finish()
	})

	Describe("Run Method", func() {
		When("ClusterVersion has VersionNotFound condition", func() {
			It("Should detect the condition and escalate with appropriate notes", func() {
				cv := &configv1.ClusterVersion{
					ObjectMeta: v1.ObjectMeta{Name: "version"},
					Spec:       configv1.ClusterVersionSpec{Channel: "stable-4.18"},
					Status: configv1.ClusterVersionStatus{
						Desired: configv1.Release{Version: "4.18.5"},
						Conditions: []configv1.ClusterOperatorStatusCondition{
							{
								Type:    "RetrievedUpdates",
								Status:  "False",
								Reason:  "VersionNotFound",
								Message: "Unable to retrieve available updates: version 4.18.5 not found",
							},
						},
					},
				}
				fakeClient = fake.NewClientBuilder().WithScheme(scheme).WithObjects(cv).Build()
				inv.kclient = fakeClient

				// Arrange
				awsCli.EXPECT().GetSecurityGroupID(gomock.Eq(clusterDeployment.Spec.ClusterMetadata.InfraID)).Return("sg-123", nil)
				awsCli.EXPECT().GetSubnetID(gomock.Eq(clusterDeployment.Spec.ClusterMetadata.InfraID)).Return([]string{"subnet-1"}, nil)
				pdClient.EXPECT().EscalateIncidentWithNote(gomock.Any()).DoAndReturn(func(note string) error {
					Expect(note).To(ContainSubstring("Network verifier passed"))
					Expect(note).To(ContainSubstring("ClusterVersion error detected: Unable to retrieve available updates: version 4.18.5 not found"))
					Expect(note).To(ContainSubstring("This indicates the current version 4.18.5 is not found in the specified channel stable-4.18"))
					Expect(note).To(ContainSubstring("Alert escalated to on-call primary for review"))
					return nil
				})

				// Act
				result, err := inv.Run(resources)

				// Assert
				Expect(err).ToNot(HaveOccurred())
				Expect(result.ServiceLogPrepared.Performed).To(BeFalse())
			})
		})

		When("Network verifier fails", func() {
			It("Should prepare a service log and escalate", func() {
				// Arrange
				awsCli.EXPECT().GetSecurityGroupID(gomock.Eq(clusterDeployment.Spec.ClusterMetadata.InfraID)).Return("sg-123", nil)
				awsCli.EXPECT().GetSubnetID(gomock.Eq(clusterDeployment.Spec.ClusterMetadata.InfraID)).Return([]string{"subnet-1"}, nil)
				pdClient.EXPECT().EscalateIncidentWithNote(gomock.Any()).DoAndReturn(func(note string) error {
					Expect(note).To(ContainSubstring("NetworkVerifier found unreachable targets"))
					Expect(note).To(ContainSubstring("osdctl servicelog post test-cluster"))
					Expect(note).To(ContainSubstring("Alert escalated to on-call primary for review"))
					return nil
				})

				// Act
				result, err := inv.Run(resources)

				// Assert
				Expect(err).ToNot(HaveOccurred())
				Expect(result.ServiceLogPrepared.Performed).To(BeTrue())
			})
		})

		When("Kubernetes client fails to list ClusterVersion", func() {
			It("Should escalate with a warning note", func() {
				fakeClient = fake.NewClientBuilder().WithScheme(scheme).WithRuntimeObjects().Build()
				inv.kclient = fakeClient

				// Arrange
				awsCli.EXPECT().GetSecurityGroupID(gomock.Eq(clusterDeployment.Spec.ClusterMetadata.InfraID)).Return("sg-123", nil)
				awsCli.EXPECT().GetSubnetID(gomock.Eq(clusterDeployment.Spec.ClusterMetadata.InfraID)).Return([]string{"subnet-1"}, nil)
				pdClient.EXPECT().EscalateIncidentWithNote(gomock.Any()).DoAndReturn(func(note string) error {
					Expect(note).To(ContainSubstring("Network verifier passed"))
					Expect(note).To(ContainSubstring("Failed to list ClusterVersion"))
					Expect(note).To(ContainSubstring("This may indicate cluster access issues"))
					Expect(note).To(ContainSubstring("Alert escalated to on-call primary for review"))
					return nil
				})

				// Act
				result, err := inv.Run(resources)

				// Assert
				Expect(err).ToNot(HaveOccurred())
				Expect(result.ServiceLogPrepared.Performed).To(BeFalse())
			})
		})
	})
})

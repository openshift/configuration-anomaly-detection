package aiassisted

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	cmv1 "github.com/openshift-online/ocm-sdk-go/clustersmgmt/v1"
	awsmock "github.com/openshift/configuration-anomaly-detection/pkg/aws/mock"
	backplanemock "github.com/openshift/configuration-anomaly-detection/pkg/backplane/mock"
	"github.com/openshift/configuration-anomaly-detection/pkg/executor"
	investigation "github.com/openshift/configuration-anomaly-detection/pkg/investigations/investigation"
	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
	"github.com/openshift/configuration-anomaly-detection/pkg/notewriter"
	ocmmock "github.com/openshift/configuration-anomaly-detection/pkg/ocm/mock"
	pdmock "github.com/openshift/configuration-anomaly-detection/pkg/pagerduty/mock"
	"github.com/openshift/configuration-anomaly-detection/pkg/types"
	hivev1 "github.com/openshift/hive/apis/hive/v1"
	"go.uber.org/mock/gomock"
)

func TestAiassisted(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Aiassisted Suite")
}

// Test helper functions to check for specific action types
func hasActionType(actions []types.Action, actionType string) bool {
	for _, action := range actions {
		if action.Type() == actionType {
			return true
		}
	}
	return false
}

func hasEscalateAction(actions []types.Action) bool {
	return hasActionType(actions, string(executor.ActionTypeEscalateIncident))
}

func hasNoteAction(actions []types.Action) bool {
	return hasActionType(actions, string(executor.ActionTypePagerDutyNote))
}

var _ = Describe("aiassisted", func() {
	var (
		r                 *investigation.ResourceBuilderMock
		mockCtrl          *gomock.Controller
		cluster           *cmv1.Cluster
		clusterDeployment *hivev1.ClusterDeployment
	)

	BeforeEach(func() {
		logging.InitLogger("fatal", "", "") // Mute logger for the tests
		mockCtrl = gomock.NewController(GinkgoT())

		var err error

		region := cmv1.NewCloudRegion().Name("us-east-1")
		cluster, err = cmv1.NewCluster().
			ID("test-cluster-id").
			State(cmv1.ClusterStateReady).
			Region(region).
			Build()
		Expect(err).ToNot(HaveOccurred())

		clusterDeployment = &hivev1.ClusterDeployment{
			Spec: hivev1.ClusterDeploymentSpec{
				ClusterMetadata: &hivev1.ClusterMetadata{
					InfraID: "test-infra-id",
				},
			},
		}

		r = &investigation.ResourceBuilderMock{
			Resources: &investigation.Resources{
				Name:              "Test",
				Cluster:           cluster,
				ClusterDeployment: clusterDeployment,
				AwsClient:         awsmock.NewMockClient(mockCtrl),
				BpClient:          &backplanemock.MockClient{},
				OcmClient:         ocmmock.NewMockClient(mockCtrl),
				PdClient:          pdmock.NewMockClient(mockCtrl),
				Notes:             notewriter.New("Test", logging.RawLogger),
			},
		}
	})

	AfterEach(func() {
		mockCtrl.Finish()
	})

	Describe("Run", func() {
		Context("when AI runtime configuration is nil", func() {
			It("should escalate with configuration warning", func() {
				inv := Investigation{AIConfig: nil}
				result, err := inv.Run(r)

				Expect(err).ToNot(HaveOccurred())
				Expect(result.Actions).NotTo(BeEmpty())
				Expect(hasEscalateAction(result.Actions)).To(BeTrue())
				Expect(hasNoteAction(result.Actions)).To(BeTrue())
			})
		})
	})
})

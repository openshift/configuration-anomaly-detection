package aiassisted

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	cmv1 "github.com/openshift-online/ocm-sdk-go/clustersmgmt/v1"
	awsmock "github.com/openshift/configuration-anomaly-detection/pkg/aws/mock"
	backplanemock "github.com/openshift/configuration-anomaly-detection/pkg/backplane/mock"
	"github.com/openshift/configuration-anomaly-detection/pkg/executor"
	investigation "github.com/openshift/configuration-anomaly-detection/pkg/investigations/investigation"
	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
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
				Notes:             nil,
			},
		}
	})

	AfterEach(func() {
		mockCtrl.Finish()
	})

	inv := Investigation{}

	Describe("Run", func() {
		Context("when AI configuration is not set", func() {
			It("should escalate with configuration warning", func() {
				// By default, CAD_AI_AGENT_CONFIG env var is not set in tests
				result, err := inv.Run(r)

				Expect(err).ToNot(HaveOccurred())
				Expect(result.Actions).NotTo(BeEmpty())
				Expect(hasEscalateAction(result.Actions)).To(BeTrue())
				Expect(hasNoteAction(result.Actions)).To(BeTrue())
			})
		})

		Context("when AI is disabled in configuration", func() {
			BeforeEach(func() {
				err := os.Setenv("CAD_AI_AGENT_CONFIG", `{
					"enabled": false,
					"runtime_arn": "test-arn",
					"region": "us-east-1",
					"user_id": "test-user"
				}`)
				Expect(err).ToNot(HaveOccurred())
			})

			AfterEach(func() {
				err := os.Unsetenv("CAD_AI_AGENT_CONFIG")
				Expect(err).ToNot(HaveOccurred())
			})

			It("should escalate with disabled warning", func() {
				result, err := inv.Run(r)

				Expect(err).ToNot(HaveOccurred())
				Expect(result.Actions).NotTo(BeEmpty())
				Expect(hasEscalateAction(result.Actions)).To(BeTrue())
				Expect(hasNoteAction(result.Actions)).To(BeTrue())
			})
		})

		Context("when organization ID fetch fails", func() {
			BeforeEach(func() {
				err := os.Setenv("CAD_AI_AGENT_CONFIG", `{
					"enabled": true,
					"runtime_arn": "test-arn",
					"region": "us-east-1",
					"user_id": "test-user"
				}`)
				Expect(err).ToNot(HaveOccurred())

				ocmClient := r.Resources.OcmClient.(*ocmmock.MockClient)
				ocmClient.EXPECT().GetOrganizationID(gomock.Any()).Return("", fmt.Errorf("failed to fetch organization"))
			})

			AfterEach(func() {
				err := os.Unsetenv("CAD_AI_AGENT_CONFIG")
				Expect(err).ToNot(HaveOccurred())
			})

			It("should escalate with organization error", func() {
				result, err := inv.Run(r)

				Expect(err).ToNot(HaveOccurred())
				Expect(result.Actions).NotTo(BeEmpty())
				Expect(hasEscalateAction(result.Actions)).To(BeTrue())
				Expect(hasNoteAction(result.Actions)).To(BeTrue())
			})
		})

		Context("when cluster is not in allowlist", func() {
			BeforeEach(func() {
				err := os.Setenv("CAD_AI_AGENT_CONFIG", `{
					"enabled": true,
					"runtime_arn": "test-arn",
					"region": "us-east-1",
					"user_id": "test-user",
					"clusters": ["other-cluster-id"],
					"organizations": ["test-org-id"]
				}`)
				Expect(err).ToNot(HaveOccurred())

				ocmClient := r.Resources.OcmClient.(*ocmmock.MockClient)
				ocmClient.EXPECT().GetOrganizationID("test-cluster-id").Return("test-org-id", nil)
			})

			AfterEach(func() {
				err := os.Unsetenv("CAD_AI_AGENT_CONFIG")
				Expect(err).ToNot(HaveOccurred())
			})

			It("should escalate with allowlist error", func() {
				result, err := inv.Run(r)

				Expect(err).ToNot(HaveOccurred())
				Expect(result.Actions).NotTo(BeEmpty())
				Expect(hasEscalateAction(result.Actions)).To(BeTrue())
				Expect(hasNoteAction(result.Actions)).To(BeTrue())
			})
		})

		Context("when organization is not in allowlist", func() {
			BeforeEach(func() {
				err := os.Setenv("CAD_AI_AGENT_CONFIG", `{
					"enabled": true,
					"runtime_arn": "test-arn",
					"region": "us-east-1",
					"user_id": "test-user",
					"clusters": ["test-cluster-id"],
					"organizations": ["other-org-id"]
				}`)
				Expect(err).ToNot(HaveOccurred())

				ocmClient := r.Resources.OcmClient.(*ocmmock.MockClient)
				ocmClient.EXPECT().GetOrganizationID("test-cluster-id").Return("test-org-id", nil)
			})

			AfterEach(func() {
				err := os.Unsetenv("CAD_AI_AGENT_CONFIG")
				Expect(err).ToNot(HaveOccurred())
			})

			It("should escalate with allowlist error", func() {
				result, err := inv.Run(r)

				Expect(err).ToNot(HaveOccurred())
				Expect(result.Actions).NotTo(BeEmpty())
				Expect(hasEscalateAction(result.Actions)).To(BeTrue())
				Expect(hasNoteAction(result.Actions)).To(BeTrue())
			})
		})
	})

	Describe("InvestigationPayload", func() {
		Context("ToAgentCorePayload", func() {
			It("should marshal to correct JSON format", func() {
				payload := InvestigationPayload{
					InvestigationID:      "test-incident-id",
					InvestigationPayload: "",
					AlertName:            "test-alert-name",
					ClusterID:            "test-cluster-id",
				}

				jsonBytes, err := payload.ToAgentCorePayload()
				Expect(err).ToNot(HaveOccurred())
				Expect(jsonBytes).NotTo(BeNil())

				// Unmarshal to verify structure
				var wrapper map[string]interface{}
				err = json.Unmarshal(jsonBytes, &wrapper)
				Expect(err).ToNot(HaveOccurred())

				// Check wrapper has "prompt" field
				Expect(wrapper).To(HaveKey("prompt"))
				promptStr, ok := wrapper["prompt"].(string)
				Expect(ok).To(BeTrue())

				// Parse inner JSON
				var innerPayload InvestigationPayload
				err = json.Unmarshal([]byte(promptStr), &innerPayload)
				Expect(err).ToNot(HaveOccurred())

				// Verify inner fields
				Expect(innerPayload.InvestigationID).To(Equal("test-incident-id"))
				Expect(innerPayload.AlertName).To(Equal("test-alert-name"))
				Expect(innerPayload.ClusterID).To(Equal("test-cluster-id"))
				Expect(innerPayload.InvestigationPayload).To(Equal(""))
			})

			It("should handle special characters in alert name", func() {
				payload := InvestigationPayload{
					InvestigationID:      "test-id",
					InvestigationPayload: "",
					AlertName:            "[HCP] (Critical) api-RapidErrorBudgetBurn test-cluster - test-host",
					ClusterID:            "test-cluster-id",
				}

				jsonBytes, err := payload.ToAgentCorePayload()
				Expect(err).ToNot(HaveOccurred())

				var wrapper map[string]interface{}
				err = json.Unmarshal(jsonBytes, &wrapper)
				Expect(err).ToNot(HaveOccurred())

				promptStr := wrapper["prompt"].(string)
				Expect(promptStr).To(ContainSubstring("[HCP]"))
				Expect(promptStr).To(ContainSubstring("(Critical)"))
			})
		})
	})
})

package aiassisted

import (
	"encoding/json"
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
		Context("when cluster is a management cluster", func() {
			It("should skip AI investigation and escalate", func() {
				r.Resources.IsInfrastructureCluster = true

				inv := Investigation{}
				result, err := inv.Run(r)

				Expect(err).ToNot(HaveOccurred())
				Expect(result.Actions).NotTo(BeEmpty())
				Expect(hasEscalateAction(result.Actions)).To(BeTrue())
				Expect(hasNoteAction(result.Actions)).To(BeTrue())
			})
		})

		Context("when AI runtime configuration is nil", func() {
			It("should escalate with configuration warning", func() {
				inv := Investigation{}
				result, err := inv.Run(r)

				Expect(err).ToNot(HaveOccurred())
				Expect(result.Actions).NotTo(BeEmpty())
				Expect(hasEscalateAction(result.Actions)).To(BeTrue())
				Expect(hasNoteAction(result.Actions)).To(BeTrue())
			})
		})
	})

	// Happy Path to Test Investigation Report Format
	Describe("FormatInvestigationReport", func() {
		Context("when formatting a complete investigation result", func() {
			It("should create human-readable markdown with all fields", func() {
				command := "oc apply -f fix.yaml"

				result := &CoraInvestigationResult{
					ClusterID:  "test-cluster-abc",
					AlertName:  "ClusterOperatorDegraded",
					Summary:    "The cluster-samples-operator is degraded due to missing ImageStreams",
					Confidence: "high",
					Reasoning:  "Root cause analysis shows the operator cannot find required ImageStreams",
					Evidence:   "Checked cluster-samples-operator logs and found missing ImageStream errors",
					RemediationSteps: []RemediationStep{
						{
							Action:  "Restore default ImageStreams",
							Command: &command,
						},
					},
					NeedsEscalation: true,
				}

				output := FormatInvestigationReport(result)

				Expect(output).To(ContainSubstring("test-cluster-abc"))
				Expect(output).To(ContainSubstring("ClusterOperatorDegraded"))
				Expect(output).To(ContainSubstring("The cluster-samples-operator is degraded"))
				Expect(output).To(ContainSubstring("HIGH"))
				Expect(output).To(ContainSubstring("Restore default ImageStreams"))
				Expect(output).To(ContainSubstring("oc apply -f fix.yaml"))
				Expect(output).To(ContainSubstring("⚠️ ESCALATE"))
			})
		})

		// Tests whether Go handles "null" command case correctly
		Context("when handling null command", func() {
			It("should skip code block when command is nil", func() {
				result := &CoraInvestigationResult{
					ClusterID:  "test-cluster",
					AlertName:  "TestAlert",
					Summary:    "Issue found",
					Confidence: "high",
					Reasoning:  "Manual verification required",
					Evidence:   "System logs inconclusive",
					RemediationSteps: []RemediationStep{
						{
							Action:  "Manually verify the configuration in console",
							Command: nil,
						},
					},
					NeedsEscalation: false,
				}

				output := FormatInvestigationReport(result)

				Expect(output).To(ContainSubstring("Manually verify the configuration"))
				Expect(output).ToNot(ContainSubstring("```bash"))
			})
		})

		// Tests empty steps array
		Context("when remediation has no steps", func() {
			It("should show no action steps available message", func() {
				result := &CoraInvestigationResult{
					ClusterID:        "test-cluster",
					AlertName:        "TestAlert",
					Summary:          "Self-healing succeeded",
					Confidence:       "high",
					Reasoning:        "System automatically resolved the issue",
					Evidence:         "Cluster operators returned to healthy state",
					RemediationSteps: []RemediationStep{},
					NeedsEscalation:  false,
				}

				output := FormatInvestigationReport(result)

				Expect(output).To(ContainSubstring("No action steps available"))
			})
		})

		// Tests JSON parsing with real Cora output.
		// If only err = nil --> parsing worked.
		// If error != nil --> parsing failed
		Context("when parsing real Cora JSON output", func() {
			It("should correctly unmarshal JSON into structs", func() {
				jsonInput := `{
					"investigation_id": "inv-quick-schema-test",
					"cluster_id": "test-cluster",
					"alert_name": "QuickSchemaTest",
					"timestamp": "2026-07-06T20:11:38.578390Z",
					"duration_seconds": 22.301245596,
					"summary": "Test investigation completed successfully",
					"confidence": "high",
					"reasoning": "This investigation was explicitly marked as a quick schema test",
					"evidence": "Investigation request received with the following parameters",
					"remediation_steps": [
						{
							"action": "No remediation required - this was a test investigation to validate the schema",
							"command": null
						}
					],
					"needs_escalation": false,
					"escalation_reason": null
				}`

				var result CoraInvestigationResult
				err := json.Unmarshal([]byte(jsonInput), &result)

				Expect(err).ToNot(HaveOccurred())
				Expect(result.ClusterID).To(Equal("test-cluster"))
				Expect(result.AlertName).To(Equal("QuickSchemaTest"))
				Expect(result.Summary).To(Equal("Test investigation completed successfully"))
				Expect(result.Confidence).To(Equal("high"))
				Expect(result.RemediationSteps).To(HaveLen(1))
				Expect(result.RemediationSteps[0].Command).To(BeNil())
				Expect(result.NeedsEscalation).To(BeFalse())
			})
		})
	})
})

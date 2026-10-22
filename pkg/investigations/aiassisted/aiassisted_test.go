package aiassisted

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/bedrockagentcore"
	"github.com/openshift/configuration-anomaly-detection/pkg/aws"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	cmv1 "github.com/openshift-online/ocm-sdk-go/clustersmgmt/v1"
	awsmock "github.com/openshift/configuration-anomaly-detection/pkg/aws/mock"
	backplanemock "github.com/openshift/configuration-anomaly-detection/pkg/backplane/mock"
	"github.com/openshift/configuration-anomaly-detection/pkg/config"
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

// Test constants to avoid goconst violations
const (
	testClusterID = "test-cluster"
	testAlertName = "TestAlert"
	testConfHigh  = "high"
	testConfLow   = "low"
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

func expectReportNoteEscalation(actions []types.Action) {
	GinkgoHelper()
	Expect(actions).To(HaveLen(3), "expected exactly a Backplane report, PagerDuty note, and escalation action")
	Expect(actions[0].Type()).To(Equal(string(executor.ActionTypeBackplaneReport)), "the Backplane report must precede the note so its report link can be included")
	Expect(actions[1].Type()).To(Equal(string(executor.ActionTypePagerDutyNote)), "the PagerDuty note must follow the report and precede escalation")
	Expect(actions[2].Type()).To(Equal(string(executor.ActionTypeEscalateIncident)), "escalation must be queued last, after reporting")
}

type testAgentClient struct {
	stream io.ReadCloser
	err    error
}

func (c testAgentClient) InvokeAgentRuntime(context.Context, *bedrockagentcore.InvokeAgentRuntimeInput, ...func(*bedrockagentcore.Options)) (*bedrockagentcore.InvokeAgentRuntimeOutput, error) {
	if c.err != nil {
		return nil, c.err
	}
	return &bedrockagentcore.InvokeAgentRuntimeOutput{Response: c.stream}, nil
}

type testAIStream struct {
	*strings.Reader
	err    error
	closed bool
}

func (s *testAIStream) Read(p []byte) (int, error) {
	n, err := s.Reader.Read(p)
	if err == io.EOF && s.err != nil {
		return n, s.err
	}
	return n, err
}

func (s *testAIStream) Close() error {
	s.closed = true
	return nil
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

		Context("when cluster is HCP", func() {
			It("returns a note before escalation without contacting AWS", func() {
				r.Resources.IsHCP = true
				result, err := (&Investigation{}).Run(r)
				Expect(err).NotTo(HaveOccurred(), "HCP clusters should skip AI and return reporting actions without an error")
				Expect(result.Actions).To(HaveLen(2), "HCP clusters should return only a warning note and escalation, with no Backplane report")
				Expect(result.Actions[0].Type()).To(Equal(string(executor.ActionTypePagerDutyNote)), "the HCP warning note must precede escalation")
				Expect(result.Actions[1].Type()).To(Equal(string(executor.ActionTypeEscalateIncident)), "HCP clusters must queue escalation after the warning note")
			})
		})

		Context("when PagerDuty client is missing", func() {
			It("returns a warning report and note before escalation", func() {
				r.Resources.PdClient = nil
				result, err := (&Investigation{AIConfig: &config.AIAgentConfig{}}).Run(r)
				Expect(err).NotTo(HaveOccurred(), "a missing PagerDuty client should produce warning reporting and escalation actions, not a Run error")
				expectReportNoteEscalation(result.Actions)
			})
		})

		Context("when AI runtime configuration is nil", func() {
			It("should escalate with configuration warning", func() {
				inv := Investigation{}
				result, err := inv.Run(r)

				Expect(err).ToNot(HaveOccurred())
				Expect(result.Actions).NotTo(BeEmpty())
				expectReportNoteEscalation(result.Actions)
			})
		})

		Context("when a PagerDuty client is available on a non-HCP, non-infra cluster", func() {
			It("accesses PdClient through the pagerduty.Client interface, not a concrete-type assertion", func() {
				// Regression test: Run used to fetch incident details via
				// `r.PdClient.(*pagerduty.SdkClient)`, a concrete-type
				// assertion. Any interface-only implementation of
				// pagerduty.Client (like this mock, or the trackingPDClient
				// wrapper used in production) would fail that assertion and
				// silently skip the whole AI investigation. These EXPECT
				// calls only pass if Run instead calls the methods directly
				// on the pagerduty.Client interface.
				pdClientMock := pdmock.NewMockClient(mockCtrl)
				pdClientMock.EXPECT().GetIncidentID().Return("INC-123").Times(1)
				pdClientMock.EXPECT().GetTitle().Return("SomeAlert").Times(1)
				r.Resources.PdClient = pdClientMock

				inv := Investigation{
					AIConfig: &config.AIAgentConfig{
						RuntimeARN:     "arn:aws:bedrock-agentcore:us-east-1:123456789012:runtime/test",
						Region:         "us-east-1",
						UserID:         "cad-test",
						InvokerRoleArn: "arn:aws:iam::123456789012:role/test-role",
						TimeoutSeconds: 60,
					},
					// Never assume a cancelled context prevents SDK credential or
					// network access: stub the entire AWS client factory.
					getAIClient: func(context.Context, string, string, string) (aws.AgentCoreAPI, error) {
						return nil, errors.New("offline client failure")
					},
				}
				result, err := inv.Run(r)

				Expect(err).ToNot(HaveOccurred())
				expectReportNoteEscalation(result.Actions)
			})
		})

		DescribeTable("reports before escalating every AI outcome without calling AWS",
			func(response string, clientErr, invokeErr, readErr error, timeout int) {
				pd := pdmock.NewMockClient(mockCtrl)
				pd.EXPECT().GetIncidentID().Return("INC-123")
				pd.EXPECT().GetTitle().Return(testAlertName)
				// No EscalateIncident expectation: Run must not escalate directly.
				r.Resources.PdClient = pd
				stream := &testAIStream{Reader: strings.NewReader(response), err: readErr}
				inv := Investigation{
					AIConfig: &config.AIAgentConfig{TimeoutSeconds: timeout},
					getAIClient: func(context.Context, string, string, string) (aws.AgentCoreAPI, error) {
						return testAgentClient{stream: stream, err: invokeErr}, clientErr
					},
				}
				result, err := inv.Run(r)
				Expect(err).NotTo(HaveOccurred(), "every AI outcome should return reporting and escalation actions rather than a Run error")
				expectReportNoteEscalation(result.Actions)
				if clientErr == nil && invokeErr == nil {
					Expect(stream.closed).To(BeTrue(), "the AI response stream must be closed after success, read failure, timeout, or invalid JSON")
					if timeout == 0 {
						Expect(r.Resources.Notes.String()).To(ContainSubstring("timed out or was cancelled"), "an expired context must record a timeout warning even when the stream ends with clean EOF")
					}
				}
			},
			Entry("success recommending escalation", `{"summary":"done","needs_escalation":true}`, nil, nil, nil, 60),
			Entry("success recommending no escalation", `{"summary":"done","needs_escalation":false}`, nil, nil, nil, 60),
			Entry("client creation failure", "", errors.New("client failed"), nil, nil, 60),
			Entry("invocation failure", "", nil, errors.New("invoke failed"), nil, 60),
			Entry("invocation timeout", "", nil, context.DeadlineExceeded, nil, 0),
			Entry("stream failure", "partial", nil, nil, errors.New("read failed"), 60),
			Entry("stream timeout with clean EOF", `{"summary":"partial"}`, nil, nil, nil, 0),
			Entry("invalid JSON", "not json", nil, nil, nil, 60),
		)
	})

	Describe("FormatPagerDutyNote", func() {
		Context("when formatting a complete investigation result", func() {
			It("should produce a well-structured plain text note", func() {
				result := &CoraInvestigationResult{
					ClusterID:        "test-cluster-abc",
					AlertName:        "ClusterOperatorDegraded CRITICAL (1)",
					Summary:          "The cluster-samples-operator is degraded due to missing ImageStreams",
					Confidence:       testConfHigh,
					NeedsEscalation:  true,
					RemediationSteps: []RemediationStep{},
				}

				output := FormatPagerDutyNote(result)

				Expect(output).To(ContainSubstring("Alert: ClusterOperatorDegraded CRITICAL (1)"), "should contain alert name")
				Expect(output).To(ContainSubstring("Confidence: HIGH"), "should contain uppercase confidence")
				Expect(output).To(ContainSubstring("The cluster-samples-operator is degraded"), "should contain summary text")
				Expect(output).To(ContainSubstring("⚠️ Cora recommends escalation"), "should contain escalation recommendation")
				Expect(output).ToNot(ContainSubstring("--report-id report-id"), "report IDs are appended after report creation")

				Expect(output).ToNot(ContainSubstring("REASONING:"), "simplified note should not contain reasoning section")
				Expect(output).ToNot(ContainSubstring("ACTION STEPS:"), "simplified note should not contain action steps section")
			})
		})

		Context("when no escalation is needed", func() {
			It("should show no escalation needed message", func() {
				result := &CoraInvestigationResult{
					ClusterID:        testClusterID,
					AlertName:        testAlertName,
					Summary:          "Self-healing succeeded",
					Confidence:       testConfHigh,
					RemediationSteps: []RemediationStep{},
					NeedsEscalation:  false,
				}

				output := FormatPagerDutyNote(result)

				Expect(output).To(ContainSubstring("✅ Cora: no further escalation needed"), "should show Cora's no-escalation message")
				Expect(output).ToNot(ContainSubstring("⚠️"), "should not contain escalation warning emoji")
			})
		})

		Context("when escalation is needed", func() {
			It("should show Cora's escalation recommendation", func() {
				result := &CoraInvestigationResult{
					ClusterID:        testClusterID,
					AlertName:        testAlertName,
					Summary:          "Investigation inconclusive",
					Confidence:       testConfLow,
					RemediationSteps: []RemediationStep{},
					NeedsEscalation:  true,
				}

				output := FormatPagerDutyNote(result)

				Expect(output).To(ContainSubstring("⚠️ Cora recommends escalation"), "should show Cora's escalation recommendation")
			})
		})

		Context("when Cora returns a cluster ID", func() {
			It("should not include a report footer before the report is created", func() {
				result := &CoraInvestigationResult{
					ClusterID:        "cora-returned-id",
					AlertName:        testAlertName,
					Summary:          "Issue found",
					Confidence:       testConfHigh,
					RemediationSteps: []RemediationStep{},
					NeedsEscalation:  false,
				}

				output := FormatPagerDutyNote(result)

				Expect(output).ToNot(ContainSubstring("--report-id"), "report command is appended after report creation")
				Expect(output).ToNot(ContainSubstring("cora-returned-id"), "note should not contain Cora's internal cluster ID")
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
					Confidence: testConfHigh,
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
					ClusterID:  testClusterID,
					AlertName:  testAlertName,
					Summary:    "Issue found",
					Confidence: testConfHigh,
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
					ClusterID:        testClusterID,
					AlertName:        testAlertName,
					Summary:          "Self-healing succeeded",
					Confidence:       testConfHigh,
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
				Expect(result.ClusterID).To(Equal(testClusterID))
				Expect(result.AlertName).To(Equal("QuickSchemaTest"))
				Expect(result.Summary).To(Equal("Test investigation completed successfully"))
				Expect(result.Confidence).To(Equal(testConfHigh))
				Expect(result.RemediationSteps).To(HaveLen(1))
				Expect(result.RemediationSteps[0].Command).To(BeNil())
				Expect(result.NeedsEscalation).To(BeFalse())
			})
		})
	})
})

package upgradeconfigsyncfailureover4hr

import (
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	cmv1 "github.com/openshift-online/ocm-sdk-go/clustersmgmt/v1"
	"github.com/openshift/configuration-anomaly-detection/pkg/executor"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/investigation"
	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
	"github.com/openshift/configuration-anomaly-detection/pkg/notewriter"
	"github.com/openshift/configuration-anomaly-detection/pkg/ocm"
	ocmmock "github.com/openshift/configuration-anomaly-detection/pkg/ocm/mock"
	"github.com/openshift/configuration-anomaly-detection/pkg/types"
	"go.uber.org/mock/gomock"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func testScheme() *runtime.Scheme {
	s := runtime.NewScheme()
	_ = corev1.AddToScheme(s)
	return s
}

func hasActionType(actions []types.Action, actionType string) bool {
	for _, action := range actions {
		if action.Type() == actionType {
			return true
		}
	}
	return false
}

func hasSilenceAction(actions []types.Action) bool {
	return hasActionType(actions, string(executor.ActionTypeSilenceIncident))
}

func hasEscalateAction(actions []types.Action) bool {
	return hasActionType(actions, string(executor.ActionTypeEscalateIncident))
}

func hasServiceLogAction(actions []types.Action) bool {
	return hasActionType(actions, string(executor.ActionTypeServiceLog))
}

var _ = Describe("parseMUOLogs", func() {
	var notes *notewriter.NoteWriter

	BeforeEach(func() {
		logging.InitLogger("fatal", "", "")
		notes = notewriter.New("test", logging.RawLogger)
	})

	It("should detect leader election deadlock", func() {
		logs := `2026-10-19T10:00:00Z INFO starting operator
2026-10-19T10:01:00Z ERROR Leader pod has been deleted, waiting for garbage collection
2026-10-19T10:02:00Z INFO retrying`
		parseMUOLogs(logs, notes)
		Expect(notes.String()).To(ContainSubstring("MUO deadlock detected"))
	})

	It("should detect TLS handshake timeout", func() {
		logs := `2026-10-19T10:00:00Z INFO starting sync
2026-10-19T10:01:00Z ERROR net/http: TLS handshake timeout
2026-10-19T10:02:00Z INFO retrying`
		parseMUOLogs(logs, notes)
		Expect(notes.String()).To(ContainSubstring("TLS handshake timeout"))
	})

	It("should detect ocm-config-getter errors", func() {
		logs := `2026-10-19T10:00:00Z ERROR ocm-config-getter failed to retrieve config from OCM`
		parseMUOLogs(logs, notes)
		Expect(notes.String()).To(ContainSubstring("ocm-config-getter"))
	})

	It("should detect multiple patterns", func() {
		logs := `Leader pod has been deleted, waiting for garbage collection
net/http: TLS handshake timeout`
		parseMUOLogs(logs, notes)
		output := notes.String()
		Expect(output).To(ContainSubstring("deadlock"))
		Expect(output).To(ContainSubstring("TLS handshake"))
	})

	It("should report success when no patterns found", func() {
		logs := `2026-10-19T10:00:00Z INFO everything is fine
2026-10-19T10:01:00Z INFO sync complete`
		parseMUOLogs(logs, notes)
		Expect(notes.String()).To(ContainSubstring("No known error patterns"))
	})

	It("should handle empty logs", func() {
		parseMUOLogs("", notes)
		Expect(notes.String()).To(ContainSubstring("No known error patterns"))
	})
})

var _ = Describe("checkMUOConfig", func() {
	var notes *notewriter.NoteWriter

	BeforeEach(func() {
		logging.InitLogger("fatal", "", "")
		notes = notewriter.New("test", logging.RawLogger)
	})

	It("should succeed with correct ocmBaseUrl", func() {
		cm := &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      muoConfigMapName,
				Namespace: muoNamespace,
			},
			Data: map[string]string{
				"config.yaml": `configManager:
  source: OCM
  ocmBaseUrl: https://api.openshift.com`,
			},
		}
		k8sClient := fake.NewClientBuilder().WithScheme(testScheme()).WithObjects(cm).Build()
		err := checkMUOConfig(k8sClient, notes)
		Expect(err).NotTo(HaveOccurred())
		Expect(notes.String()).To(ContainSubstring("ocmBaseUrl is correct"))
	})

	It("should warn with wrong ocmBaseUrl", func() {
		cm := &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      muoConfigMapName,
				Namespace: muoNamespace,
			},
			Data: map[string]string{
				"config.yaml": `configManager:
  source: OCM
  ocmBaseUrl: https://wrong.example.com`,
			},
		}
		k8sClient := fake.NewClientBuilder().WithScheme(testScheme()).WithObjects(cm).Build()
		err := checkMUOConfig(k8sClient, notes)
		Expect(err).NotTo(HaveOccurred())
		Expect(notes.String()).To(ContainSubstring("wrong.example.com"))
		Expect(notes.String()).To(ContainSubstring(expectedOCMBase))
	})

	It("should error when configmap not found", func() {
		k8sClient := fake.NewClientBuilder().WithScheme(testScheme()).Build()
		err := checkMUOConfig(k8sClient, notes)
		Expect(err).To(HaveOccurred())
		Expect(notes.String()).To(ContainSubstring("Failed to read MUO configmap"))
	})

	It("should error when config.yaml key missing", func() {
		cm := &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      muoConfigMapName,
				Namespace: muoNamespace,
			},
			Data: map[string]string{
				"other-key": "value",
			},
		}
		k8sClient := fake.NewClientBuilder().WithScheme(testScheme()).WithObjects(cm).Build()
		err := checkMUOConfig(k8sClient, notes)
		Expect(err).To(HaveOccurred())
		Expect(notes.String()).To(ContainSubstring("missing 'config.yaml' key"))
	})

	It("should error on invalid YAML", func() {
		cm := &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      muoConfigMapName,
				Namespace: muoNamespace,
			},
			Data: map[string]string{
				"config.yaml": `: invalid yaml [[[`,
			},
		}
		k8sClient := fake.NewClientBuilder().WithScheme(testScheme()).WithObjects(cm).Build()
		err := checkMUOConfig(k8sClient, notes)
		Expect(err).To(HaveOccurred())
		Expect(notes.String()).To(ContainSubstring("Failed to parse MUO config"))
	})
})

var _ = Describe("Run", func() {
	var (
		mockCtrl *gomock.Controller
		r        *investigation.ResourceBuilderMock
		cluster  *cmv1.Cluster
		inv      Investigation
	)

	BeforeEach(func() {
		logging.InitLogger("fatal", "", "")
		mockCtrl = gomock.NewController(GinkgoT())
		var err error
		cluster, err = cmv1.NewCluster().ID("test-cluster-id").Build()
		Expect(err).NotTo(HaveOccurred())

		r = &investigation.ResourceBuilderMock{
			Resources: &investigation.Resources{
				Cluster:   cluster,
				OcmClient: ocmmock.NewMockClient(mockCtrl),
			},
		}
	})

	AfterEach(func() {
		mockCtrl.Finish()
	})

	When("user is banned due to export control", func() {
		It("should escalate", func() {
			r.Resources.OcmClient.(*ocmmock.MockClient).EXPECT().
				CheckIfUserBanned(gomock.Any()).
				Return(ocm.UserBannedError{Code: "export_control_compliance"})

			result, err := inv.Run(r)
			Expect(err).NotTo(HaveOccurred())
			Expect(hasEscalateAction(result.Actions)).To(BeTrue())
			Expect(hasSilenceAction(result.Actions)).To(BeFalse())
		})
	})

	When("user is banned for other reasons", func() {
		It("should send service log and silence", func() {
			r.Resources.OcmClient.(*ocmmock.MockClient).EXPECT().
				CheckIfUserBanned(gomock.Any()).
				Return(ocm.UserBannedError{Code: "terms_and_conditions"})

			result, err := inv.Run(r)
			Expect(err).NotTo(HaveOccurred())
			Expect(hasServiceLogAction(result.Actions)).To(BeTrue())
			Expect(hasSilenceAction(result.Actions)).To(BeTrue())
			Expect(hasEscalateAction(result.Actions)).To(BeFalse())
		})
	})

	When("ban check fails with unexpected error", func() {
		It("should escalate", func() {
			r.Resources.OcmClient.(*ocmmock.MockClient).EXPECT().
				CheckIfUserBanned(gomock.Any()).
				Return(fmt.Errorf("connection timeout"))

			result, err := inv.Run(r)
			Expect(err).NotTo(HaveOccurred())
			Expect(hasEscalateAction(result.Actions)).To(BeTrue())
			Expect(hasSilenceAction(result.Actions)).To(BeFalse())
		})
	})

	When("initial resource build fails", func() {
		It("should propagate the error", func() {
			r.BuildError = fmt.Errorf("infrastructure error: resource build failed")

			_, err := inv.Run(r)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("infrastructure error"))
		})
	})
})

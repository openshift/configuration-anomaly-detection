package upgradeconfigsyncfailureover4hr

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	sdk "github.com/openshift-online/ocm-sdk-go"
	amv1 "github.com/openshift-online/ocm-sdk-go/accountsmgmt/v1"
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
		found := parseMUOLogs(logs, notes)
		Expect(found).To(BeTrue())
		Expect(notes.String()).To(ContainSubstring("MUO deadlock detected"))
	})

	It("should detect TLS handshake timeout", func() {
		logs := `2026-10-19T10:00:00Z INFO starting sync
2026-10-19T10:01:00Z ERROR net/http: TLS handshake timeout
2026-10-19T10:02:00Z INFO retrying`
		found := parseMUOLogs(logs, notes)
		Expect(found).To(BeTrue())
		Expect(notes.String()).To(ContainSubstring("TLS handshake timeout"))
	})

	It("should detect ocm-config-getter errors at ERROR level", func() {
		logs := `2026-10-19T10:00:00Z ERROR ocm-config-getter failed to retrieve config from OCM`
		found := parseMUOLogs(logs, notes)
		Expect(found).To(BeTrue())
		Expect(notes.String()).To(ContainSubstring("ocm-config-getter"))
	})

	It("should not match ocm-config-getter at INFO level", func() {
		logs := `2026-10-19T10:00:00Z INFO ocm-config-getter: configuration loaded`
		found := parseMUOLogs(logs, notes)
		Expect(found).To(BeFalse())
		Expect(notes.String()).To(ContainSubstring("No known error patterns"))
	})

	It("should detect multiple patterns", func() {
		logs := `Leader pod has been deleted, waiting for garbage collection
net/http: TLS handshake timeout`
		found := parseMUOLogs(logs, notes)
		Expect(found).To(BeTrue())
		output := notes.String()
		Expect(output).To(ContainSubstring("deadlock"))
		Expect(output).To(ContainSubstring("TLS handshake"))
	})

	It("should report success when no patterns found", func() {
		logs := `2026-10-19T10:00:00Z INFO everything is fine
2026-10-19T10:01:00Z INFO sync complete`
		found := parseMUOLogs(logs, notes)
		Expect(found).To(BeFalse())
		Expect(notes.String()).To(ContainSubstring("No known error patterns"))
	})

	It("should handle empty logs", func() {
		found := parseMUOLogs("", notes)
		Expect(found).To(BeFalse())
		Expect(notes.String()).To(ContainSubstring("No known error patterns"))
	})
})

var _ = Describe("checkMUOConfig", func() {
	var notes *notewriter.NoteWriter

	BeforeEach(func() {
		logging.InitLogger("fatal", "", "")
		notes = notewriter.New("test", logging.RawLogger)
	})

	It("should succeed with correct ocmBaseUrl and OCM source", func() {
		cm := &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      muoConfigMapName,
				Namespace: muoNamespace,
			},
			Data: map[string]string{
				muoConfigKey: `configManager:
  source: OCM
  ocmBaseUrl: https://api.openshift.com`,
			},
		}
		k8sClient := fake.NewClientBuilder().WithScheme(testScheme()).WithObjects(cm).Build()
		found, err := checkMUOConfig(k8sClient, notes)
		Expect(err).NotTo(HaveOccurred())
		Expect(found).To(BeFalse())
		Expect(notes.String()).To(ContainSubstring("ocmBaseUrl is correct"))
	})

	It("should warn with wrong ocmBaseUrl", func() {
		cm := &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      muoConfigMapName,
				Namespace: muoNamespace,
			},
			Data: map[string]string{
				muoConfigKey: `configManager:
  source: OCM
  ocmBaseUrl: https://wrong.example.com`,
			},
		}
		k8sClient := fake.NewClientBuilder().WithScheme(testScheme()).WithObjects(cm).Build()
		found, err := checkMUOConfig(k8sClient, notes)
		Expect(err).NotTo(HaveOccurred())
		Expect(found).To(BeTrue())
		Expect(notes.String()).To(ContainSubstring("wrong.example.com"))
		Expect(notes.String()).To(ContainSubstring(expectedOCMBase))
	})

	It("should succeed with LOCAL source", func() {
		cm := &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      muoConfigMapName,
				Namespace: muoNamespace,
			},
			Data: map[string]string{
				muoConfigKey: `configManager:
  source: LOCAL`,
			},
		}
		k8sClient := fake.NewClientBuilder().WithScheme(testScheme()).WithObjects(cm).Build()
		found, err := checkMUOConfig(k8sClient, notes)
		Expect(err).NotTo(HaveOccurred())
		Expect(found).To(BeFalse())
		Expect(notes.String()).To(ContainSubstring("LOCAL"))
	})

	It("should warn with unknown source", func() {
		cm := &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      muoConfigMapName,
				Namespace: muoNamespace,
			},
			Data: map[string]string{
				muoConfigKey: `configManager:
  source: UNKNOWN`,
			},
		}
		k8sClient := fake.NewClientBuilder().WithScheme(testScheme()).WithObjects(cm).Build()
		found, err := checkMUOConfig(k8sClient, notes)
		Expect(err).NotTo(HaveOccurred())
		Expect(found).To(BeTrue())
		Expect(notes.String()).To(ContainSubstring("UNKNOWN"))
	})

	It("should report finding when configmap key missing", func() {
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
		found, err := checkMUOConfig(k8sClient, notes)
		Expect(err).NotTo(HaveOccurred())
		Expect(found).To(BeTrue())
		Expect(notes.String()).To(ContainSubstring("missing"))
	})

	It("should error when configmap not found", func() {
		k8sClient := fake.NewClientBuilder().WithScheme(testScheme()).Build()
		_, err := checkMUOConfig(k8sClient, notes)
		Expect(err).To(HaveOccurred())
		Expect(notes.String()).To(ContainSubstring("Failed to read MUO configmap"))
	})

	It("should error on invalid YAML", func() {
		cm := &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      muoConfigMapName,
				Namespace: muoNamespace,
			},
			Data: map[string]string{
				muoConfigKey: `: invalid yaml [[[`,
			},
		}
		k8sClient := fake.NewClientBuilder().WithScheme(testScheme()).WithObjects(cm).Build()
		_, err := checkMUOConfig(k8sClient, notes)
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
		It("should send service log and escalate", func() {
			r.Resources.OcmClient.(*ocmmock.MockClient).EXPECT().
				CheckIfUserBanned(gomock.Any()).
				Return(ocm.UserBannedError{Code: "terms_and_conditions"})

			result, err := inv.Run(r)
			Expect(err).NotTo(HaveOccurred())
			Expect(hasServiceLogAction(result.Actions)).To(BeTrue())
			Expect(hasEscalateAction(result.Actions)).To(BeTrue())
			Expect(hasSilenceAction(result.Actions)).To(BeFalse())
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

	When("user is not banned and cluster is accessible", func() {
		var (
			ocmServer *httptest.Server
			ocmConn   *sdk.Connection
		)

		BeforeEach(func() {
			ocmServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprint(w, `{"kind":"RegistryCredentialList","items":[],"page":1,"size":0,"total":0}`)
			}))
			var err error
			ocmConn, err = sdk.NewConnectionBuilder().
				URL(ocmServer.URL).
				Tokens("fake-token").
				Insecure(true).
				Build()
			Expect(err).NotTo(HaveOccurred())

			account, _ := amv1.NewAccount().ID("user-1").Email("test@example.com").Build()
			r.Resources.OcmClient.(*ocmmock.MockClient).EXPECT().
				CheckIfUserBanned(gomock.Any()).Return(nil)
			r.Resources.OcmClient.(*ocmmock.MockClient).EXPECT().
				GetCreatorFromCluster(gomock.Any()).Return(account, nil)
			r.Resources.OcmClient.(*ocmmock.MockClient).EXPECT().
				GetConnection().Return(ocmConn)
		})

		AfterEach(func() {
			ocmConn.Close()
			ocmServer.Close()
		})

		It("should escalate when MUO config has wrong ocmBaseUrl", func() {
			pullSecret := createTestPullSecret("test@example.com")
			muoCM := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      muoConfigMapName,
					Namespace: muoNamespace,
				},
				Data: map[string]string{
					muoConfigKey: `configManager:
  source: OCM
  ocmBaseUrl: https://wrong.example.com`,
				},
			}
			r.Resources.K8sClient = fake.NewClientBuilder().
				WithScheme(testScheme()).
				WithObjects(muoCM, pullSecret).
				Build()

			result, err := inv.Run(r)
			Expect(err).NotTo(HaveOccurred())
			Expect(hasEscalateAction(result.Actions)).To(BeTrue())
		})

		It("should escalate with valid pull secret and correct MUO config", func() {
			pullSecret := createTestPullSecret("test@example.com")
			muoCM := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      muoConfigMapName,
					Namespace: muoNamespace,
				},
				Data: map[string]string{
					muoConfigKey: `configManager:
  source: OCM
  ocmBaseUrl: https://api.openshift.com`,
				},
			}
			r.Resources.K8sClient = fake.NewClientBuilder().
				WithScheme(testScheme()).
				WithObjects(muoCM, pullSecret).
				Build()

			result, err := inv.Run(r)
			Expect(err).NotTo(HaveOccurred())
			Expect(hasEscalateAction(result.Actions)).To(BeTrue())
		})

		It("should escalate when pull secret email mismatches", func() {
			pullSecret := createTestPullSecret("wrong@example.com")
			muoCM := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      muoConfigMapName,
					Namespace: muoNamespace,
				},
				Data: map[string]string{
					muoConfigKey: `configManager:
  source: OCM
  ocmBaseUrl: https://api.openshift.com`,
				},
			}
			r.Resources.K8sClient = fake.NewClientBuilder().
				WithScheme(testScheme()).
				WithObjects(muoCM, pullSecret).
				Build()

			result, err := inv.Run(r)
			Expect(err).NotTo(HaveOccurred())
			Expect(hasEscalateAction(result.Actions)).To(BeTrue())
		})

		It("should handle missing pull secret with infrastructure error", func() {
			muoCM := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      muoConfigMapName,
					Namespace: muoNamespace,
				},
				Data: map[string]string{
					muoConfigKey: `configManager:
  source: OCM
  ocmBaseUrl: https://api.openshift.com`,
				},
			}
			r.Resources.K8sClient = fake.NewClientBuilder().
				WithScheme(testScheme()).
				WithObjects(muoCM).
				Build()

			_, err := inv.Run(r)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("Pull secret"))
		})
	})
})

func createTestPullSecret(email string) *corev1.Secret {
	dockerConfig := map[string]interface{}{
		"auths": map[string]interface{}{
			"cloud.openshift.com": map[string]interface{}{
				"auth":  "dGVzdDp0ZXN0",
				"email": email,
			},
		},
	}
	data, _ := json.Marshal(dockerConfig)
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pull-secret",
			Namespace: "openshift-config",
		},
		Type: corev1.SecretTypeDockerConfigJson,
		Data: map[string][]byte{
			".dockerconfigjson": data,
		},
	}
}

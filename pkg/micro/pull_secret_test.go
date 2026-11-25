package micro_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	sdk "github.com/openshift-online/ocm-sdk-go"
	"github.com/openshift/configuration-anomaly-detection/pkg/executor"
	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
	"github.com/openshift/configuration-anomaly-detection/pkg/micro"
	"github.com/openshift/configuration-anomaly-detection/pkg/notewriter"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func pullSecretScheme() *runtime.Scheme {
	s := runtime.NewScheme()
	_ = corev1.AddToScheme(s)
	return s
}

func createPullSecret(email string) *corev1.Secret {
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

func testOCMConnection(serverURL string) *sdk.Connection {
	conn, err := sdk.NewConnectionBuilder().
		URL(serverURL).
		Tokens("fake-token").
		Insecure(true).
		Build()
	Expect(err).NotTo(HaveOccurred())
	return conn
}

var _ = Describe("PullSecret", func() {
	var notes *notewriter.NoteWriter

	BeforeEach(func() {
		logging.InitLogger("fatal", "", "")
		notes = notewriter.New("test", logging.RawLogger)
	})

	When("pull secret is not found", func() {
		It("should return an error", func() {
			k8sClient := fake.NewClientBuilder().WithScheme(pullSecretScheme()).Build()
			_, err := micro.PullSecret(k8sClient, nil, "user-1", "test@example.com", notes)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("failed to get pull secret"))
		})
	})

	When("pull secret email matches OCM email", func() {
		It("should return Done with Escalate and note email match", func() {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprint(w, `{"kind":"RegistryCredentialList","items":[],"page":1,"size":0,"total":0}`)
			}))
			defer server.Close()

			secret := createPullSecret("test@example.com")
			k8sClient := fake.NewClientBuilder().WithScheme(pullSecretScheme()).WithObjects(secret).Build()
			conn := testOCMConnection(server.URL)
			defer conn.Close()

			result, err := micro.PullSecret(k8sClient, conn, "user-1", "test@example.com", notes)
			Expect(err).NotTo(HaveOccurred())
			Expect(result.Done).To(BeTrue())
			Expect(hasActionType(result.Actions, string(executor.ActionTypeEscalateIncident))).To(BeTrue())
			Expect(notes.String()).To(ContainSubstring("email matches"))
		})
	})

	When("pull secret email does not match OCM email", func() {
		It("should return Done with Escalate indicating pull secret issue", func() {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprint(w, `{"kind":"RegistryCredentialList","items":[],"page":1,"size":0,"total":0}`)
			}))
			defer server.Close()

			secret := createPullSecret("wrong@example.com")
			k8sClient := fake.NewClientBuilder().WithScheme(pullSecretScheme()).WithObjects(secret).Build()
			conn := testOCMConnection(server.URL)
			defer conn.Close()

			result, err := micro.PullSecret(k8sClient, conn, "user-1", "test@example.com", notes)
			Expect(err).NotTo(HaveOccurred())
			Expect(result.Done).To(BeTrue())
			Expect(hasActionType(result.Actions, string(executor.ActionTypeEscalateIncident))).To(BeTrue())
			Expect(notes.String()).To(ContainSubstring("does not match"))
		})
	})

	When("pull secret has empty dockerconfigjson", func() {
		It("should return Done with Escalate indicating pull secret issue", func() {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprint(w, `{"kind":"RegistryCredentialList","items":[],"page":1,"size":0,"total":0}`)
			}))
			defer server.Close()

			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "pull-secret",
					Namespace: "openshift-config",
				},
				Type: corev1.SecretTypeDockerConfigJson,
				Data: map[string][]byte{
					".dockerconfigjson": []byte(`{"auths":{}}`),
				},
			}
			k8sClient := fake.NewClientBuilder().WithScheme(pullSecretScheme()).WithObjects(secret).Build()
			conn := testOCMConnection(server.URL)
			defer conn.Close()

			result, err := micro.PullSecret(k8sClient, conn, "user-1", "test@example.com", notes)
			Expect(err).NotTo(HaveOccurred())
			Expect(result.Done).To(BeTrue())
			Expect(hasActionType(result.Actions, string(executor.ActionTypeEscalateIncident))).To(BeTrue())
		})
	})
})

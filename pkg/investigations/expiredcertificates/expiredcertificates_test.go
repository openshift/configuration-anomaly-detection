package expiredcertificates

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	cmv1 "github.com/openshift-online/ocm-sdk-go/clustersmgmt/v1"
	configv1 "github.com/openshift/api/config/v1"
	operatorv1 "github.com/openshift/api/operator/v1"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/investigation"
	"github.com/openshift/configuration-anomaly-detection/pkg/notewriter"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func testScheme() *runtime.Scheme {
	s := runtime.NewScheme()
	_ = corev1.AddToScheme(s)
	_ = configv1.Install(s)
	_ = operatorv1.Install(s)
	return s
}

type clientImpl struct {
	client.Client
}

func newFakeClient(objs ...client.Object) client.Client {
	return fake.NewClientBuilder().
		WithScheme(testScheme()).
		WithObjects(objs...).
		WithIndex(&corev1.Secret{}, "type", func(o client.Object) []string {
			return []string{string(o.(*corev1.Secret).Type)}
		}).
		Build()
}

func newTestCluster(id string) *cmv1.Cluster {
	cluster, _ := cmv1.NewCluster().ID(id).Build()
	return cluster
}

func newTestNotes() *notewriter.NoteWriter {
	return notewriter.New("expiredcertificates", nil)
}

func generateTestCert(cn string, notBefore, notAfter time.Time, dnsNames ...string) []byte {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		Issuer:       pkix.Name{CommonName: "Test CA"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		DNSNames:     dnsNames,
	}
	certBytes, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
}

func validCert(cn string, dnsNames ...string) []byte {
	return generateTestCert(cn, time.Now().Add(-24*time.Hour), time.Now().Add(365*24*time.Hour), dnsNames...)
}

func expiredCert(cn string) []byte {
	return generateTestCert(cn, time.Now().Add(-48*time.Hour), time.Now().Add(-1*time.Hour))
}

func expiringSoonCert(cn string) []byte {
	return generateTestCert(cn, time.Now().Add(-24*time.Hour), time.Now().Add(7*24*time.Hour))
}

func tlsSecret(namespace, name string, certData []byte) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
		Type:       corev1.SecretTypeTLS,
		Data: map[string][]byte{
			"tls.crt": certData,
			"tls.key": []byte("fake-key"),
		},
	}
}

func ingressController(secretName string) *operatorv1.IngressController {
	ic := &operatorv1.IngressController{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "openshift-ingress-operator",
			Name:      "default",
		},
	}
	if secretName != "" {
		ic.Spec.DefaultCertificate = &corev1.LocalObjectReference{Name: secretName}
	}
	return ic
}

// --- parseTLSCert tests ---

func TestParseTLSCert_Valid(t *testing.T) {
	certPEM := validCert("test.example.com", "test.example.com", "*.test.example.com")
	info, err := parseTLSCert(certPEM)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Subject != "test.example.com" {
		t.Errorf("expected subject 'test.example.com', got %q", info.Subject)
	}
	if len(info.SANs) != 2 {
		t.Errorf("expected 2 SANs, got %d", len(info.SANs))
	}
	if info.isExpired() {
		t.Error("expected cert not to be expired")
	}
	if info.isExpiringSoon() {
		t.Error("expected cert not to be expiring soon")
	}
}

func TestParseTLSCert_Expired(t *testing.T) {
	certPEM := expiredCert("expired.example.com")
	info, err := parseTLSCert(certPEM)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !info.isExpired() {
		t.Error("expected cert to be expired")
	}
	if !strings.Contains(info.statusString(), "EXPIRED") {
		t.Errorf("expected EXPIRED in status, got %q", info.statusString())
	}
}

func TestParseTLSCert_ExpiringSoon(t *testing.T) {
	certPEM := expiringSoonCert("expiring.example.com")
	info, err := parseTLSCert(certPEM)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.isExpired() {
		t.Error("expected cert not to be expired yet")
	}
	if !info.isExpiringSoon() {
		t.Error("expected cert to be expiring soon")
	}
	if !strings.Contains(info.statusString(), "EXPIRING SOON") {
		t.Errorf("expected EXPIRING SOON in status, got %q", info.statusString())
	}
}

func TestParseTLSCert_EmptyData(t *testing.T) {
	_, err := parseTLSCert(nil)
	if err == nil {
		t.Error("expected error for empty data")
	}
}

func TestParseTLSCert_InvalidPEM(t *testing.T) {
	_, err := parseTLSCert([]byte("not a pem block"))
	if err == nil {
		t.Error("expected error for invalid PEM")
	}
}

// --- checkCertRelevantOperators tests ---

// --- checkAPIServerCerts tests ---

func TestCheckAPIServerCustomCerts_NoCerts(t *testing.T) {
	apiServer := &configv1.APIServer{
		ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
	}
	k8s := newFakeClient(apiServer)
	notes := newTestNotes()
	inv := &Investigation{}
	inv.checkAPIServerCerts(context.Background(), clientImpl{k8s}, notes)

	output := notes.String()
	if !strings.Contains(output, "no named serving certificates configured") {
		t.Errorf("expected no custom certs message, got:\n%s", output)
	}
}

func TestCheckAPIServerCustomCerts_ValidCert(t *testing.T) {
	secret := tlsSecret("openshift-config", "api-cert", validCert("api.example.com", "api.example.com"))
	apiServer := &configv1.APIServer{
		ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
		Spec: configv1.APIServerSpec{
			ServingCerts: configv1.APIServerServingCerts{
				NamedCertificates: []configv1.APIServerNamedServingCert{
					{
						Names:              []string{"api.example.com"},
						ServingCertificate: configv1.SecretNameReference{Name: "api-cert"},
					},
				},
			},
		},
	}
	k8s := newFakeClient(apiServer, secret)
	notes := newTestNotes()
	inv := &Investigation{}
	inv.checkAPIServerCerts(context.Background(), clientImpl{k8s}, notes)

	output := notes.String()
	if !strings.Contains(output, "api-cert") {
		t.Errorf("expected cert info in output, got:\n%s", output)
	}
	if strings.Contains(output, "issue(s)") {
		t.Errorf("expected no issues for valid cert, got:\n%s", output)
	}
}

func TestCheckAPIServerCustomCerts_ExpiredCert(t *testing.T) {
	secret := tlsSecret("openshift-config", "api-cert", expiredCert("api.example.com"))
	apiServer := &configv1.APIServer{
		ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
		Spec: configv1.APIServerSpec{
			ServingCerts: configv1.APIServerServingCerts{
				NamedCertificates: []configv1.APIServerNamedServingCert{
					{
						Names:              []string{"api.example.com"},
						ServingCertificate: configv1.SecretNameReference{Name: "api-cert"},
					},
				},
			},
		},
	}
	k8s := newFakeClient(apiServer, secret)
	notes := newTestNotes()
	inv := &Investigation{}
	inv.checkAPIServerCerts(context.Background(), clientImpl{k8s}, notes)

	output := notes.String()
	if !strings.Contains(output, "EXPIRED") {
		t.Errorf("expected EXPIRED in output, got:\n%s", output)
	}
	if !strings.Contains(output, "1 issue") {
		t.Errorf("expected issue count, got:\n%s", output)
	}
}

// --- checkIngressCert tests ---

func TestCheckIngressCert_ValidCert(t *testing.T) {
	secret := tlsSecret("openshift-ingress", "ingress-cert", validCert("*.apps.example.com", "*.apps.example.com"))
	k8s := newFakeClient(secret, ingressController("ingress-cert"))
	notes := newTestNotes()
	inv := &Investigation{}
	inv.checkIngressCert(context.Background(), clientImpl{k8s}, notes)

	output := notes.String()
	if !strings.Contains(output, "ingress-cert") {
		t.Errorf("expected secret name in output, got:\n%s", output)
	}
	if !strings.Contains(output, "valid") {
		t.Errorf("expected valid status, got:\n%s", output)
	}
}

func TestCheckIngressCert_ExpiredCert(t *testing.T) {
	secret := tlsSecret("openshift-ingress", "ingress-cert", expiredCert("*.apps.example.com"))
	k8s := newFakeClient(secret, ingressController("ingress-cert"))
	notes := newTestNotes()
	inv := &Investigation{}
	inv.checkIngressCert(context.Background(), clientImpl{k8s}, notes)

	output := notes.String()
	if !strings.Contains(output, "EXPIRED") {
		t.Errorf("expected EXPIRED in output, got:\n%s", output)
	}
}

func TestCheckIngressCert_NoCertConfigured(t *testing.T) {
	k8s := newFakeClient(ingressController(""))
	notes := newTestNotes()
	inv := &Investigation{}
	inv.checkIngressCert(context.Background(), clientImpl{k8s}, notes)

	output := notes.String()
	if !strings.Contains(output, "no defaultCertificate configured") {
		t.Errorf("expected warning about missing cert, got:\n%s", output)
	}
}

// --- checkComponentRouteCerts tests ---

func TestCheckComponentRouteCerts_NoneConfigured(t *testing.T) {
	ingress := &configv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
	}
	k8s := newFakeClient(ingress)
	notes := newTestNotes()
	inv := &Investigation{}
	inv.checkComponentRouteCerts(context.Background(), clientImpl{k8s}, notes)

	output := notes.String()
	if !strings.Contains(output, "no custom component route certificates") {
		t.Errorf("expected no custom certs message, got:\n%s", output)
	}
}

func TestCheckComponentRouteCerts_ValidOAuthCert(t *testing.T) {
	secret := tlsSecret("openshift-config", "oauth-cert", validCert("oauth.example.com", "oauth.example.com"))
	ingress := &configv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
		Spec: configv1.IngressSpec{
			ComponentRoutes: []configv1.ComponentRouteSpec{
				{
					Namespace:                "openshift-authentication",
					Name:                     "oauth-openshift",
					Hostname:                 "oauth.example.com",
					ServingCertKeyPairSecret: configv1.SecretNameReference{Name: "oauth-cert"},
				},
			},
		},
	}
	k8s := newFakeClient(ingress, secret)
	notes := newTestNotes()
	inv := &Investigation{}
	inv.checkComponentRouteCerts(context.Background(), clientImpl{k8s}, notes)

	output := notes.String()
	if !strings.Contains(output, "openshift-authentication/oauth-openshift") {
		t.Errorf("expected component route info, got:\n%s", output)
	}
	if strings.Contains(output, "issue(s)") {
		t.Errorf("expected no issues for valid cert, got:\n%s", output)
	}
}

func TestCheckComponentRouteCerts_ExpiredOAuthCert(t *testing.T) {
	secret := tlsSecret("openshift-config", "oauth-cert", expiredCert("oauth.example.com"))
	ingress := &configv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
		Spec: configv1.IngressSpec{
			ComponentRoutes: []configv1.ComponentRouteSpec{
				{
					Namespace:                "openshift-authentication",
					Name:                     "oauth-openshift",
					Hostname:                 "oauth.example.com",
					ServingCertKeyPairSecret: configv1.SecretNameReference{Name: "oauth-cert"},
				},
			},
		},
	}
	k8s := newFakeClient(ingress, secret)
	notes := newTestNotes()
	inv := &Investigation{}
	inv.checkComponentRouteCerts(context.Background(), clientImpl{k8s}, notes)

	output := notes.String()
	if !strings.Contains(output, "EXPIRED") {
		t.Errorf("expected EXPIRED in output, got:\n%s", output)
	}
	if !strings.Contains(output, "customer-supplied") {
		t.Errorf("expected customer-supplied rotation note, got:\n%s", output)
	}
}

// --- checkCriticalTLSSecrets tests ---

func TestCheckCriticalTLSSecrets_AllValid(t *testing.T) {
	objs := []client.Object{
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "openshift-config"}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "openshift-ingress"}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "openshift-config-managed"}},
		tlsSecret("openshift-config", "cert-1", validCert("cert1.example.com")),
		tlsSecret("openshift-ingress", "router-certs-default", validCert("*.apps.example.com")),
		tlsSecret("openshift-config-managed", "managed-cert", validCert("managed.example.com")),
	}
	k8s := newFakeClient(objs...)
	notes := newTestNotes()
	inv := &Investigation{}
	inv.checkCriticalTLSSecrets(context.Background(), clientImpl{k8s}, notes)

	output := notes.String()
	if strings.Contains(output, "expired or expiring") {
		t.Errorf("expected no expired certs, got:\n%s", output)
	}
}

func TestCheckCriticalTLSSecrets_ExpiredCert(t *testing.T) {
	objs := []client.Object{
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "openshift-config"}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "openshift-ingress"}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "openshift-config-managed"}},
		tlsSecret("openshift-config", "good-cert", validCert("good.example.com")),
		tlsSecret("openshift-config", "bad-cert", expiredCert("bad.example.com")),
	}
	k8s := newFakeClient(objs...)
	notes := newTestNotes()
	inv := &Investigation{}
	inv.checkCriticalTLSSecrets(context.Background(), clientImpl{k8s}, notes)

	output := notes.String()
	if !strings.Contains(output, "1 expired or expiring") {
		t.Errorf("expected 1 expired cert, got:\n%s", output)
	}
	if !strings.Contains(output, "bad-cert") {
		t.Errorf("expected bad-cert in output, got:\n%s", output)
	}
}

func TestCheckCriticalTLSSecrets_IgnoresNonTLSSecrets(t *testing.T) {
	objs := []client.Object{
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "openshift-config"}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "openshift-ingress"}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "openshift-config-managed"}},
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Namespace: "openshift-config", Name: "opaque-secret"},
			Type:       corev1.SecretTypeOpaque,
			Data:       map[string][]byte{"key": []byte("value")},
		},
	}
	k8s := newFakeClient(objs...)
	notes := newTestNotes()
	inv := &Investigation{}
	inv.checkCriticalTLSSecrets(context.Background(), clientImpl{k8s}, notes)

	output := notes.String()
	if strings.Contains(output, "expired or expiring") {
		t.Errorf("expected no cert issues, got:\n%s", output)
	}
}

// --- Run integration tests ---

func TestRun_HealthyCluster(t *testing.T) {
	objs := []client.Object{
		&configv1.APIServer{ObjectMeta: metav1.ObjectMeta{Name: "cluster"}},
		&configv1.Ingress{ObjectMeta: metav1.ObjectMeta{Name: "cluster"}},
		ingressController("ingress-cert"),
		tlsSecret("openshift-ingress", "ingress-cert", validCert("*.apps.example.com")),
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "openshift-config"}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "openshift-ingress"}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "openshift-config-managed"}},
	}

	fakeK8s := newFakeClient(objs...)

	rb := &investigation.ResourceBuilderMock{
		Resources: &investigation.Resources{
			Cluster:   newTestCluster("test-cluster"),
			K8sClient: clientImpl{fakeK8s},
			Notes:     newTestNotes(),
		},
	}

	inv := &Investigation{}
	result, err := inv.Run(rb)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Actions) != 2 {
		t.Fatalf("expected 2 actions (backplane report + PD note), got %d", len(result.Actions))
	}
}

func TestRun_ClusterAccessError(t *testing.T) {
	rb := &investigation.ResourceBuilderMock{
		BuildError: investigation.RestConfigError{
			ClusterID: "test-cluster",
			Err:       fmt.Errorf("cannot create remediations on hive, management or service clusters"),
		},
	}

	inv := &Investigation{}
	result, err := inv.Run(rb)
	if err != nil {
		t.Fatalf("cluster access errors should not return an error, got: %v", err)
	}
	if len(result.Actions) == 0 {
		t.Fatal("expected a note action for cluster access error")
	}
}

func TestRun_BuildError(t *testing.T) {
	rb := &investigation.ResourceBuilderMock{
		BuildError: fmt.Errorf("some unexpected infrastructure error"),
	}

	inv := &Investigation{}
	_, err := inv.Run(rb)
	if err == nil {
		t.Fatal("expected an error for non-cluster-access build failures")
	}
}

func TestRun_HCPCluster(t *testing.T) {
	objs := []client.Object{
		&configv1.APIServer{ObjectMeta: metav1.ObjectMeta{Name: "cluster"}},
		&configv1.Ingress{ObjectMeta: metav1.ObjectMeta{Name: "cluster"}},
		ingressController("ingress-cert"),
		tlsSecret("openshift-ingress", "ingress-cert", validCert("*.apps.example.com")),
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "openshift-config"}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "openshift-ingress"}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "openshift-config-managed"}},
	}

	fakeK8s := newFakeClient(objs...)

	rb := &investigation.ResourceBuilderMock{
		Resources: &investigation.Resources{
			Cluster:   newTestCluster("test-hcp-cluster"),
			K8sClient: clientImpl{fakeK8s},
			IsHCP:     true,
			Notes:     newTestNotes(),
		},
	}

	inv := &Investigation{}
	result, err := inv.Run(rb)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Actions) == 0 {
		t.Fatal("expected actions to be returned")
	}
}

// --- getIngressCertSecretName tests ---

func TestGetIngressCertSecretName_WithCert(t *testing.T) {
	k8s := newFakeClient(ingressController("custom-ingress-cert"))
	notes := newTestNotes()
	inv := &Investigation{}
	name := inv.getIngressCertSecretName(context.Background(), clientImpl{k8s}, notes)

	if name != "custom-ingress-cert" {
		t.Errorf("expected 'custom-ingress-cert', got %q", name)
	}
}

func TestGetIngressCertSecretName_NoCert(t *testing.T) {
	k8s := newFakeClient(ingressController(""))
	notes := newTestNotes()
	inv := &Investigation{}
	name := inv.getIngressCertSecretName(context.Background(), clientImpl{k8s}, notes)

	if name != "" {
		t.Errorf("expected empty string, got %q", name)
	}
}

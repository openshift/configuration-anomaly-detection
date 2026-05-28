package expiredcertificates

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	configv1 "github.com/openshift/api/config/v1"
	operatorv1 "github.com/openshift/api/operator/v1"
	"github.com/openshift/configuration-anomaly-detection/pkg/notewriter"

	"github.com/openshift/configuration-anomaly-detection/pkg/executor"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/investigation"
	k8sclient "github.com/openshift/configuration-anomaly-detection/pkg/k8s"
	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
	"github.com/openshift/configuration-anomaly-detection/pkg/types"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	expiryWarningThreshold = 7 * 24 * time.Hour

	clusterSingletonName       = "cluster"
	nsOpenshiftConfig          = "openshift-config"
	nsOpenshiftIngress         = "openshift-ingress"
	nsOpenshiftConfigManaged   = "openshift-config-managed"
	nsOpenshiftIngressOperator = "openshift-ingress-operator"
	nsOpenShiftServiceCA       = "openshift-service-ca"
	defaultIngressController   = "default"
)

var criticalTLSNamespaces = []string{
	nsOpenshiftConfig,
	nsOpenshiftIngress,
	nsOpenshiftConfigManaged,
	nsOpenShiftServiceCA,
}

type certInfo struct {
	Subject   string
	Issuer    string
	SANs      []string
	NotBefore time.Time
	NotAfter  time.Time
}

func (c *certInfo) isExpired() bool {
	return time.Now().After(c.NotAfter)
}

func (c *certInfo) isExpiringSoon() bool {
	return !c.isExpired() && time.Until(c.NotAfter) < expiryWarningThreshold
}

func (c *certInfo) statusString() string {
	if c.isExpired() {
		return fmt.Sprintf("EXPIRED (expired %dd ago)", int(time.Since(c.NotAfter).Hours()/24))
	}
	if c.isExpiringSoon() {
		return fmt.Sprintf("EXPIRING SOON (expires in %dd)", int(time.Until(c.NotAfter).Hours()/24))
	}
	return fmt.Sprintf("valid (expires in %dd)", int(time.Until(c.NotAfter).Hours()/24))
}

type Investigation struct{}

func (i *Investigation) Run(rb investigation.ResourceBuilder) (investigation.InvestigationResult, error) {
	ctx := context.Background()
	result := investigation.InvestigationResult{}

	r, err := rb.WithCluster().WithK8sClient().WithNotes().Build()
	if err != nil {
		if msg, ok := investigation.ClusterAccessErrorMessage(err); ok {
			logging.Warnf("Cluster access error for expiredcertificates: %v", err)
			result.Actions = []types.Action{
				executor.Note(msg),
			}
			return result, nil
		}
		return result, investigation.WrapInfrastructure(err, "failed to build resources for expiredcertificates")
	}

	notes := r.Notes

	if r.IsHCP {
		notes.AppendSuccess("API Server Certs: skipped (secret access on management cluster is restricted by backplane)")
	} else {
		i.checkAPIServerCerts(ctx, r.K8sClient, notes)
	}
	i.checkIngressCert(ctx, r.K8sClient, notes)
	i.checkComponentRouteCerts(ctx, r.K8sClient, notes)
	i.checkCriticalTLSSecrets(ctx, r.K8sClient, notes)

	result.Actions = executor.NoteAndReportFrom(notes, r.Cluster.ID(), i.Name())
	return result, nil
}

func (i *Investigation) checkAPIServerCerts(ctx context.Context, k8sClient k8sclient.Client, notes *notewriter.NoteWriter) {
	apiServer := &configv1.APIServer{}
	if err := k8sClient.Get(ctx, client.ObjectKey{Name: clusterSingletonName}, apiServer); err != nil {
		notes.AppendWarning("API Server Certs: failed to get APIServer config - %v", err)
		return
	}

	namedCerts := apiServer.Spec.ServingCerts.NamedCertificates
	if len(namedCerts) == 0 {
		notes.AppendSuccess("API Server Certs: no named serving certificates configured")
		return
	}

	var issues []string
	for _, nc := range namedCerts {
		secretName := nc.ServingCertificate.Name
		if secretName == "" {
			continue
		}

		info, err := i.getSecretCertInfo(ctx, k8sClient, nsOpenshiftConfig, secretName)
		if err != nil {
			issues = append(issues, fmt.Sprintf("%s: %v", secretName, err))
			continue
		}

		// If Names is empty, the API server uses the cert's SANs to match requests
		names := nc.Names
		if len(names) == 0 {
			names = info.SANs
		}

		status := info.statusString()
		entry := fmt.Sprintf("%s (names: %s, subject: %s, issuer: %s, expires: %s) - %s",
			secretName, strings.Join(names, ", "), info.Subject, info.Issuer,
			info.NotAfter.Format(time.RFC3339), status)

		if info.isExpired() || info.isExpiringSoon() {
			issues = append(issues, entry)
		} else {
			notes.AppendSuccess("API Server Certs: %s", entry)
		}
	}

	if len(issues) > 0 {
		notes.AppendWarning("API Server Certs: %d issue(s):\n  %s", len(issues), strings.Join(issues, "\n  "))
	}
}

func (i *Investigation) checkIngressCert(ctx context.Context, k8sClient k8sclient.Client, notes *notewriter.NoteWriter) {
	secretName := i.getIngressCertSecretName(ctx, k8sClient, notes)
	if secretName == "" {
		notes.AppendWarning("Ingress Certificate: no defaultCertificate configured on IngressController/default")
		return
	}

	info, err := i.getSecretCertInfo(ctx, k8sClient, nsOpenshiftIngress, secretName)
	if err != nil {
		notes.AppendWarning("Ingress Certificate: failed to read %s in %s - %v", secretName, nsOpenshiftIngress, err)
		return
	}

	entry := fmt.Sprintf("secret: %s, subject: %s, issuer: %s, expires: %s - %s",
		secretName, info.Subject, info.Issuer, info.NotAfter.Format(time.RFC3339), info.statusString())

	if info.isExpired() || info.isExpiringSoon() {
		notes.AppendWarning("Ingress Certificate: %s", entry)
	} else {
		notes.AppendSuccess("Ingress Certificate: %s", entry)
	}
}

func (i *Investigation) getIngressCertSecretName(ctx context.Context, k8sClient k8sclient.Client, notes *notewriter.NoteWriter) string {
	ic := &operatorv1.IngressController{}
	err := k8sClient.Get(ctx, client.ObjectKey{Namespace: nsOpenshiftIngressOperator, Name: defaultIngressController}, ic)
	if err != nil {
		notes.AppendWarning("Ingress Certificate: could not read IngressController/default - %v", err)
		return ""
	}

	if ic.Spec.DefaultCertificate == nil {
		return ""
	}
	return ic.Spec.DefaultCertificate.Name
}

// checkComponentRouteCerts checks certs for OAuth, console, etc. These secrets live in openshift-config
// and would also be caught by checkCriticalTLSSecrets, but this check adds which component route is affected.
func (i *Investigation) checkComponentRouteCerts(ctx context.Context, k8sClient k8sclient.Client, notes *notewriter.NoteWriter) {
	ingress := &configv1.Ingress{}
	if err := k8sClient.Get(ctx, client.ObjectKey{Name: clusterSingletonName}, ingress); err != nil {
		notes.AppendWarning("Component Route Certs: failed to get Ingress config - %v", err)
		return
	}

	if len(ingress.Spec.ComponentRoutes) == 0 {
		notes.AppendSuccess("Component Route Certs: no custom component route certificates configured (OAuth, console use default certs)")
		return
	}

	var issues []string
	var healthy []string

	for _, route := range ingress.Spec.ComponentRoutes {
		secretName := route.ServingCertKeyPairSecret.Name
		if secretName == "" {
			continue
		}

		componentName := fmt.Sprintf("%s/%s", route.Namespace, route.Name)
		info, err := i.getSecretCertInfo(ctx, k8sClient, nsOpenshiftConfig, secretName)
		if err != nil {
			issues = append(issues, fmt.Sprintf("%s (secret: %s): %v", componentName, secretName, err))
			continue
		}

		entry := fmt.Sprintf("%s (secret: %s, subject: %s, issuer: %s, expires: %s) - %s",
			componentName, secretName, info.Subject, info.Issuer,
			info.NotAfter.Format(time.RFC3339), info.statusString())

		if info.isExpired() || info.isExpiringSoon() {
			issues = append(issues, entry)
		} else {
			healthy = append(healthy, entry)
		}
	}

	for _, h := range healthy {
		notes.AppendSuccess("Component Route Certs: %s", h)
	}
	if len(issues) > 0 {
		notes.AppendWarning("Component Route Certs: %d issue(s):\n  %s", len(issues), strings.Join(issues, "\n  "))
		notes.AppendWarning("Component Route Certs: customer-supplied certificates require customer action to rotate")
	}
}

func (i *Investigation) checkCriticalTLSSecrets(ctx context.Context, k8sClient k8sclient.Client, notes *notewriter.NoteWriter) {
	var allIssues []string

	for _, ns := range criticalTLSNamespaces {
		secretList := &corev1.SecretList{}
		if err := k8sClient.List(ctx, secretList, client.InNamespace(ns), client.MatchingFields{"type": string(corev1.SecretTypeTLS)}); err != nil {
			notes.AppendWarning("TLS Secrets (%s): failed to list - %v", ns, err)
			continue
		}

		var nsIssues []string
		tlsCount := len(secretList.Items)

		for idx := range secretList.Items {
			secret := &secretList.Items[idx]
			info, err := parseTLSCert(secret.Data["tls.crt"])
			if err != nil {
				nsIssues = append(nsIssues, fmt.Sprintf("%s/%s: failed to parse - %v", ns, secret.Name, err))
				continue
			}

			if info.isExpired() || info.isExpiringSoon() {
				nsIssues = append(nsIssues, fmt.Sprintf("%s/%s (subject: %s, issuer: %s, expires: %s) - %s",
					ns, secret.Name, info.Subject, info.Issuer,
					info.NotAfter.Format(time.RFC3339), info.statusString()))
			}
		}

		if len(nsIssues) == 0 {
			if tlsCount == 0 {
				notes.AppendSuccess("TLS Secrets (%s): no TLS secrets found", ns)
			} else {
				notes.AppendSuccess("TLS Secrets (%s): all %d TLS secrets are valid", ns, tlsCount)
			}
		} else {
			allIssues = append(allIssues, nsIssues...)
		}
	}

	if len(allIssues) > 0 {
		notes.AppendWarning("TLS Secrets: %d expired or expiring certificate(s):\n  %s", len(allIssues), strings.Join(allIssues, "\n  "))
	}
}

func (i *Investigation) getSecretCertInfo(ctx context.Context, k8sClient k8sclient.Client, namespace, name string) (*certInfo, error) {
	secret := &corev1.Secret{}
	if err := k8sClient.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, secret); err != nil {
		return nil, fmt.Errorf("failed to get secret %s/%s: %w", namespace, name, err)
	}
	return parseTLSCert(secret.Data["tls.crt"])
}

func parseTLSCert(certData []byte) (*certInfo, error) {
	if len(certData) == 0 {
		return nil, fmt.Errorf("empty certificate data")
	}

	block, _ := pem.Decode(certData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return &certInfo{
		Subject:   cert.Subject.CommonName,
		Issuer:    cert.Issuer.CommonName,
		SANs:      cert.DNSNames,
		NotBefore: cert.NotBefore,
		NotAfter:  cert.NotAfter,
	}, nil
}

func (i *Investigation) Name() string {
	return "expiredcertificates"
}

func (i *Investigation) AlertTitle() string {
	return "expiredcertificates"
}

func (i *Investigation) Description() string {
	return "Investigate expired or expiring certificates in the cluster, including custom API server, ingress, and OAuth certificates"
}

func (i *Investigation) IsExperimental() bool {
	return false
}

# expiredcertificates Investigation

Investigates expired or expiring TLS certificates in the cluster. Runs both as a standalone investigation and as a pre-check before other investigations.

On HCP clusters, API server cert checks are skipped since backplane restricts secret access on management clusters.

## Checks

- **API Server Certificates** — reads `APIServer/cluster` and resolves any secrets referenced in `spec.servingCerts.namedCertificates`. Reports expiry, subject, issuer, and SANs.
- **Ingress Certificate** — reads `IngressController/default` in `openshift-ingress-operator` and resolves the secret referenced in `spec.defaultCertificate`. Reports expiry and issuer.
- **Component Route Certificates** — reads `Ingress/cluster` and resolves secrets referenced in `spec.componentRoutes` (covers OAuth, console, and other custom component routes). Reports expiry and issuer per component.
- **Critical Namespace TLS Secrets** — enumerates all `kubernetes.io/tls` secrets in `openshift-config`, `openshift-ingress`, `openshift-config-managed`, and `openshift-service-ca`. Flags any that are expired or expiring within 7 days.

## Estimated time saved

20 minutes per alert. Manual investigation requires backplane access, checking multiple API objects and their referenced secrets across several namespaces, parsing certificate data, and writing up findings.

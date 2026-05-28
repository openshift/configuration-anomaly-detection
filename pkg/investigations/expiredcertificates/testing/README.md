# Testing expiredcertificates Investigation

## Prerequisites

- A running ROSA or HCP cluster
- `cadctl` built locally (`make build-cadctl`)
- Environment variables set (`source test/set_stage_env.sh`)

## Testing with a custom ingress certificate

### Valid certificate

Generate a self-signed cert, create the secret, and patch the IngressController:

```bash
APPS_DOMAIN=$(oc get ingresscontroller/default -n openshift-ingress-operator -o jsonpath='{.status.domain}')

openssl req -x509 -newkey rsa:2048 -nodes -keyout /tmp/ingress-test.key -out /tmp/ingress-test.crt -days 365 -subj "/CN=*.${APPS_DOMAIN}" -addext "subjectAltName=DNS:*.${APPS_DOMAIN}"

oc create secret tls custom-ingress-cert --cert=/tmp/ingress-test.crt --key=/tmp/ingress-test.key -n openshift-ingress

oc patch ingresscontroller/default -n openshift-ingress-operator --type=merge -p '{"spec":{"defaultCertificate":{"name":"custom-ingress-cert"}}}'
```

### Expired certificate

Generate a cert and backdate it so it's already expired, then replace the secret.
Requires OpenSSL 3.0+ for `-not_before`/`-not_after`. The re-sign step strips SANs
from the cert, but the investigation only uses SANs for display — expiry detection
still works correctly.

```bash
APPS_DOMAIN=$(oc get ingresscontroller/default -n openshift-ingress-operator -o jsonpath='{.status.domain}')

openssl req -x509 -newkey rsa:2048 -nodes -keyout /tmp/ingress-expired.key -out /tmp/ingress-expired.crt -days 1 -subj "/CN=*.${APPS_DOMAIN}" -addext "subjectAltName=DNS:*.${APPS_DOMAIN}" -set_serial 1

openssl x509 -in /tmp/ingress-expired.crt -signkey /tmp/ingress-expired.key -not_before 20240101000000Z -not_after 20240102000000Z -out /tmp/ingress-expired.crt

oc delete secret custom-ingress-cert -n openshift-ingress
oc create secret tls custom-ingress-cert --cert=/tmp/ingress-expired.crt --key=/tmp/ingress-expired.key -n openshift-ingress
```

### Cleanup

```bash
oc patch ingresscontroller/default -n openshift-ingress-operator --type=merge -p '{"spec":{"defaultCertificate":null}}'
oc delete secret custom-ingress-cert -n openshift-ingress
```

## Running the investigation

```bash
./bin/cadctl investigate --cluster-id=<CLUSTER_ID> --investigation=expiredcertificates
```

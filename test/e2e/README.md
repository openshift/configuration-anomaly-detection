## Locally running e2e test suite

### Setup

```
go install github.com/onsi/ginkgo/ginkgo@latest
```

Needs a stage cluster to run against

```
export OCM_CLUSTER_ID=...
ocm get /api/clusters_mgmt/v1/clusters/$OCM_CLUSTER_ID/credentials | jq -r .kubeconfig > /tmp/kubeconfig-cad-e2e
$(ocm backplane cloud credentials -oenv $OCM_CLUSTER_ID)
```

Or

```
export $(osdctl account cli -i <yourdevaccount> -p osd-staging-2 -oenv)
```

Run test suite using
You will also need the cad pagerduty routing key for the test environment from vault, at configuration-anomaly-detection/cad-testing as well as set the HTTP_PROXIES so your AWS calls will work:

```
export HTTP_PROXY="squid.corp.redhat.com:3128"
export HTTPS_PROXY="squid.corp.redhat.com:3128"
export NO_PROXY="$(ocm describe cluster $OCM_CLUSTER_ID --json | jq -r '.api.url')"
export VAULT_ADDR="https://vault.devshift.net"
export VAULT_TOKEN="$(vault login -method=oidc -token-only)"
export CAD_PD_ROUTING_KEY=$(vault kv get  -format=json osd-sre/configuration-anomaly-detection/cad-testing | jq -r ".data.data[\"pd_test_routing_key\"]")
make e2e-binary-build
DISABLE_JUNIT_REPORT=true KUBECONFIG=/tmp/kubeconfig-cad-e2e $GOPATH/bin/ginkgo --tags=osde2e -v test/e2e
```

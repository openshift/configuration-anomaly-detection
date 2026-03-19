#!/bin/bash
set -euo pipefail

export VAULT_ADDR="https://vault.devshift.net"
export VAULT_TOKEN="$(vault login -method=oidc -token-only)"
for v in $(vault kv get  -format=json osd-sre/configuration-anomaly-detection/backplane/stg | jq -r ".data.data|to_entries|map(\"\(.key)=\(.value|tostring)\")|.[]"); do export $v; done
for v in $(vault kv get  -format=json osd-sre/configuration-anomaly-detection/ocm/ocm-cad-staging | jq -r ".data.data|to_entries|map(\"\(.key)=\(.value|tostring)\")|.[]"); do export $v; done
for v in $(vault kv get  -format=json osd-sre/configuration-anomaly-detection/pd/stg | jq -r ".data.data|to_entries|map(\"\(.key)=\(.value|tostring)\")|.[]"); do export $v; done
unset VAULT_ADDR VAULT_TOKEN


PROXY_URL="http://squid.corp.redhat.com:3128"

export CAD_EXPERIMENTAL_ENABLED=true
export CAD_OCTOSQL_IMAGE=quay.io/redhat_emp1/octosql-etcd:latest
export BACKPLANE_PROXY=${PROXY_URL}
export AWS_PROXY=${PROXY_URL}

set +euo pipefail

# Example HCP clusters for testing management cluster access (Phase 1):
# - To test Phase 1 MC access: Use any stage HCP cluster ID
# - Get HCP cluster IDs from OCM or existing PagerDuty alerts
# - Example test: ./pkg/investigations/etcddatabasequotalowspace/testing/test_mc_connection.sh <hcp-cluster-id>

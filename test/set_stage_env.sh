#!/bin/bash
set -e

export VAULT_ADDR="https://vault.devshift.net"
export VAULT_TOKEN="$(vault login -method=oidc -token-only)"
for v in $(vault kv get  -format=json osd-sre/configuration-anomaly-detection/aws/osdstaging1 | jq -r ".data.data|to_entries|map(\"\(.key)=\(.value|tostring)\")|.[]"); do export $v; done
for v in $(vault kv get  -format=json osd-sre/configuration-anomaly-detection/backplane/stg | jq -r ".data.data|to_entries|map(\"\(.key)=\(.value|tostring)\")|.[]"); do export $v; done
for v in $(vault kv get  -format=json osd-sre/configuration-anomaly-detection/ocm/ocm-cad-staging | jq -r ".data.data|to_entries|map(\"\(.key)=\(.value|tostring)\")|.[]"); do export $v; done
for v in $(vault kv get  -format=json osd-sre/configuration-anomaly-detection/pd/stg | jq -r ".data.data|to_entries|map(\"\(.key)=\(.value|tostring)\")|.[]"); do export $v; done
unset VAULT_ADDR VAULT_TOKEN

export CAD_EXPERIMENTAL_ENABLED=true
export BACKPLANE_PROXY=http://squid.corp.redhat.com:3128

echo


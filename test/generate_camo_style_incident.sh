#!/usr/bin/env bash
set -e

# Creates a PD test incident with custom_details matching what CAMO produces,
# including firing_json, link, num_firing, etc. This exercises the full
# GetAlertContext → buildInvestigationPayload extraction path in CAD.
#
# Usage: ./test/generate_incident_with_alert_context.sh <clusterid>

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <clusterid>"
    echo "Creates a test incident with CAMO-style custom_details (firing_json, link, etc.)"
    exit 1
fi

cluster_id=$1
alert_name="ConfigureAlertmanagerOperatorOfflineSRE"
alert_title="${alert_name} CRITICAL (1)"
time_current=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# Load testing routing key and test service url from vault
export VAULT_ADDR="https://vault.devshift.net"
export VAULT_TOKEN="$(vault login -method=oidc -token-only)"
for v in $(vault kv get -format=json osd-sre/configuration-anomaly-detection/cad-testing | jq -r ".data.data|to_entries|map(\"\(.key)=\(.value|tostring)\")|.[]"); do export $v; done
unset VAULT_ADDR VAULT_TOKEN
echo

dedup_key=$(uuidgen)

# Build custom_details matching CAMO's Alertmanager template output.
# firing_json is a JSON array — PD will deserialize it into []interface{},
# which is the real wire format CAD must handle.
read -r -d '' custom_details << 'DETAILS' || true
{
  "alert_name": "ConfigureAlertmanagerOperatorOfflineSRE",
  "cluster_id": "CLUSTER_ID_PLACEHOLDER",
  "link": "https://github.com/openshift/ops-sop/tree/master/v4/alerts/ConfigureAlertmanagerOperatorOfflineSRE.md",
  "num_firing": 1,
  "num_resolved": 0,
  "firing_json": [
    {
      "labels": {
        "alertname": "ConfigureAlertmanagerOperatorOfflineSRE",
        "namespace": "openshift-monitoring",
        "openshift_io_alert_source": "platform",
        "prometheus": "openshift-monitoring/k8s",
        "service": "configure-alertmanager-operator",
        "severity": "critical"
      },
      "annotations": {
        "summary": "configure-alertmanager-operator has been offline for more than 15 minutes.",
        "description": "The configure-alertmanager-operator pod in openshift-monitoring is not running.",
        "runbook_url": "https://github.com/openshift/ops-sop/tree/master/v4/alerts/ConfigureAlertmanagerOperatorOfflineSRE.md"
      },
      "startsAt": "TIMESTAMP_PLACEHOLDER",
      "endsAt": "0001-01-01T00:00:00Z",
      "fingerprint": "abc123test",
      "status": "firing"
    }
  ]
}
DETAILS

# Substitute placeholders
custom_details="${custom_details//CLUSTER_ID_PLACEHOLDER/$cluster_id}"
custom_details="${custom_details//TIMESTAMP_PLACEHOLDER/$time_current}"

echo "Creating incident for $alert_name with CAMO-style custom_details"
response=$(curl --silent --request POST \
  --url https://events.pagerduty.com/v2/enqueue \
  --header 'Accept: application/json' \
  --header 'Content-Type: application/json' \
  --data "$(jq -n \
    --arg summary "$alert_title" \
    --arg timestamp "$time_current" \
    --arg routing_key "$pd_test_routing_key" \
    --arg dedup_key "$dedup_key" \
    --argjson custom_details "$custom_details" \
    '{
      payload: {
        summary: $summary,
        timestamp: $timestamp,
        severity: "critical",
        source: "cad-integration-testing",
        custom_details: $custom_details
      },
      routing_key: $routing_key,
      event_action: "trigger",
      dedup_key: $dedup_key
    }')")

if [[ $response != *"Event processed"* ]]; then
  echo "Error: Couldn't create the incident"
  echo "$response"
  exit 1
fi
echo "Incident created"
echo

# PD needs a moment to create the incident
sleep 2

INCIDENT_ID=$(curl --silent --request GET \
  --url "https://api.pagerduty.com/incidents?incident_key=${dedup_key}" \
  --header 'Accept: application/json' \
  --header "Authorization: Token token=${pd_test_token}" \
  --header 'Content-Type: application/json' | jq -r '.incidents[0].id')

echo "Incident ID: $INCIDENT_ID"
echo '{"__pd_metadata":{"incident":{"id":"'$INCIDENT_ID'"}}}' > ./payload
echo "Created ./payload"

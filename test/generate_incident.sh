#!/usr/bin/env bash
set -e

# Define the mapping of alert names to titles
# Add more mappings as needed: for the standard service, we should not need to go by title but by the `alertname` field instead.
declare -A alert_mapping=(
    ["ClusterHasGoneMissing"]="cadtest has gone missing"
    ["ClusterProvisioningDelay"]="ClusterProvisioningDelay -"
    ["ClusterMonitoringErrorBudgetBurnSRE"]="ClusterMonitoringErrorBudgetBurnSRE Critical (1)"
    ["InsightsOperatorDown"]="InsightsOperatorDown"
    ["MachineHealthCheckUnterminatedShortCircuitSRE"]="MachineHealthCheckUnterminatedShortCircuitSRE CRITICAL (1)"
    ["CreateMustGather"]="CreateMustGather"
    ["CannotRetrieveUpdatesSRE"]="CannotRetrieveUpdatesSRE"
    ["UpgradeConfigSyncFailureOver4HrSRE"]="UpgradeConfigSyncFailureOver4HrSRE Critical (1)"
    ["etcdDatabaseQuotaLowSpace"]="etcdDatabaseQuotaLowSpace CRITICAL (1)"
    ["console-errorbudgetburn"]="console-errorbudgetburn Critical (1)"
)

# Function to print help message
print_help() {
    echo "Usage: $0 <alertname> <clusterid>"
    echo -n "Available alert names (comma separated): "
    for alert_name in "${!alert_mapping[@]}"; do
        echo -n "$alert_name, "
    done
    echo
}
# Check if the correct number of arguments is provided
if [ "$#" -ne 2 ]; then
    print_help
    exit 1
fi

alert_name=$1
cluster_id=$2
time_current=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# Check if the alert name is in the mapping
if [ -z "${alert_mapping[$alert_name]}" ]; then
    echo "Error: Unknown alert name '$alert_name'"
    print_help
    exit 1
fi

alert_title="${alert_mapping[$alert_name]}"

# Load testing routing key and test service url from vault
export VAULT_ADDR="https://vault.devshift.net"
export VAULT_TOKEN="$(vault login -method=oidc -token-only)"
for v in $(vault kv get  -format=json osd-sre/configuration-anomaly-detection/cad-testing | jq -r ".data.data|to_entries|map(\"\(.key)=\(.value|tostring)\")|.[]"); do export $v; done
unset VAULT_ADDR VAULT_TOKEN
echo

dedup_key=$(uuidgen)

echo "Creating incident for $alert_name"
response=$(curl --silent --request POST \
  --url https://events.pagerduty.com/v2/enqueue \
  --header 'Accept: application/json' \
  --header 'Content-Type: application/json' \
  --data '{
    "payload": {
      "summary": "'"${alert_title}"'",
      "timestamp": "'"${time_current}"'",
      "severity": "critical",
      "source": "cad-integration-testing",
      "custom_details": {
        "alertname": "'"${alert_name}"'",
        "cluster_id": "'"${cluster_id}"'"
      }
    },
    "routing_key": "'"${pd_test_routing_key}"'",
    "event_action": "trigger",
    "dedup_key": "'"${dedup_key}"'"
  }')

if [[ $response != *"Event processed"* ]]; then
  echo "Error: Couldn't create the incident"
  exit 1
fi
echo

# Pagerduty seems to need a short while to create the incident
# Added this as we intermittently fail to get the incident id otherwise
sleep 2

INCIDENT_ID=$(curl --silent --request GET \
  --url "https://api.pagerduty.com/incidents?incident_key=${dedup_key}" \
  --header 'Accept: application/json' \
  --header "Authorization: Token token=${pd_test_token}" \
  --header 'Content-Type: application/json' | jq -r '.incidents[0].id')
echo $INCIDENT_ID
echo '{"__pd_metadata":{"incident":{"id":"'$INCIDENT_ID'"}}}' > ./payload
echo "Created ./payload"

#!/usr/bin/env bash
set -e

# Define the mapping of alert names to titles
# Add more mappings as needed: for the standard service, we should not need to go by title but by the `alertname` field instead.
declare -A alert_mapping=(
    ["ClusterHasGoneMissing"]="cadtest has gone missing"
    ["ClusterProvisioningDelay"]="ClusterProvisioningDelay -"
    ["ClusterMonitoringErrorBudgetBurnSRE"]="ClusterMonitoringErrorBudgetBurnSRE Critical (1)"
    ["InsightsOperatorDown"]="InsightsOperatorDown"
    ["ClusterOperatorDown"]="ClusterOperatorDown"
    ["MachineHealthCheckUnterminatedShortCircuitSRE"]="MachineHealthCheckUnterminatedShortCircuitSRE CRITICAL (1)"
    ["CreateMustGather"]="CreateMustGather"
    ["CannotRetrieveUpdatesSRE"]="CannotRetrieveUpdatesSRE"
    ["UpgradeConfigSyncFailureOver4HrSRE"]="UpgradeConfigSyncFailureOver4HrSRE Critical (1)"
    ["etcdDatabaseQuotaLowSpace"]="etcdDatabaseQuotaLowSpace CRITICAL (1)"
    ["console-errorbudgetburn"]="console-ErrorBudgetBurn Critical (1)"
    ["OCMAgentResponseFailureServiceLogsSRE"]="OCMAgentResponseFailureServiceLogsSRE CRITICAL (1)"
    ["ExpiredCertificates"]="expiredcertificates"
    ["FallbackTestAlert"]="FallbackTestAlert"
    ["HCPNodepoolUpgradeDelay"]="HCPNodepoolUpgradeDelay"
)

# Function to print help message
print_help() {
    echo "Usage: $0 <alertname> <clusterid> [cluster_id|firing]"
    echo "The optional third argument selects how the cluster ID is carried in the payload:"
    echo "  cluster_id (default) - as a dedicated 'cluster_id' custom detail"
    echo "  firing               - only as a label inside the JSON 'firing' custom detail,"
    echo "                         the format Alertmanager has produced since the COO cutover"
    echo -n "Available alert names (comma separated): "
    for alert_name in "${!alert_mapping[@]}"; do
        echo -n "$alert_name, "
    done
    echo
}
# Check if the correct number of arguments is provided
if [ "$#" -lt 2 ] || [ "$#" -gt 3 ]; then
    print_help
    exit 1
fi

alert_name=$1
cluster_id=$2
id_format=${3:-cluster_id}
time_current=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# Check if the alert name is in the mapping
if [ -z "${alert_mapping[$alert_name]}" ]; then
    echo "Error: Unknown alert name '$alert_name'"
    print_help
    exit 1
fi

alert_title="${alert_mapping[$alert_name]}"

# Build the custom details carrying the cluster ID in the requested format
case "$id_format" in
    cluster_id)
        custom_details=$(jq -n --arg alertname "$alert_name" --arg cluster_id "$cluster_id" \
            '{alertname: $alertname, cluster_id: $cluster_id}')
        ;;
    firing)
        # Alertmanager renders 'firing' as a JSON array of alerts, so the cluster ID is only
        # reachable as a label and no dedicated 'cluster_id' detail is sent.
        firing=$(jq -n -c --arg alertname "$alert_name" --arg cluster_id "$cluster_id" --arg ts "$time_current" \
            '[{status: "firing",
               labels: {alertname: $alertname, cluster_id: $cluster_id, node_pool_id: "cad-integration-testing", service: "srep", severity: "critical"},
               annotations: {message: ("HCP Cluster " + $cluster_id + " nodepool upgrade delay for nodepool id : cad-integration-testing")},
               startsAt: $ts}]')
        custom_details=$(jq -n --arg alertname "$alert_name" --arg firing "$firing" \
            '{alertname: $alertname, firing: $firing, num_firing: "1", num_resolved: "0"}')
        ;;
    *)
        echo "Error: Unknown cluster ID format '$id_format'"
        print_help
        exit 1
        ;;
esac

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
      "custom_details": '"${custom_details}"'
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
echo '{"__pd_metadata":{"incident":{"id":"'$INCIDENT_ID'"}}}' | base64 > ./payload
echo "Created ./payload"

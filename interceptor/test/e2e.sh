#!/bin/bash
set -e

# Text colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

# Load pd token from vault - needed by interceptor
export VAULT_ADDR="https://vault.devshift.net"
export VAULT_TOKEN="$(vault login -method=oidc -token-only)"
for v in $(vault kv get  -format=json osd-sre/configuration-anomaly-detection/cad-testing | jq -r ".data.data|to_entries|map(\"\(.key)=\(.value|tostring)\")|.[]"); do export $v; done	
unset VAULT_ADDR VAULT_TOKEN
echo 

temp_log_file=$(mktemp)

# Function to send an interceptor request and check the response
function test_interceptor {
    # Run the interceptor and print logs to temporary log file
    CAD_PD_TOKEN=$(echo $pd_test_token) CAD_SILENT_POLICY=$(echo $pd_test_silence_policy) ./../bin/interceptor > $temp_log_file  2>&1 &
    
    # Store the PID of the interceptor process
    INTERCEPTOR_PID=$!

    # Wait for 1 second to allow the interceptor to start up
    sleep 5

    local incident_id=$1
    local expected_response=$2

    # Send an interceptor request to localhost:8080
    # See https://pkg.go.dev/github.com/tektoncd/triggers/pkg/apis/triggers/v1alpha1#InterceptorRequest
    CURL_EXITCODE=0
    CURL_OUTPUT=$(curl -s -X POST -H "Content-Type: application/json" \
        -d "{\"body\":\"{\\\"__pd_metadata\\\":{\\\"incident\\\":{\\\"id\\\":\\\"$incident_id\\\"}}}\",\"header\":{\"Content-Type\":[\"application/json\"]},\"extensions\":{},\"interceptor_params\":{},\"context\":null}" \
        http://localhost:8080) || CURL_EXITCODE=$?

    # Check if the curl output matches the expected response
    if [[ "$CURL_OUTPUT" == "$expected_response" ]] && [[ "$CURL_EXITCODE" == "0" ]]; then
        echo -e "${GREEN}Test passed for incident ID $incident_id: Response is as expected.${NC}"

        # Shut down the interceptor
        kill $INTERCEPTOR_PID
    else
        echo -e "${RED}Test failed for incident ID $incident_id: Unexpected response.${NC}"
        echo -e "${RED}Expected: $expected_response${NC}"
        echo -e "${RED}Got: $CURL_OUTPUT${NC}"
        echo -e "${RED}Exit code: $CURL_EXITCODE${NC}"
        echo -e ""
        echo -e "Interceptor logs"
        cat $temp_log_file

        # Shut down the interceptor
        kill $INTERCEPTOR_PID

        return 1
    fi
}

# Expected outputs
# See https://github.com/tektoncd/triggers/blob/v0.27.0/pkg/apis/triggers/v1alpha1/interceptor_types.go#L134
EXPECTED_RESPONSE_CONTINUE='{"continue":true,"status":{}}'
EXPECTED_RESPONSE_STOP='{"continue":false,"status":{}}'

echo "========= TESTS ============="
# Test for a pre-existing alert we handle (ClusterProvisioningDelay)
echo "Test 1: alert with existing handling returns a 'continue: true' response"
test_interceptor "Q12WO44XJLR3H3" "$EXPECTED_RESPONSE_CONTINUE"

# Test for an alert we don't handle (alert called unhandled)
echo "Test 1: unhandled alerts returns a 'continue: false' response"
test_interceptor "Q3722KGCG12ZWD" "$EXPECTED_RESPONSE_STOP"

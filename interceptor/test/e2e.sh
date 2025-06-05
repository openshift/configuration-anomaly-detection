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

    local incident_id=$1
    local expected_response=$2
    local expected_metrics=$3
    local override_signature=$4

    # Run the interceptor and print logs to temporary log file
    export PD_SIGNATURE="test"
    CAD_PD_TOKEN=$(echo $pd_test_token) CAD_SILENT_POLICY=$(echo $pd_test_silence_policy) ./../bin/interceptor > $temp_log_file  2>&1 &
    PAYLOAD_BODY="{\\\"__pd_metadata\\\":{\\\"incident\\\":{\\\"id\\\":\\\"$incident_id\\\"}}}"
    PAYLOAD_BODY_FORMATTED='{"__pd_metadata":{"incident":{"id":"'$incident_id'"}}}'

    # Allow for test 3; override the signature after correct one has already been added to env
    if [[ "$override_signature" != "" ]]; then
      export PD_SIGNATURE=$override_signature
    fi

    SIGN=$(echo -n "$PAYLOAD_BODY_FORMATTED" | openssl dgst -sha256 -hmac $PD_SIGNATURE | sed 's/^.* //')

    # Store the PID of the interceptor process
    INTERCEPTOR_PID=$!

    # Wrap the webhook originating payload (this is the expected format of the payload sent to the interceptor)
    WRAPPED_PAYLOAD="{\"header\":{\"Content-Type\":[\"application/json\"],\"X-PagerDuty-Signature\":[\"v1=$SIGN\"]},\"body\":\"$PAYLOAD_BODY\"}"

    # Wait for 1 second to allow the interceptor to start up
    sleep 5


    # Send an interceptor request to localhost:8080
    # See https://pkg.go.dev/github.com/tektoncd/triggers/pkg/apis/triggers/v1alpha1#InterceptorRequest
    CURL_EXITCODE=0
    CURL_OUTPUT=$(curl -s -X POST -H "X-PagerDuty-Signature:v1=${SIGN}" -H "Content-Type: application/json" \
        -d "$WRAPPED_PAYLOAD" \
        http://localhost:8080) || CURL_EXITCODE=$?

    local return_code=0

    # Check if the curl output differs from the expected response
    if [[ "$CURL_OUTPUT" != "$expected_response" ]] || [[ "$CURL_EXITCODE" != "0" ]]; then
        echo -e "${RED}Test failed for incident ID $incident_id: Unexpected response.${NC}"
        echo -e "${RED}Expected: $expected_response${NC}"
        echo -e "${RED}Got: $CURL_OUTPUT${NC}"
        echo -e "${RED}Exit code: $CURL_EXITCODE${NC}"
        echo -e ""
        echo -e "Interceptor logs"
        cat $temp_log_file
        return_code=1
    else
        curl_metrics_exitcode=0
        curl_metrics_output=$(curl -s http://localhost:8080/metrics | grep '^cad_interceptor_') || curl_metrics_exitcode=$?

        if [[ "$curl_metrics_output" != "$expected_metrics" ]] || [[ "$curl_metrics_exitcode" != "0" ]]; then
            echo -e "${RED}Test failed for incident ID $incident_id: Unexpected metrics.${NC}"
            echo -e "${RED}Expected: $expected_metrics${NC}"
            echo -e "${RED}Got: $curl_metrics_output${NC}"
            echo -e "${RED}Exit code: $curl_metrics_exitcode${NC}"
            echo -e ""
            echo -e "Interceptor logs"
            cat $temp_log_file
            return_code=1
        else
            echo -e "${GREEN}Test passed for incident ID $incident_id: Response and metrics are as expected.${NC}"
        fi
    fi

    # Shut down the interceptor
    kill $INTERCEPTOR_PID

    return $return_code
}

# Expected outputs
# See https://github.com/tektoncd/triggers/blob/v0.27.0/pkg/apis/triggers/v1alpha1/interceptor_types.go#L134
EXPECTED_RESPONSE_CONTINUE='{"continue":true,"status":{}}'
EXPECTED_RESPONSE_STOP='{"continue":false,"status":{}}'
EXPECTED_RESPONSE_SIGNATURE_ERROR='failed to verify signature: invalid webhook signature'

echo "========= TESTS ============="
# Test for a pre-existing alert we handle (ClusterProvisioningDelay)
echo "Test 1: alert with existing handling returns a 'continue: true' response"
test_interceptor "Q12WO44XJLR3H3" "$EXPECTED_RESPONSE_CONTINUE" "cad_interceptor_requests_total 1"

# Test for an alert we don't handle (alert called unhandled)
echo "Test 2: unhandled alerts returns a 'continue: false' response"
test_interceptor "Q3722KGCG12ZWD" "$EXPECTED_RESPONSE_STOP" "cad_interceptor_requests_total 1"

# Test for an alert with invalid signature
echo "Test 3: expected failure due to invalid signature"
PD_SIGNATURE="invalid-signature"
test_interceptor "Q12WO44XJLR3H3" "$EXPECTED_RESPONSE_SIGNATURE_ERROR" 'cad_interceptor_errors_total{error_code="400",reason="failed to verify signature"} 1'$'\n''cad_interceptor_requests_total 1' "invalid-signature"

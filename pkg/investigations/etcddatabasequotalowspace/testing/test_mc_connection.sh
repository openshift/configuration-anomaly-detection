#!/bin/bash
# Test script to validate management cluster access for HCP clusters
# Usage: ./test_mc_connection.sh <hcp-cluster-id>

set -euo pipefail

CLUSTER_ID="${1:-}"
if [ -z "$CLUSTER_ID" ]; then
    echo "Usage: $0 <hcp-cluster-id>"
    echo "Example: $0 2abc123xyz"
    exit 1
fi

echo "Testing management cluster access for HCP cluster: $CLUSTER_ID"
echo "=================================================="
echo ""

# Source environment variables
if [ -f "../../../../test/set_stage_env.sh" ]; then
    source ../../../../test/set_stage_env.sh
else
    echo "ERROR: Could not find test/set_stage_env.sh"
    exit 1
fi

# Build cadctl if needed
if [ ! -f "../../../../bin/cadctl" ]; then
    echo "Building cadctl..."
    cd ../../../../
    make build
    cd -
fi

# Create test payload
echo "Generating test payload..."
cd ../../../../test
./generate_incident.sh "etcdDatabaseQuotaLowSpace" "$CLUSTER_ID" > /tmp/test_payload.json
cd -

echo ""
echo "Payload contents:"
cat /tmp/test_payload.json
echo ""

# Run investigation
echo "Running investigation..."
../../../../bin/cadctl investigate --payload-path /tmp/test_payload.json

echo ""
echo "Test complete! Check output above for:"
echo "  1. Management cluster ID was retrieved"
echo "  2. HCP namespace was resolved"
echo "  3. Remediation RBAC was created on MC"
echo "  4. K8s client successfully connected to MC"
echo "  5. Success message: 'Phase 1 complete - management cluster access established'"

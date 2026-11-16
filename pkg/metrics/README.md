# Metrics

This package provides metric instrumentation.

You can test metrics locally by spawning a aggregation pushgateway container and pushing metrics there.

```bash
# Spawn local gateway
podman run --name cad-pushgw -e PAG_APILISTEN=:9091 -e PAG_LIFECYCLELISTEN=:9092 -p 9091:9091 -p 9092:9092 -d ghcr.io/zapier/prom-aggregation-gateway:v0.7.0
# Verify you can reach the gateway (expect empty answer until you pushed metrics)
curl http://localhost:9091/metrics
# Build the binary with your metics changes. produces ./bin/cadctl
make build-cadctl-release   
# Backplane + OCM + PagerDuty credentials (prompts for a vault OIDC login)
source test/set_stage_env.sh
# Point CAD at the local gateway
export CAD_PROMETHEUS_PUSHGATEWAY="localhost:9091"
# Investigation routing config (maps alert titles -> investigations)
export CAD_INVESTIGATION_CONFIG_PATH="./docs/investigation-config.example.yaml"
# Generate a test incident requires a valid rosa cluster id
./test/generate_incident.sh ClusterOperatorDown <classic-cluster-id>
# Run cad locally 
./bin/cadctl investigate --payload-path payload
# Verify your metrics got pushed and are available on the gateway
curl http://localhost:9091/metrics
```

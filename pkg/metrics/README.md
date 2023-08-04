# Metrics

This package provides metric instrumentation.

You can test metrics locally by spawning a aggregation pushgateway container and pushing metrics there.

```bash
# Spawn local gateway
podman run --name cad-pushgw -e PAG_APILISTEN=:9091 -e PAG_LIFECYCLELISTEN=:9092 -p 9091:9091 -p 9092:9092 -d ghcr.io/zapier/prom-aggregation-gateway:v0.7.0
# Verify you can reach the gateway (expect empty answer until you pushed metrics)
curl http://localhost:9091/metrics 
# Point cad to the gateway
export CAD_PROMETHEUS_PUSHGATEWAY="localhost:9091"
# Run cad locally (it is not relevant for cad to succeed to test the metrics)
./cadctl investigate --payload-path payload.json
# Verify your metrics got pushed and are available on the gateway
curl http://localhost:9091/metrics
```

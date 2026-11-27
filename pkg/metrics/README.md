# Metrics

This package provides metric instrumentation.

CAD pushes to an aggregation gateway, which sums every pushed sample into its running total. `Push()` therefore resets the pushed counters after each successful push, so it can be called multiple times per run (e.g. early, to survive OOM kills, and again at exit) without double-counting.

## Must-gather attempts

- `cad_investigate_must_gather_started_total{source,alert_type,product}` - incremented once per attempt, before collection starts, and pushed immediately.
- `cad_investigate_must_gather_outcome_total{status,reason,source,alert_type,product}` - incremented at most once per attempt; `status` is `success`, `failed` or `skipped`.

`source` is one of `legacy` (dedicated CreateMustGather alert), `sampled` (entry in another alert's chain) or `manual`; `alert_type` is the originating alert config name. Attempts without an outcome (`started - outcomes`) were OOM-killed, timed out, or are still running. Each retry of the investigation after an infrastructure error is a separate attempt.

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

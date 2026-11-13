# Testing infranodesneedresizingsre

## Unit tests

```bash
go test ./pkg/investigations/infranodesneedresizingsre/...
```

## Manual test against a stage cluster

1. Create a stage OSD/ROSA Classic cluster that has an infra machine pool (so `node-role.kubernetes.io/infra`
   nodes exist).
2. Generate the incident by hand:

   ```bash
   ./test/generate_incident.sh InfraNodesNeedResizingSRE <cluster_id>
   source test/set_stage_env.sh
   export CAD_INVESTIGATION_CONFIG_PATH=./pkg/investigations/infranodesneedresizingsre/testing/local-config.yaml
   make build-cadctl-release && ./bin/cadctl investigate --payload-path payload
   ```

3. Expect a PD note that lists each infra node's scheduled CPU/memory requests against its allocatable, the
   top requesting namespaces, and a resize recommendation (or a note to confirm against metrics when requests
   are below 85%). The incident is escalated and nothing is mutated.

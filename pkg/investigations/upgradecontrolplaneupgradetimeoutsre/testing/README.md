# Testing upgradecontrolplaneupgradetimeoutsre

## Unit tests

```bash
go test ./pkg/investigations/upgradecontrolplaneupgradetimeoutsre/...
```

## Manual test against a stage Classic cluster (customer PDB blocking drain)

1. Create a stage OSD/ROSA Classic cluster on an older z-stream and schedule an upgrade.
2. Before the upgrade reaches the machine-config operator, create a blocking PDB on a pod pinned to a master node:

   ```bash
   oc apply -f pkg/investigations/upgradecontrolplaneupgradetimeoutsre/testing/blocking-pdb.yaml
   ```

3. Wait for MUO to fire `UpgradeControlPlaneUpgradeTimeoutSRE`, or generate the incident by hand:

   ```bash
   ./test/generate_incident.sh UpgradeControlPlaneUpgradeTimeoutSRE <cluster_id>
   source test/set_stage_env.sh
   export CAD_INVESTIGATION_CONFIG_PATH=./pkg/investigations/upgradecontrolplaneupgradetimeoutsre/testing/local-config.yaml
   make build-cadctl-release && ./bin/cadctl investigate --payload-path payload
   ```

4. Expect a PD note naming `cad-test/cad-test-blocking-pdb`, a `customer_pdb_preventing_drain_automated`
   service log on the cluster, and the incident silenced.
5. Clean up: `oc delete -f pkg/investigations/upgradecontrolplaneupgradetimeoutsre/testing/blocking-pdb.yaml`.

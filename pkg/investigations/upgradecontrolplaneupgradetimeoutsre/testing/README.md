# Testing upgradecontrolplaneupgradetimeoutsre

## Unit tests

```bash
go test ./pkg/investigations/upgradecontrolplaneupgradetimeoutsre/...
```

## Manual test against a stage Classic cluster (PDB blocking the master rollout)

1. Create a stage OSD/ROSA Classic cluster on an older z-stream and schedule an upgrade.
2. Before the upgrade reaches the machine-config operator, create a blocking PDB on a pod that runs on a master node:

   ```bash
   oc apply -f pkg/investigations/upgradecontrolplaneupgradetimeoutsre/testing/blocking-pdb.yaml
   ```

3. Wait for MUO to fire `UpgradeControlPlaneUpgradeTimeoutSRE`, or generate the incident by hand:

   ```bash
   ./test/generate_incident.sh UpgradeControlPlaneUpgradeTimeoutSRE <cluster_id>
   source test/set_stage_env.sh
   export CAD_INVESTIGATION_CONFIG_PATH=./pkg/investigations/upgradecontrolplaneupgradetimeoutsre/testing/local-config.yaml
   make build-cadctl && ./bin/cadctl investigate --payload-path payload
   ```

4. Expect the PD note to show `Likely blocker: master MachineConfigPool rollout stalled at N/3 nodes`,
   followed by the `pdbblockingnodedrain` note naming `cad-test/cad-test-blocking-pdb`.
5. Clean up: `oc delete -f pkg/investigations/upgradecontrolplaneupgradetimeoutsre/testing/blocking-pdb.yaml`.

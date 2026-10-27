# upgradecontrolplaneupgradetimeoutsre Investigation

Triages the `UpgradeControlPlaneUpgradeTimeoutSRE` alert, raised by the managed-upgrade-operator (MUO)
when the control-plane part of a Classic cluster upgrade runs past its timeout. Tracked in MCS-93.

**Stage: informing.** Read-only. Writes findings to the PagerDuty note and always escalates.
No service logs, silences or cluster changes.

## Investigation Flow

| # | Check | Description |
|---|-------|-------------|
| 0 | **Gates** | Infrastructure (management/service) cluster: escalate as an incident and stop the chain. HCP: escalate, since this is a Classic (MUO) alert. |
| 1 | **ClusterVersion** | Desired version, whether it completed, CVO `Failing` and `Progressing` messages |
| 2 | **ClusterOperators** | Unavailable, degraded, and operators whose `operator` version is not yet the desired version |
| 3 | **MachineConfigPools** | Pools still updating or degraded; the `master` pool is tracked separately because it gates control-plane completion |
| 4 | **Verdict** | A single `Likely blocker:` line, most specific signal first: completed → CVO Failing → unavailable CO → degraded CO → master MCP degraded → master MCP stalled → lagging COs → none found |

## PDB-blocked drains

PDB detection is not duplicated here. The investigation config chains `pdbblockingnodedrain`
after this investigation, so a stalled master rollout caused by a PDB with `disruptionsAllowed=0`
is reported in the same incident. When the verdict is "master MachineConfigPool rollout stalled",
the PDB note that follows names the blocking PDB and whether it is customer- or platform-managed.

```yaml
- alert_title: "UpgradeControlPlaneUpgradeTimeoutSRE"
  name: upgradecontrolplaneupgradetimeoutsre
  investigations:
    - precheck
    - ccam
    - upgradecontrolplaneupgradetimeoutsre
    - pdbblockingnodedrain
```

## Next stages

1. Soak in production; compare the `Likely blocker:` verdict with how on-call resolved each incident.
2. Customer-managed PDB blocking drain: send a service log and silence (CAD "Servicelog & Silence" pattern).
   CAD never edits or deletes a customer PDB. MUO resolves the alert when the upgrade completes.

## Testing

Refer to the [testing README](./testing/README.md) for instructions on testing this investigation.

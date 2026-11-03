# upgradecontrolplaneupgradetimeoutsre Investigation

Handles the `UpgradeControlPlaneUpgradeTimeoutSRE` alert, raised by the managed-upgrade-operator (MUO)
when the control-plane part of a Classic cluster upgrade runs past its timeout. Tracked in MCS-93.

The investigation identifies the cases where CAD can take a concrete action. Everything else is
escalated to on-call without further classification.

**Stage: informing.** No service logs or silences are sent yet. For the actionable cases the PD note
records the action CAD would take (including the full service log text) and the incident is escalated.
Actioning will be enabled in a follow-up once the verdicts have been compared with on-call resolutions.

## Investigation Flow

| # | Case | Action |
|---|------|--------|
| 0 | Management/service cluster | Escalate as an incident, stop the chain |
| 0 | HCP cluster | Escalate (Classic-only alert) |
| 1 | ClusterVersion upgrade already `Completed` (and `observedGeneration == generation`) | Would silence (MUO resolves the alert); escalate |
| 2 | Node cordoned >10m, drain blocked only by customer-managed PDB(s) with `disruptionsAllowed=0` | Would send [`customer_pdb_preventing_drain_automated`](https://github.com/openshift/managed-notifications/blob/master/osd/customer_pdb_preventing_drain_automated.json) service log and silence; escalate |
| – | Platform-managed PDB also blocking, ClusterVersion unreadable, or no PDB blocking | Escalate |

CAD never edits or deletes a PDB. A PDB is customer-managed unless its namespace is `openshift`,
`openshift-*` or `kube-*`.

## Testing

Refer to the [testing README](./testing/README.md) for instructions on testing this investigation.

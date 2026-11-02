# upgradecontrolplaneupgradetimeoutsre Investigation

Handles the `UpgradeControlPlaneUpgradeTimeoutSRE` alert, raised by the managed-upgrade-operator (MUO)
when the control-plane part of a Classic cluster upgrade runs past its timeout. Tracked in MCS-93.

The investigation only acts where CAD can take a concrete action. Everything else is escalated
to on-call without further classification.

## Investigation Flow

| # | Case | Action |
|---|------|--------|
| 0 | Management/service cluster | Escalate as an incident, stop the chain |
| 0 | HCP cluster | Escalate (Classic-only alert) |
| 1 | ClusterVersion upgrade already `Completed` (and `observedGeneration == generation`) | Silence; MUO resolves the alert |
| 2 | Node cordoned >10m, drain blocked only by customer-managed PDB(s) with `disruptionsAllowed=0` | Send [`customer_pdb_preventing_drain_automated`](https://github.com/openshift/managed-notifications/blob/master/osd/customer_pdb_preventing_drain_automated.json) service log, silence |
| – | Platform-managed PDB also blocking, ClusterVersion unreadable, or no PDB blocking | Escalate |

CAD never edits or deletes a PDB. A PDB is customer-managed unless its namespace is `openshift`,
`openshift-*` or `kube-*`.

## Testing

Refer to the [testing README](./testing/README.md) for instructions on testing this investigation.

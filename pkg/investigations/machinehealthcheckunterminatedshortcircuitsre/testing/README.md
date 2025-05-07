# Testing MachineHealthCheckUnterminatedShortCircuitSRE

The `MachineHealthCheckUnterminatedShortCircuitSRE` alert is derived from the `MachineHealthCheck` objects in the `openshift-machine-api` namespace on the cluster. Specifically, it is triggered when the number of nodes matching one of the `.spec.unhealthyConditions` meets or exceeds the `.spec.maxUnhealthy` value for a [duration of time](https://github.com/openshift/managed-cluster-config/blob/3338dd375fa6517d7768eca985c3ca115bbc1484/deploy/sre-prometheus/100-machine-health-check-unterminated-short-circuit.PrometheusRule.yaml#L16).


## Setup

Before applying any test configuration, be sure to [pause hive syncsetting](https://github.com/openshift/ops-sop/blob/master/v4/knowledge_base/pause-syncset.md), to avoid having these changes overwritten mid-test.

Then, apply the following changes to the `MachineHealthCheck` object(s) you wish to check against, in order to make testing a little easier:
- Reducing the `.spec.maxUnhealthy` value will lower the number of nodes that need to be "broken" to short-circuit the machine-api-operator and halt remediation
- Reducing the `.spec.unhealthyConditions` timeouts ensures that the machine-api short-circuits much more quickly after modifying the nodes

A patched version of the default `MachineHealthCheck/srep-worker-healthcheck` object is pre-configured [here](./srep-worker-healthcheck_machinehealthcheck.yaml). Use the following command to apply it to your test cluster:

```sh
ocm backplane elevate "testing CAD" -- replace -f ./srep-worker-healthcheck_machinehealthcheck.yaml
```

## Test Cases

Because it has a fairly broad definition, a `MachineHealthCheckUnterminatedShortCircuitSRE` alert could fire as a result of several different scenarios. A few are outlined below, along with methods to reproduce them.

### nodes `NotReady`, machines `Running`

While the `machine-api-operator` owns and operates the `machine` object-type, it's important to note that its `MachineHealthCheck` objects actually utilize the `.status` of the corresponding **node** to determine if a machine is healthy. This is because a machine's status only reflects whether the VM in the cloud provider is running or not, while the node's status indicates whether the instance is a functional part of the cluster. Therefore, it's possible for a `MachineHealthCheckUnterminatedShortCircuitSRE` alert to fire while all `machines` have a `.status.phase` of `Running`.

The simplest way to reproduce this is to login onto the node and stop the `kubelet.service` on multiple nodes at once.


This can be done via the debug command:

```sh
ocm backplane elevate "testing CAD" -- debug node/$NODE
```

inside the container, run:

```sh
chroot /host
systemctl stop kubelet.service
```

This should automatically remove the debug pod. The node status should flip to `NotReady` shortly thereafter.

### Nodes stuck deleting due to customer workloads not draining

Components like the cluster-autoscaler will try to automatically manage cluster machines via scale-up/scale-down actions based on overall resource utilization. If workloads cannot be drained during a scale-down operation, several nodes can get stuck in a `SchedulingDisabled` phase concurrently, triggering the alert.

To simulate this, create a pod that will have to be drained prior to deleting the machine, alongside an (incorrectly configured) PDB that will prevent it from being drained:

```sh
ocm backplane elevate "testing CAD" -- create -f ./unstoppable_workload.yaml -f ./unstoppable_pdb.yaml
```

Next, simulate a scale-down by patching the machineset the pod is running on. *NOTE*: Just deleting the machine will result in it being replaced, and will not trigger a MachineHealthCheckUnterminatedShortCircuitSRE alert.
```sh
# Get pod's node
NODE=$(oc get po -n default -l app=test-cad -o jsonpath="{.items[].spec.nodeName}")
# Get node's machineset
MACHINESET=$(oc get machines -A -o json | jq --arg NODE "${NODE}" -r '.items[] | select(.status.nodeRef.name == $NODE) | .metadata.labels["machine.openshift.io/cluster-api-machineset"]')
# Scale node's machineset
oc scale machineset/${MACHINESET} --replicas=0 -n openshift-machine-api
```

### Machines in `Failed` phase

Having several machines in a `Failed` state still violates a `MachineHealthCheck`'s `.status.maxUnhealthy`, despite the machines not having any corresponding nodes to check against.

One method to simulate this is to edit the machineset so it contains invalid configurations. The following patch updates a worker machineset to use the `fakeinstancetype` machine-type, for example:

```sh
ocm backplane elevate "testing CAD" -- patch machinesets $MACHINESET -n openshift-machine-api --type merge -p '{"spec": {"template": {"spec": {"providerSpec": {"value": {"instanceType": "fakeinstancetype"}}}}}}'
oc delete machine -n openshift-machine-api -l machine.openshift.io/cluster-api-machineset=$MACHINESET
```

## Additional Resources
The following pages may be useful if the information in this guide is insufficient or has become stale.

- [Machine API Brief](https://github.com/openshift/machine-api-operator/blob/main/docs/user/machine-api-operator-overview.md)
- [Machine API FAQ](https://github.com/openshift/machine-api-operator/blob/main/FAQ.md)
- [MachineHealthCheck documentation](https://docs.redhat.com/en/documentation/openshift_container_platform/4.17/html/machine_management/deploying-machine-health-checks#machine-health-checks-resource_deploying-machine-health-checks)
- [Alert SOP](https://github.com/openshift/ops-sop/blob/master/v4/alerts/MachineHealthCheckUnterminatedShortCircuitSRE.md)

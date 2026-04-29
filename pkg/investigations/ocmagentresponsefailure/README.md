# ocmagentresponsefailure Investigation

Investigates the OCMAgentResponseFailureServiceLogsSRE alert; as part of this investigation, the following checks are run:

1. Network egress verifier
1. OCM banned user validation
1. Pull secret validation

Once the initial informing phase tests are over, a Service Log will be sent out if the cluster owner is banned, with the only exception being if the reason of the ban is due to Export Control Compliance.
In any other case the investigation is escalated to SRE for further analysis, please refer to the [SOP](https://github.com/openshift/ops-sop/blob/master/v4/alerts/OCMAgentResponseFailureServiceLogsSRE.md) for this alert for further information.


## Testing

Refer to the [testing README](./testing/README.md) for instructions on how to test this investigation.


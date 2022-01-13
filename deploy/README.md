# Tekton Pipeline to Trigger CAD Tests

This directory contains the configuration for tekton pipelines that perform the cloud provider/infrastructure configuration checks as part of one Pipeline.

## Installation

Install CAD by running the following commands:

First, apply the subscription to the pipeline operator:

```console
oc apply -f pipeline-operator-subscription.yaml
```

Wait a minute until it becomes available, then apply the rest:

```console
oc apply -f . 
```

**Note**: The pipeline require a persistant storage. The pvc defined here only works for AWS, so for local testing on a crc a pvc with the same name should be created manually.

The CRs are going to be created in the `configuration-anomaly-detection` namespace.

After applying the CRs, a Weblistner will be opened for triggereing pipelines. F.e. http://el-pipeline-event-listener.ci.svc.cluster.local:8080 on CRC.

## Trigger a Pipeline Run

PipelineRuns can be started via the following post command:

```console
curl -X POST --connect-timeout 1 -v --data '{"event": {"id":"12312"}}' http://el-cad-event-listener.ci.svc.cluster.local:8080
```
The Pipeline expects to receive details of a pagerduty event as payload. See the webhook payload that is send by Pagerduty [here](https://developer.pagerduty.com/docs/ZG9jOjExMDI5NTkw-v3-overview#webhook-payload).

Or directly via the following command:

```console
oc create -f pipeline-run.yaml
```

The logs of the last pipeline can be fetched with the command as long as the pods are still available:

```console
tkn pipelinerun logs -f -n configuration-anomaly-detection $(tkn pipelinerun list -n configuration-anomaly-detection -o name --limit 1 | cut -d "/" -f2)
```

The result of the last runs can be seen with:

```console
tkn pipelinerun list -n configuration-anomaly-detection 
```

The documentation for further Tekton commands is available [here](https://docs.openshift.com/container-platform/4.4/cli_reference/tkn_cli/op-tkn-reference.html).

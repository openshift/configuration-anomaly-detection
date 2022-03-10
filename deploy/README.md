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

After applying the CRs, a Weblistner will be opened for triggereing pipelines. F.e. http://el-pipeline-event-listener.configuration-anomaly-detection.svc.cluster.local:8080 on CRC.

## Trigger a Pipeline Run

PipelineRuns can be started via the following post command:

```console
curl -X POST --connect-timeout 1 -v --data '{"event": {"id":"12312"}}' http://el-cad-event-listener.configuration-anomaly-detection.svc.cluster.local:8080
```

or for more details, see [tekton's docs on the matter](https://github.com/tektoncd/triggers/tree/main/examples#invoking-the-triggers-locally)

The Pipeline expects to receive details of a pagerduty event as payload. See the webhook payload that is send by Pagerduty [here](https://developer.pagerduty.com/docs/ZG9jOjExMDI5NTkw-v3-overview#webhook-payload).

Or directly via the following command:

```console
oc create -f pipeline-run.yaml
```

The logs of the last pipeline can be fetched with the command as long as the pods are still available:
the `tkn` tool is pulled from https://github.com/tektoncd/cli

```console
tkn pipelinerun logs -f -n configuration-anomaly-detection $(tkn pipelinerun list -n configuration-anomaly-detection -o name --limit 1 | cut -d "/" -f2)
```

The result of the last runs can be seen with:

```console
tkn pipelinerun list -n configuration-anomaly-detection 
```

The documentation for further Tekton commands is available [here](https://docs.openshift.com/container-platform/4.4/cli_reference/tkn_cli/op-tkn-reference.html).

## What Do We Have Here
### Subscription
[pipeline-operator-subscription.yaml](./pipeline-operator-subscription.yaml) will deploy the tekton pipeline operator on the cluster
### Namesapce
straightforward, but [namespace.yaml](./namespace.yaml) holds all of the next resources
#### PVC
[pvc-cad.yaml](./pvc-cad.yaml) is not really needed, but has saved data the workloads were doing
#### SA
[serviceaccount.yaml](./serviceaccount.yaml) holds the serviceaccount, role and clusterroles that are needed for the CAD resource
#### Trigger
[pipeline-trigger.yaml](./pipeline-trigger.yaml) holds all of the triggers and the base config that starts the pipeline
#### PipeLine
[pipeline.yaml](./pipeline.yaml) the order of the tasks that is triggered by [pipeline-trigger.yaml](./pipeline-trigger.yaml)
#### Tasks
[task-cad-checks.yaml](./task-cad-checks.yaml) is the actual task
##### Tasks Secrets
###### AWS
[task-cad-checks-secrets-aws.yaml](./task-cad-checks-secrets-aws.yaml) this will hold the AWS creds, and we have an env file [aws.env.sample](./aws.env.sample) for populating it

see [../pkg/aws/](../pkg/aws/) for more details

###### PagerDury
[task-cad-checks-secrets-pd.yaml](./task-cad-checks-secrets-pd.yaml) thiis will hold the pd creds
see [../pkg/pagerduty/](../pkg//pagerduty/) for more details

###### OCM
[task-cad-checks-secrets-ocm.yaml](./task-cad-checks-secrets-ocm.yaml) thiis will hold the ocm creds
see [../pkg/ocm/](../pkg/ocm/) for more details

#### PipelineRun
[pipeline-run.yaml](./pipeline-run.yaml) can trigger a pipeline

# Tekton Pipeline to Trigger CAD Tests

This directory contains the configuration for tekton pipelines that perform the cloud provider/infrastructure configuration checks as part of one pipeline.

## What Do We Have Here
### Namespace
[namespace.yaml](./namespace.yaml) holds all the next resources.
#### Trigger
[pipeline-trigger.yaml](./pipeline-trigger.yaml) holds all the triggers and the base config that starts the pipeline.
#### Pipeline
[pipeline.yaml](./pipeline.yaml) the order of the tasks that is triggered by [pipeline-trigger.yaml](./pipeline-trigger.yaml).
#### Tasks
[task-cad-checks.yaml](./task-cad-checks.yaml) is the actual task.

#### Tasks Secrets
##### AWS
[task-cad-checks-secrets-aws.yaml](./task-cad-checks-secrets-aws.yaml) This will hold the AWS creds, and we have an env file [aws.env.sample](./aws.env.sample) for populating it.

**Note**: AWS_DEFAULT_REGION and AWS_SESSION_TOKEN env variables are for development purposes only and are optional.

See [../pkg/aws/](../pkg/aws/) for more details.

##### PagerDuty
[task-cad-checks-secrets-pd.yaml](./task-cad-checks-secrets-pd.yaml) This will hold the pd creds.
See [../pkg/pagerduty/](../pkg/pagerduty/) for more details.

##### OCM
[task-cad-checks-secrets-ocm-client.yaml](./task-cad-checks-secrets-ocm-client.yaml) This will hold the ocm creds.

CAD_OCM_CLIENT_* env vars are in internal kv store. 

See [../pkg/ocm/](../pkg/ocm/) for more details.

#### PipelineRun
[pipeline-run.yaml](./pipeline-run.yaml) can trigger a pipeline.


## Installation

**Note**: some commands may require cluster-admin. To get it consult your docs team.

Install CAD by running the following commands:

1. Add the pipelines operator
    First, apply the subscription to the pipeline operator:

    ```console
    oc apply -f tekton
    ```

2. Configure secrets
   
    See section at the bottom of `Tasks Secrets` to configure.

3. Deploy container image
   
    The repo builds the binary to a container using [../Dockerfile](a container file). build it using:

    ```console
    docker build . -t ${IMAGE_LOCATION}
    ```
    and deploy it to a location you want, then change the image in the [./task-cad-checks.yaml](./task-cad-checks.yaml) using [https://github.com/mikefarah/yq](yq)
    ```console
    OVERRIDE_IMAGE=${IMAGE_LOCATION} yq --inplace '.spec.steps[].image=env(OVERRIDE_IMAGE)' task-cad-checks.yaml
    ```
    **Note**: The test image repository in Quay must be public.

4. Deploy components

    Wait a minute until it becomes available, then apply the rest:

    ```console
    oc apply -f namespace/
    oc apply -f .
    ```

    **Note**: the resource [./pipeline-run.yaml](./pipeline-run.yaml) will not be created using `oc apply && oc delete` as it uses a `.metadata.generateName`, thus is only available to create using `oc create` as seen later on

    The CRs are going to be created in the `configuration-anomaly-detection` namespace.

    After applying the CRs, a Weblistner will be opened for triggering pipelines. F.e. http://el-pipeline-event-listener.configuration-anomaly-detection.svc.cluster.local:8080 on CRC.

5. **Optional:** Exposing as a route.

    If you would like to expose the service via a route, you can run
    ```
    oc create route edge --service=el-cad-event-listener
    ```

## Trigger a Pipeline Run

Pipeline runs can be started via the following post command:

```console
oc exec -it deploy/el-cad-event-listener -- curl -X POST -H 'X-Secret-Token: samplesecret' --connect-timeout 1 -v --data '{"event": {"data": {"id":"12312"}}}' http://el-cad-event-listener.configuration-anomaly-detection.svc.cluster.local:8080
```

For more details, see the [Tekton Documentation](https://github.com/tektoncd/triggers/tree/main/examples#invoking-the-triggers-locally).

The pipeline expects to receive details of a PagerDuty event as payload. See the [webhook payload](https://developer.pagerduty.com/docs/ZG9jOjQ1MTg4ODQ0-overview) that is sent by PagerDuty.


The logs of the last pipeline can be fetched with the following command as long as the pods are still available:

```console
tkn pipelinerun logs -f -n configuration-anomaly-detection $(tkn pipelinerun list -n configuration-anomaly-detection -o name --limit 1 | cut -d "/" -f2)
```
The `tkn` tool is pulled from https://github.com/tektoncd/cli.

The result of the last runs can be seen with:

```console
tkn pipelinerun list -n configuration-anomaly-detection 
```

See the [Tekton documentation](https://docs.openshift.com/container-platform/4.4/cli_reference/tkn_cli/op-tkn-reference.html) for further commands.

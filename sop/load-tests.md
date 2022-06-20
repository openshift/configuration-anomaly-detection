# Load Tests

## Introduction

The following document lists all necessary steps to perform a load test on CAD.
Our CAD deployment located in the `deploy` directory lists a resource quota for PipelineRuns.
This quota has an upper barrier of 100 PipelineRuns, thus it is not possible to schedule more than
100 PipelineRuns. For our load test, we will not surpass this upper limit. Instead, we are going
to concurrently schedule as much PipelineRuns as possible to test our system. 

## Challenges

### PagerDuty

PagerDuty has a rate limit for its REST API of [900 events/min](https://developer.pagerduty.com/docs/ZG9jOjExMDI5NTUz-rate-limiting) across an entire organization.

### OCM

According to the Red Hat customer portal: [OCM has a rate limit between 100 thousand requests and 20 Million requests per day](https://access.redhat.com/documentation/en-us/red_hat_openshift_api_management/1/guide/654cb07c-d1e6-48a9-b0bd-5286421f768c).

### Amazon AWS

CAD uses the [LookupEvent AWS API Endpoint](https://docs.aws.amazon.com/cli/latest/reference/cloudtrail/lookup-events.html). 
We have two queries available every second, If we try to use more tokens we will get throttled.
This means, we have 100 seconds to spawn 100 PipelineRuns.

## Perform the load test

### Requirements

For the load tests we need the following infrastructure:

* One stage cluster that we can use to trigger a DMS alert.
* Access to [https://deadmanssnitch.com/](https://deadmanssnitch.com/)
* Access to the stage cluster, where CAD is running.

### Create the stage cluster and trigger the alert

First, login into OCM stage. Then, create a new test cluster:
`ocm create cluster --region eu-central-1 cad-load-test-1`

Feel free, to change the region if you are located somewhere else.
Now, wait until the cluster changes the state to `ready`. You can observe this via:

`ocm describe cluster cad-load-test-1`

For breaking the cluster, wait until the cluster is in state `ready` and then
delete all machine instances. Wait a little until all instances are in state `terminated`.
If the cluster is broken, login into [deadmanssnitch](https://deadmanssnitch.com/).
Then, search for the cluster and edit its settings. Since June 2022, it is possible
to set a `heartbeat` DMS for a cluster. Select `heartbeat` and change the cycle to 1min.
This small configuration change allows us to trigger an alert within the next minute.


If that is done and DMS has alerted us, login into OCM prod. Then, login into the
stage cluster, where CAD is running on and switch to the stage namespace:

`oc project configuration-anomaly-detection-stage`

In the namespace, there should be a new `cad-check-*` pod. If you cannot find it. List all pods sorted
by creationTimestamp:
`oc get po --sort-by='{.metadata.creationTimestamp}'`

Pick the latest pod and show the first 10 lines of logs (for instance):
`oc logs cad-check-b3108c49-32e3-428c-b03a-69f7c337610e-perform-ca-dhzf6 | head -30`

There should be a JSON payload in the logs. Copy it and save it in `tools/payload.json`. We will use this payload to trigger our 100
PipelineRuns for load testing.

### use the existing payload to create the load test

Get the necessary SECRET_TOKEN for accessing our API from our secret store. Then, set the SECRET_TOKEN via:

`export SECRET_TOKEN="stage secret token"`

Next, call the `tools/cad_load_test.sh` script to execute the load test.

### Cleanup

If everything is done, do not forget to delete the created cluster: `ocm delete cluster "cluster ID"`

# Contribution Guide

CAD provides a terminal cli. It is a collection of functions to investigate potential cloud infrastructure configuration problems.
Currently, CAD reacts to certain alerts that appear in Pagerduty.

## Build

To build the code, you can use the following target:

```shell
make
```

The binary is then available under `./cadctl/cadctl`

## Integrate a new alert

CAD investigations are triggered by pagerduty webhooks. The required investigation type is identified by CAD based on the title and service extracted from the alert payload.
As pagerduty itself does not provide finer granularity for webhooks than service-based, CAD must filter out the alerts it should investigate for itself. For more information, please refer to https://support.pagerduty.com/docs/webhooks.

To integrate a new alert:
- add it to the `isAlertSupported` function in `investigate.go` and write a corresponding CAD service.
- implement functions for the event types (triggered, resolved, escalated...) that require an investigation in a new CAD service.
- add a webhook to both the stage and production version of the service your alert fires on. E.g. https://redhat.pagerduty.com/integrations/webhooks/PRI7A2P

## Testing

To test an investigation, it may be sufficient to run CAD locally. A payload with an incident ID from PD should be used as an argument. However, make sure to trigger the particular incident in a cluster first. That way, when it becomes available in Pagerduty,  a cloud infrastructure for the test investigation to run on exists. Otherwise, the test will be cut off by either CAD not being able to find the PD incident, or CAD being unable to log in to the cloud provider. 

Try to add as many unit tests as possible to the functions you are writing. Have a look into the other investigations about how the dependencies are mocked away. Think of the happy as well as unhappy paths.
Keep the entry arguments for each investigation the same. The argument is a path to a JSON blob which should look similar to the one received by Pagerduty.

```bash
echo '{"event": {"data":{"id": "<pd-incident-id>"}}}' > ./payload
cadctl investigate --payload-path ./payload
```

NOTE: the JSON blob is reduced here to the important part that is analyzed by CAD atm. PD sends a larger JSON object.

CAD is in the end deployed on an OpenShift cluster. Different configurations are set depending on the environment it serves (in, stage, prod). However, when you design the investigation functions, keep in mind how the investigation will be runnable from the local machine, without the need to deploy them first into Kubernetes. This means that required configurations should be injected via env-variables to the CLI and not be fetched by f.e. a config map, and think of the dependent values.

The dependencies so far are:

- AWS
- Pagerduty
- OCM
- Tekton
  
To test Tekton and the deployment configuration, put CAD on OpenShift behind a Tekton event-listener and use curl to trigger pipeline runs by using example payloads.

## Coding Style

Standard software engineering practices apply here:
Please use small functions. Add comments when needed. Think about naming. Export reusable functionality. Use a linter. Try to apply a hexagonal architecture pattern. Add unit tests. Ask peers to review your PRs. Follow the [golang coding style](https://go.dev/doc/effective_go).

## Verify error messages are unique

To grep any part of an error message and see the exact location it was created, use the following command:

```shell
make check-duplicate-error-messages
```

Verify that there are no two entries with the same string.
This also forces us to use `fmt.Errorf` and not a `errors.New`

## Other

additional steps will be added as required

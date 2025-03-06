# CAD Tekton Interceptor

The tekton interceptor is a component plugged between the event listener and the task runs. The interceptor makes sure we don't start a pipeline for every alert we receive. Instead, alerts are filtered based on whether or not they are handled by CAD. Unhandled alerts are directly escalated and no pipeline is started.

## Testing

### E2E

The interceptor has E2E tests starting the HTTP service and checking the HTTP responses. The tests are based on pre-existing PagerDuty alerts.

``` bash

make e2e-interceptor

# To also print the output of the interceptor service:
CAD_E2E_VERBOSE=true make test-interceptor
```

## Development

It is possible to run the interceptor locally in a "minimal" state, where E2E is not used, and only the
crucial-to-run env variables (seen below) are set as placeholders. This is useful for *local* development/debugging.

``` bash
$ make build-interceptor

$ CAD_SILENT_POLICY=test
$ CAD_PD_TOKEN=test
$ PD_SIGNATURE=test

$ ./bin/interceptor
```

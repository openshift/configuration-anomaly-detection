# Package Library

this will hold all of the integrations / code that is to be used by the `cadctl` cli tool

## Specific Integrations

### PagerDuty

see [the subfolder for pagerduty](./pagerduty/)

### AWS

see [the subfolder for aws](./aws/)

## Development

add a new endpoint to cadctl
```
make bin/cobra
cd ./cadctl
../bin/cobra add -a "Red Hat, Inc." -l apache test
```

change the endpoint to include the code that needs to run with all of the required params

build `cadctl` (explained in the root README.md) and run `cadctl test`

# Package Library

This holds all of the integrations / code that is to be used by the `cadctl` cli tool.

## Specific Integrations

### PagerDuty

See [the subfolder for PagerDuty](./pagerduty/)

### AWS

See [the subfolder for AWS](./aws/)

### OCM

See [the subfolder for OCM](./ocm/)

## Development

1. Add a new endpoint to cadctl.
   
    ```
    make bin/cobra
    cd ./cadctl
    ../bin/cobra add -a "Red Hat, Inc." -l apache test
    ```

2. Change the endpoint to include the code that needs to run with all of the required params.

3. Build `cadctl` (explained in the root README.md) and run `cadctl test`.

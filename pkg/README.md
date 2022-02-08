# Package Library

this will hold all of the integrations / code that is to be used by the `cadctl` cli tool

## Specific Integrations

### PagerDuty

Use the `pagerduty.NewWithToken` to create the PagerDuty client, and use the functions it has

#### Manutally test on an incident
to do this, use the https://github.com/martindstone/pagerduty-cli tool.

create the incident:
```shell
INCIDENT_TITLE= # the title you would want the incident to have
SERVICE_ID= # the service under which the incident is created
ESCALATION_POLICY_ID= # the escalation polict under which the incident is created (in case the default escalation policy will ping oncall
pd incident:create --title=${INCIDENT_TITLE} --service_id=${SERVICE_ID} --escalation_policy_id=${ESCALATION_POLICY_ID}
```
the command will output the incident's id

verify the incident has changed after running the `cadctl` change:
```shell
# for CLI data
INCIDENT_ID= # the ID pulled from the previous command
pd rest:get --endpoint /incidents/${INCIDENT_ID}
# for the UI
pd incident:open --ids ${INCIDENT_ID}
```

and from there you can resolve the incident:
```shell
INCIDENT_ID= # the ID pulled from the create command
pd incident:resolve --ids ${INCIDENT_ID}
```

## Development

add a new endpoint to cadctl
```
make bin/cobra
cd ./cadctl
../bin/cobra add -a "Red Hat, Inc." -l apache test
```

change the endpoint to include the code that needs to run with all of the required params

build `cadctl` (explained in the root README.md) and run `cadctl test`

# PagerDuty Package

Use the `pagerduty.NewWithToken` to create the PagerDuty client, and use the functions it has
[embedmd]:# (../../cadctl/cmd/cluster-missing/cluster-missing.go /\/\/ GetPDClient/ /^}$/)
```go
// GetPDClient will retrieve the PagerDuty from the 'pagerduty' package
func GetPDClient() (pagerduty.PagerDuty, error) {
	CAD_PD, ok := os.LookupEnv("CAD_PD")
	if !ok {
		return pagerduty.PagerDuty{}, fmt.Errorf("could not load CAD_PD envvar")
	}

	return pagerduty.NewWithToken(CAD_PD)
}
```


## Manutally test on an incident

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

## Receiving PagerDuty Webhook Messages

### Manual Testing
#### Set up the WebHook
To do this I needed to create a webhook https://support.pagerduty.com/docs/webhooks#add-a-v3-webhook-subscription
and attach it to a schedule (I put all of the options on)

#### Provide an http receiver to push the webhook data to

then I installed https://ngrok.com/ on my machine and started it with 
```
ngrok http 8080
```
which had a http and a https url I could provide

this is what I plumbed to PD

##### Disclaimer
NGROK HAS NOT BEEN APPROVED BY THE SECURITY TEAM, DO NOT USE WITH PRODUCTION DATA
TODO: find a better alternative

#### Connect the http receive to a local port to receive the webhook data
then I used `nc` to retrieve the data:

```
while true; do { echo -e 'HTTP/1.1 200 OK\r\n'; } | nc -l 8080; done
```

which also worked and printed to stdout the data

##### Send a local payload instead of the webhook to test the flow so far works
to test without PD you can send to the URL the following command

```
URL= # the URL from ngrok
curl -XPOST -d'{}' ${URL}
```

#### Prettify the webhook data into oranized yaml data
then to parse the data in a pretty format:

1. I saved all of the json blobs in a yaml file.
2. I added them into a yaml array: 
  - I added a `items:` to the top of the file
  - each json was prepended with `- ` (dash then a space)
3. I used https://github.com/mikefarah/yq to prettify the whole thing

```
FILE= # the file which the webhook json blobs that were transformed by the previous steps were saved
yq -P ${FILE}
```

4. I added a description to each event to make it usable for the next reader

see the titles with 
```
yq e .items[].description  parsed-by-yq-webhook-payloads-from-test-pagerduty.yaml
```

to pull a specific json blob (the first one in this example
```
 yq '.items[0] | del(.description)'  parsed-by-yq-webhook-payloads-from-test-pagerduty.yaml -ojson | jq -c
```

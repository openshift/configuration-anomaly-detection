# PagerDuty Package

Use the `pagerduty.NewWithToken` to create the PagerDuty client, and use the functions it has
[embedmd]:# (../../cadctl/cmd/cluster-missing/cluster-missing.go /\/\/ GetPDClient/ /^}$/)
```go
// GetPDClient will retrieve the PagerDuty from the 'pagerduty' package
func GetPDClient() (pagerduty.Client, error) {
	cadPD, hasCadPD := os.LookupEnv("CAD_PD_TOKEN")
	cadEscalationPolicy, hasCadEscalationPolicy := os.LookupEnv("CAD_ESCALATION_POLICY")
	cadSilentPolicy, hasCadSilentPolicy := os.LookupEnv("CAD_SILENT_POLICY")

	if !hasCadEscalationPolicy || !hasCadSilentPolicy || !hasCadPD {
		return pagerduty.Client{}, fmt.Errorf("one of the required envvars in the list '(CAD_ESCALATION_POLICY CAD_SILENT_POLICY CAP_PD_TOKEN)' is missing")
	}

	client, err := pagerduty.NewWithToken(cadPD, cadEscalationPolicy, cadSilentPolicy)
	if err != nil {
		return pagerduty.Client{}, fmt.Errorf("could not initialze the client: %w", err)
	}

	return client, nil
}
```

## make `cadctl` load PD creds
### if you have `pagerduty-cli` installed
you can run the oneliner:
```
export CAD_PD_TOKEN=$(jq  .subdomains[].legacyToken ~/.config/pagerduty-cli/config.json -r) 
```
and the token will be used

### if you wish to load a token from the UI
use the link to get a token, and bind it to the envvar https://support.pagerduty.com/docs/api-access-keys#generate-a-user-token-rest-api-key

### Create the secret 

* CAD_ESCALATION_POLICY: refers to the escalation policy CAD should use to escalate the incident to
* CAD_PD_EMAIL: refers  to the email for a login via mail/pw credentials
* CAD_PD_PW: refers to the password for a login via mail/pw credentials
* CAD_PD_TOKEN: refers to the generated private access token for token-based authentication
* CAD_PD_USERNAME: refers to the username in case username/pw credentials should be used
* CAD_SILENT_POLICY: refers to the silent policy CAD should use if the incident shall be silent
* PD_SIGNATURE: refers to the PagerDuty webhook signature (HMAC+SHA256)
* X_SECRET_TOKEN: refers to our custom Secret Token for authenticating against our pipeline


## Manually test on an incident

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
and attach it to a schedule (I put all the options on)

#### Provide a http receiver to push the webhook data to

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

#### Prettify the webhook data into organized yaml data
then to parse the data in a pretty format:

1. I saved all the json blobs in a yaml file.
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
 yq '.items[0] | del(.description)'  parsed-by-yq-webhook-payloads-from-test-pagerduty.yaml -ojson | jq > ../../payload.json
```

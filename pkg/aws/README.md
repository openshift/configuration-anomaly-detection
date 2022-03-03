# AWS Package

Use the `aws.New` to create an AWS client, and use the functions it has to interact with AWS resources

an example can be seen in [here](../../cadctl/cmd/cluster-missing/cluster-missing.go)

## Testing

### Pull a CHGM event

```shell
TEAM= # the PD team you are assigned to
pd incident:list --teams "$TEAM" | grep -i missing
```

### extract the external ID

```shell
I= #Incident ID
pd rest:get -e=/incidents/$I/alerts | jq -r '.alerts[].body.details.notes' | yq .cluster_id
```

### login to the owner cluster

using a private script, we can login to the cluster that owns the cluster we want to check (as it holds the aws account)
-- DM privately to get the details

### use `osdctl` to retrieve the creds

```shell
CLUSTER_INTERNAL_ID= # the internal id of the cluster
osdctl account cli -oenv -C ${CLUSTER_INTERNAL_ID} > file.env
```

### export the envvars and use the CLI

In your code, you can import envvars like in this example:

```go
AWS_ACCESS_KEY_ID, hasAWS_ACCESS_KEY_ID := os.LookupEnv("AWS_ACCESS_KEY_ID")
AWS_SECRET_ACCESS_KEY, hasAWS_SECRET_ACCESS_KEY := os.LookupEnv("AWS_SECRET_ACCESS_KEY")
AWS_SESSION_TOKEN, hasAWS_SESSION_TOKEN := os.LookupEnv("AWS_SESSION_TOKEN")
AWS_DEFAULT_REGION, hasAWS_DEFAULT_REGION := os.LookupEnv("AWS_DEFAULT_REGION")
if !hasAWS_ACCESS_KEY_ID || !hasAWS_SECRET_ACCESS_KEY || !hasAWS_SESSION_TOKEN || !hasAWS_DEFAULT_REGION {
    return fmt.Errorf("one of the required envvars in the list '(AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_DEFAULT_REGION)' is missing")
}

a, err := aws.NewClient(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN, AWS_DEFAULT_REGION)
if err != nil {
    return fmt.Errorf("could not start awsClient: %w", err)
}
```

Then execute the command:

```bash
export $(cat file.env)
../../cadctl/cadctl cluster-missing -i just_a_number
```
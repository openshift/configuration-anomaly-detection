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


[embedmd]:# (../../cadctl/cmd/cluster-missing/cluster-missing.go /\/\/ GetAWSClient/ /^}$/)
```go
// GetAWSClient will retrieve the AwsClient from the 'aws' package
func GetAWSClient() (aws.Client, error) {
	awsAccessKeyID, hasAwsAccessKeyID := os.LookupEnv("AWS_ACCESS_KEY_ID")
	awsSecretAccessKey, hasAwsSecretAccessKey := os.LookupEnv("AWS_SECRET_ACCESS_KEY")
	awsSessionToken, hasAwsSessionToken := os.LookupEnv("AWS_SESSION_TOKEN")
	awsDefaultRegion, hasAwsDefaultRegion := os.LookupEnv("AWS_DEFAULT_REGION")
	if !hasAwsAccessKeyID || !hasAwsSecretAccessKey {
		return aws.Client{}, fmt.Errorf("one of the required envvars in the list '(AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY)' is missing")
	}
	if !hasAwsSessionToken {
		fmt.Println("AWS_SESSION_TOKEN not provided, but is not required ")
	}
	if !hasAwsDefaultRegion {
		fmt.Println("setting AWS_DEFAULT_REGION to a default value")
		awsDefaultRegion = "us-east-1"
	}

	return aws.NewClient(awsAccessKeyID, awsSecretAccessKey, awsSessionToken, awsDefaultRegion)
}
```

Then execute the command:

```bash
export $(cat file.env)
../../cadctl/cadctl cluster-missing -i just_a_number
```


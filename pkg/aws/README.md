# AWS Package

Use the `aws.New` to create an AWS client, and use the functions it has to interact with AWS resources

an example can be seen in [here](../../cadctl/cmd/cluster-missing/cluster-missing.go)

## Testing

### Pull a CHGM event
```
TEAM= # the PD team you are assigned to
pd incident:list --teams "$TEAM" | grep -i missing
```

### extract the external ID
```
I= #Incident ID
pd rest:get -e=/incidents/$I/alerts | jq -r '.alerts[].body.details.notes' | yq .cluster_id
```

### login to the owner cluster
using a private script, we can login to the cluster that owns the cluster we want to check (as it holds the aws account)
-- DM privately to get the details

### use `osdctl` to retrieve the creds
```
CLUSTER_INTERNAL_ID= # the internal id of the cluster
osdctl account cli -oenv -C ${CLUSTER_INTERNAL_ID} > file.env
```

### export the envvars and use the CLI

```
export $(cat file.env)
../../cadctl/cadctl cluster-missing -i just_a_number
```

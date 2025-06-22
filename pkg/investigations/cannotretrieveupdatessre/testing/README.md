# Testing CannotRetrieveUpdatesSRE Investigation

### Update the ClusterVersion Channel
- Below script helps to set the test channel to check the clusterversion change.
```sh
#!/bin/bash

# Use test channel for the ClusterVersion
oc patch clusterversion version --type merge -p '{"spec":{"channel":"stable-4.18-test"}}' --as backplane-cluster-admin
sleep 30

# Verify
oc get clusterversion version -o jsonpath='{.spec.channel}' | grep "stable-4.18-test" || { echo "Failed to set the channel"; exit 1; }

# Optional: Revert back to the original change
#oc patch clusterversion version --type merge -p '{"spec":{"channel":"stable-4.18"}}' --as backplane-cluster-admin
```

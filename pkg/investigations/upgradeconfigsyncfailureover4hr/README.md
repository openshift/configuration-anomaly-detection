# upgradeconfigsyncfailureover4hr Investigation

Investigates the UpgradeConfigSyncFailureOver4HrSRE alert by validating cluster pull secrets against OCM account data.

## What it checks

- Uses `pkg/ocm` to check if the cluster owner is banned:
  - if the owner is banned due to export control compliance, the incident is escalated for SREs to follow up ([SOP](https://github.com/openshift/ops-sop/blob/master/v4/alerts/UpgradeConfigSyncFailureOver4HrSRE.md)).
  - if the owner is banned for any other reason, a Service Log is sent out.
- Uses `pkg/pullsecret` to validate:
  1. **Email**: `cloud.openshift.com` email in cluster pull secret matches OCM account email
  2. **Registry credentials**: Per-registry email and token match OCM credentials

## Manual Integration Test

1. Set up a cluster and test incident in PagerDuty

2. Backup the pull secret:
   ```bash
   oc get secret pull-secret -ojson -n openshift-config --as backplane-cluster-admin > backup_pull_secret.json
   ```

3. Extract, decode, and modify the `cloud.openshift.com` email:
   ```bash
   oc get secret pull-secret -n openshift-config --as backplane-cluster-admin \
     -o jsonpath='{.data.\.dockerconfigjson}' | base64 -d > decoded_pullsecret.json
   # Edit decoded_pullsecret.json - change .auths["cloud.openshift.com"].email
   ```

4. Apply the broken pull secret:
   ```bash
   oc patch secret pull-secret -n openshift-config --as backplane-cluster-admin \
     -p "{\"data\":{\".dockerconfigjson\":\"$(cat decoded_pullsecret.json | base64 -w0)\"}}"
   ```

5. Run CAD investigation - expect warning: `Pull secret does not match on cluster and in OCM.`

6. Restore original:
   ```bash
   oc apply -f backup_pull_secret.json --as backplane-cluster-admin
   ```

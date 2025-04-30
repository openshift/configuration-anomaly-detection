# upgradeconfigsyncfailureover4hr Investigation

Package upgradeconfigsyncfailureover4hr contains functionality for the UpgradeConfigSyncFailureOver4HrSRE investigation

### Integration test for Secret Key check
In order to integration test the logic for checking the pull-secret in OCM vs the pull-secret on your cluster you'll need to do a few things.

 1. Set up a cluster and test incident in pagerduty as you would for any CAD investigation test. 
 2. Get the pull secret from the cluster and output it to a file.

     `oc get secret pull-secret -ojson -n openshift-config --as backplane-cluster-admin > backup_pull_secret.json`
 3. Make a copy of the file you just created for easy backup. We'll be making edits later to the copied file.
     `cp backup_pull_secret.json broken_pull_secret.json
 4. Decrypt the .dockerconfigjson entry. The easiest way to do this is to copy the whole part in quotes to your clipboard, echo it in your terminal, and pipe it through `base64 -d` and save the output in a separate file.

     `echo $copied value | base64 -d`
 5. Find the entry for registry.connect.redhat.com and copy the encrypted value for the auth entry. Exclude the quotes again. Repeat the process of de-encrypting this value using `base64 -d`

     `echo $copied_value | base64 -d`
 6. Edit this value in a text editor and change the value after the colon. Leave the preceeding value before the colon as it is. 
 7. Do the encryption process detailed above backwards. First you'll need to encrypt your new pull-secret.dockerconfigjson.registry.connect.redhat.com.auth value (the one we just changed). Simply echo it on your command line and pipe it into base64. Place the whole value in single quotes to avoid any text parsing issues. 

     `echo $changed_value | base64`
 8. Replace that value in the registry.connect.redhat.com.auth value in your decrypted .dockerconfigjson you saved in step 4 then base64 encrypt the whole thing. Take that encrypted value and replace the encrypted .dockerconfigjson value in your broken_pull_secret.json file.
 9. Apply the newly broken pull-secret json file to your cluster using oc apply.
 
     `oc apply -f broken_pull_secret.json --as backplane-cluster-admin`
 10. Re run your test according to the CAD readme. This should return a warning in the logs `⚠️ Pull secret does not match on cluster and in OCM` and apply the same message to the pagerduty incident.
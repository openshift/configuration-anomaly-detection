## Locally running e2e test suite
When updating your operator it's beneficial to add e2e tests for new functionality AND ensure existing functionality is not breaking using e2e tests. 
To do this, following steps are recommended

1. Run "make e2e-binary-build"  to make sure e2e tests build

2. Run "go install github.com/onsi/ginkgo/ginkgo@latest"

3. Create a ROSA Cluster which would be used for E2E testing using the below command:

    rosa create cluster --cluster-name=<cluster-name> --profile <default-aws-profile>

4. Get kubeadmin credentials from your cluster using 

ocm get /api/clusters_mgmt/v1/clusters/(cluster-id)/credentials | jq -r .kubeconfig > /(path-to)/kubeconfig

5. AWS Credentials
These are needed for interacting with the cluster. You can find them in the ~/.aws/credentials file.
Check for the access key and the secret key from the <default-aws-profile> used for creating the cluster.
export AWS_ACCESS_KEY_ID=<your AWS access key ID>
export AWS_SECRET_ACCESS_KEY=<your AWS secret access key>

6. PAGERDUTY ROUTING KEY

This is required for the PagerDuty alerts that are being sent as part of the testing:

https://redhat.pagerduty.com/service-directory/P4BLYHK/integrations

The value can be picked up from the Integration Key in the above link

export CAD_PAGERDUTY_ROUTING_KEY=<url-integration-key-value>

7. OCM_CLUSTER_ID

For running the test cases set up the value of OCM_CLUSTER_ID from the Internal ID of the cluster created in Step #3.

export OCM_CLUSTER_ID=<internal-cluster-id>

7. Run test suite using 
 
DISABLE_JUNIT_REPORT=true KUBECONFIG=/(path-to)/kubeconfig  ./(path-to)/bin/ginkgo  --tags=osde2e -v test/e2e

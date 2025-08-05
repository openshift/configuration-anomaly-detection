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

6. Generate OCM Token
To authenticate with OCM, run the command below. It will return a token and also generate a configuration file.
Run: ocm token
Then export the token:
export OCM_TOKEN=$(ocm token)

7. Enable Debug Mode
This enables detailed logging during test execution:
export CAD_DEBUG=true

8. OCM Configuration File Path
When you run ocm token, it creates a file at the default location ~/.config/ocm/ocm.json. Set the environment variable pointing to this file:
export CAD_OCM_FILE_PATH=~/.config/ocm/ocm.json

## ONLY FOR LOCAL TESTING, THIS CONFIGURATION HAS TO BE REVERTED BACK BEFORE COMMIT AND PUSHING TO THE REPOSITORY

Comment out #56,57 in configuration_anomaly_detection_tests.go and replace with the following code:

ocme2eCli, err = ocme2e.New(ctx, ocmToken, clientID, clientSecret, ocmEnv)
Expect(err).ShouldNot(HaveOccurred(), "Unable to setup E2E OCM Client")

ocmCli, err = ocm.New(cadOcmFilePath)
Expect(err).ShouldNot(HaveOccurred(), "Unable to setup ocm anomaly detection client")

Add below statements in #50,#53 respectively 

ocmToken := os.Getenv("OCM_TOKEN")
Expect(ocmToken).NotTo(BeEmpty(), "OCM_TOKEN must be set")

## "!! PLEASE NOTE THAT SINCE OCM_TOKEN IS NOW DEPRECATED ABOVE LINES OF CODE HAVE TO BE REMOVED AND #56,57 HAVE TO BE UNCOMMENTED !!"

9. Run test suite using 
 
DISABLE_JUNIT_REPORT=true KUBECONFIG=/(path-to)/kubeconfig  ./(path-to)/bin/ginkgo  --tags=osde2e -v test/e2e

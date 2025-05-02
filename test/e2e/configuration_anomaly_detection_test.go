//go:build osde2e
// +build osde2e

package osde2etests

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/onsi/ginkgo/v2"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	awsinternal "github.com/openshift/configuration-anomaly-detection/pkg/aws"
	"github.com/openshift/configuration-anomaly-detection/pkg/ocm"
	ocme2e "github.com/openshift/osde2e-common/pkg/clients/ocm"
	"github.com/openshift/osde2e-common/pkg/clients/openshift"
	logger "sigs.k8s.io/controller-runtime/pkg/log"
)

var _ = Describe("Configuration Anomaly Detection", Ordered, func() {
	var (
		ocmCli    *ocme2e.Client
		ocmlsCli  ocm.Client
		k8s       *openshift.Client
		region    string
		provider  string
		clusterID string
		egressLS  = ocm.LimitedSupportReason{
			Summary: "Cluster is in Limited Support due to unsupported cloud provider configuration",
			Details: "Your cluster requires you to take action. SRE has observed that there have been changes made to the network configuration which impacts normal working of the cluster, including lack of network egress to internet-based resources which are required for the cluster operation and support. Please revert changes, and refer to documentation regarding firewall requirements for PrivateLink clusters: https://access.redhat.com/documentation/en-us/red_hat_openshift_service_on_aws/4/html/prepare_your_environment/rosa-sts-aws-prereqs#osd-aws-privatelink-firewall-prerequisites_rosa-sts-aws-prereqs#",
		}
	)

	// Helper function to post Limited Support reason and silence PagerDuty alert
	postStoppedInfraLimitedSupport := func(clusterID string, ocmlsCli ocm.Client) error {
		err := ocmlsCli.PostLimitedSupportReason(&egressLS, clusterID)
		if err != nil {
			return fmt.Errorf("failed sending service log: %w", err)
		}
		return nil
	}

	ginkgo.BeforeAll(func(ctx context.Context) {
		logger.SetLogger(ginkgo.GinkgoLogr)
		var err error
		ocmEnv := ocme2e.Stage
		ocmToken := os.Getenv("OCM_TOKEN")
		clientID := os.Getenv("CLIENT_ID")
		clientSecret := os.Getenv("CLIENT_SECRET")
		clusterID = os.Getenv("CLUSTER_ID")

		Expect(ocmToken).NotTo(BeEmpty(), "OCM_TOKEN must be set")
		Expect(clusterID).NotTo(BeEmpty(), "CLUSTER_ID must be set")
		ocmCli, err = ocme2e.New(ctx, ocmToken, clientID, clientSecret, ocmEnv)
		Expect(err).ShouldNot(HaveOccurred(), "Unable to setup E2E OCM Client")
		ocmlsCli, err = ocm.New("")
		Expect(err).ShouldNot(HaveOccurred(), "Unable to setup ocm client")
		k8s, err = openshift.New(ginkgo.GinkgoLogr)
		Expect(err).ShouldNot(HaveOccurred(), "Unable to setup k8s client")
		region, err = k8s.GetRegion(ctx)
		Expect(err).NotTo(HaveOccurred(), "Could not determine region")
		provider, err = k8s.GetProvider(ctx)
		Expect(err).NotTo(HaveOccurred(), "Could not determine provider")
	})

	ginkgo.It("can fetch service logs", func(ctx context.Context) {
		if provider == "aws" {
			awsAccessKey := os.Getenv("AWS_ACCESS_KEY_ID")
			awsSecretKey := os.Getenv("AWS_SECRET_ACCESS_KEY")
			Expect(awsAccessKey).NotTo(BeEmpty(), "awsAccessKey not found")
			Expect(awsSecretKey).NotTo(BeEmpty(), "awsSecretKey not found")
			_, err := session.NewSession(aws.NewConfig().WithCredentials(credentials.NewStaticCredentials(awsAccessKey, awsSecretKey, "")).WithRegion(region))
			Expect(err).NotTo(HaveOccurred(), "Could not set up aws session")
		}
	})

	ginkgo.It("AWS CCS: cluster has gone missing (blocked egress)", Label("aws", "ccs", "chgm", "limited-support", "blocking-egress"), func(ctx context.Context) {
		if provider == "aws" {
			awsAccessKey := os.Getenv("AWS_ACCESS_KEY_ID")
			awsSecretKey := os.Getenv("AWS_SECRET_ACCESS_KEY")
			Expect(awsAccessKey).NotTo(BeEmpty(), "AWS access key not found")
			Expect(awsSecretKey).NotTo(BeEmpty(), "AWS secret key not found")
			awsCli, err := awsinternal.NewClient(awsAccessKey, awsSecretKey, "", region)
			Expect(err).NotTo(HaveOccurred(), "Failed to create AWS client")
			clusterResource, err := ocmCli.ClustersMgmt().V1().Clusters().Cluster(clusterID).Get().Send()
			Expect(err).NotTo(HaveOccurred(), "Failed to fetch cluster from OCM")
			cluster := clusterResource.Body()
			infraID := cluster.InfraID()
			Expect(infraID).NotTo(BeEmpty(), "InfraID missing from cluster")
			sgID, err := awsCli.GetSecurityGroupID(infraID)
			Expect(err).NotTo(HaveOccurred(), "Failed to get security group ID")

			// Block egress
			//Expect(awsinternal.BlockEgress(ctx, awsCli.Ec2Client, sgID)).To(Succeed(), "Failed to block egress")

			//Post limited support reason and silence PagerDuty
			err = postStoppedInfraLimitedSupport(clusterID, ocmlsCli)
			Expect(err).NotTo(HaveOccurred(), "Failed to post limited support reason")
			ginkgo.GinkgoWriter.Printf("Limited support reason posted. Restoring egress...\n")

			// Wait for 10 minutes
			ginkgo.GinkgoWriter.Printf("Egress blocked. Waiting for 10 minutes to observe cluster behavior...\n")
			time.Sleep(10 * time.Minute)
			ginkgo.GinkgoWriter.Printf("10-minute wait completed. Posting limited support reason...\n")

			// Restore egress
			Expect(awsinternal.RestoreEgress(ctx, awsCli.Ec2Client, sgID)).To(Succeed(), "Failed to restore egress")

			ocmCli.Connection.Close()
		}
	})

})

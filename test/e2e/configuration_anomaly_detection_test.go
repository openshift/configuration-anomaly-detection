//go:build osde2e
// +build osde2e

package osde2etests

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/onsi/ginkgo/v2"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	awsinternal "github.com/openshift/configuration-anomaly-detection/pkg/aws"
	"github.com/openshift/configuration-anomaly-detection/pkg/ocm"
	ocme2e "github.com/openshift/osde2e-common/pkg/clients/ocm"
	"github.com/openshift/osde2e-common/pkg/clients/openshift"
	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/client-go/util/retry"
	logger "sigs.k8s.io/controller-runtime/pkg/log"
)

var _ = Describe("Configuration Anomaly Detection", Ordered, func() {
	var (
		ocme2eCli *ocme2e.Client
		ocmCli    ocm.Client
		k8s       *openshift.Client
		region    string
		provider  string
		clusterID string
	)

	BeforeAll(func(ctx context.Context) {
		logger.SetLogger(ginkgo.GinkgoLogr)
		var err error
		ocmEnv := ocme2e.Stage
		ocmToken := os.Getenv("OCM_TOKEN")
		clientID := os.Getenv("CLIENT_ID")
		clientSecret := os.Getenv("CLIENT_SECRET")
		clusterID = os.Getenv("CLUSTER_ID")
		cadOcmFilePath := os.Getenv("CAD_OCM_FILE_PATH")

		Expect(ocmToken).NotTo(BeEmpty(), "OCM_TOKEN must be set")
		Expect(clusterID).NotTo(BeEmpty(), "CLUSTER_ID must be set")
		Expect(cadOcmFilePath).NotTo(BeEmpty(), "CAD_OCM_FILE_PATH must be set")

		ocme2eCli, err = ocme2e.New(ctx, ocmToken, clientID, clientSecret, ocmEnv)
		Expect(err).ShouldNot(HaveOccurred(), "Unable to setup E2E OCM Client")

		ocmCli, err = ocm.New(cadOcmFilePath)
		Expect(err).ShouldNot(HaveOccurred(), "Unable to setup ocm anomaly detection client")

		k8s, err = openshift.New(ginkgo.GinkgoLogr)
		Expect(err).ShouldNot(HaveOccurred(), "Unable to setup k8s client")

		region, err = k8s.GetRegion(ctx)
		Expect(err).NotTo(HaveOccurred(), "Could not determine region")

		provider, err = k8s.GetProvider(ctx)
		Expect(err).NotTo(HaveOccurred(), "Could not determine provider")
	})

	AfterAll(func() {
		if ocme2eCli != nil && ocme2eCli.Connection != nil {
			ocme2eCli.Connection.Close()
		}
	})

	It("AWS CCS: cluster has gone missing (blocked egress)", Label("aws", "ccs", "chgm", "limited-support", "blocking-egress"), func(ctx context.Context) {
		if provider == "aws" {
			awsAccessKey := os.Getenv("AWS_ACCESS_KEY_ID")
			awsSecretKey := os.Getenv("AWS_SECRET_ACCESS_KEY")
			Expect(awsAccessKey).NotTo(BeEmpty(), "AWS access key not found")
			Expect(awsSecretKey).NotTo(BeEmpty(), "AWS secret key not found")

			awsCfg, err := config.LoadDefaultConfig(ctx,
				config.WithRegion(region),
				config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
					awsAccessKey,
					awsSecretKey,
					"",
				)),
			)
			Expect(err).NotTo(HaveOccurred(), "Failed to create AWS config")

			ec2Client := ec2.NewFromConfig(awsCfg)
			ec2Wrapper := NewEC2ClientWrapper(ec2Client)

			awsCli, err := awsinternal.NewClient(awsAccessKey, awsSecretKey, "", region)
			Expect(err).NotTo(HaveOccurred(), "Failed to create AWS client")

			clusterResource, err := ocme2eCli.ClustersMgmt().V1().Clusters().Cluster(clusterID).Get().Send()
			Expect(err).NotTo(HaveOccurred(), "Failed to fetch cluster from OCM")

			cluster := clusterResource.Body()
			infraID := cluster.InfraID()
			Expect(infraID).NotTo(BeEmpty(), "InfraID missing from cluster")

			sgID, err := awsCli.GetSecurityGroupID(infraID)
			Expect(err).NotTo(HaveOccurred(), "Failed to get security group ID")

			// Get limited support reasons before blocking egress
			lsResponseBefore, err := GetLimitedSupportReasons(ocme2eCli, clusterID)
			Expect(err).NotTo(HaveOccurred(), "Failed to get limited support reasons")
			lsReasonsBefore := lsResponseBefore.Items().Len()

			ginkgo.GinkgoWriter.Printf("Limited support reasons before blocking egress: %d\n", lsReasonsBefore)
			ginkgo.GinkgoWriter.Printf("Blocking egress for security group: %s\n", sgID)

			// Block egress
			Expect(BlockEgress(ctx, ec2Wrapper, sgID)).To(Succeed(), "Failed to block egress")
			ginkgo.GinkgoWriter.Printf("Egress blocked\n")

			time.Sleep(20 * time.Minute)

			lsResponseAfter, err := GetLimitedSupportReasons(ocme2eCli, clusterID)
			Expect(err).NotTo(HaveOccurred(), "Failed to get limited support reasons")

			// Print the response data
			fmt.Println("Limited Support Response After Blocking Egress:")
			fmt.Printf("Total items: %d\n", lsResponseAfter.Items().Len())

			// Iterate through each item and print details
			items := lsResponseAfter.Items().Slice()
			for i, item := range items {
				fmt.Printf("Reason #%d:\n", i+1)
				fmt.Printf("  - Summary: %s\n", item.Summary())
				fmt.Printf("  - Details: %s\n", item.Details())
			}

			// Restore egress
			Expect(RestoreEgress(ctx, ec2Wrapper, sgID)).To(Succeed(), "Failed to restore egress")
			ginkgo.GinkgoWriter.Printf("Egress restored\n")
		}
	})

	It("AWS CCS: cluster has gone missing (no known misconfiguration)", func(ctx context.Context) {
		if provider == "aws" {
			// Get cluster information from OCM
			response, err := ocme2eCli.ClustersMgmt().V1().Clusters().Cluster(clusterID).Get().Send()
			Expect(err).ToNot(HaveOccurred(), "failed to get cluster from OCM")
			cluster := response.Body()
			Expect(cluster).ToNot(BeNil(), "received nil cluster from OCM")

			// Get service logs
			logs, err := GetServiceLogs(ocmCli, cluster)
			Expect(err).ToNot(HaveOccurred(), "Failed to get service logs")
			logsBefore := logs.Items().Slice()

			lsResponseBefore, err := GetLimitedSupportReasons(ocme2eCli, clusterID)
			Expect(err).NotTo(HaveOccurred(), "Failed to get limited support reasons")
			lsReasonsBefore := lsResponseBefore.Items().Len()

			var zero int32 = 0

			// Step 1: Scale down cluster-monitoring-operator with retry
			fmt.Println("Step 1: Scaling down cluster-monitoring-operator")
			var originalCMOReplicas int32
			err = retry.RetryOnConflict(retry.DefaultRetry, func() error {
				cmo := &appsv1.Deployment{}
				err := k8s.Get(ctx, "cluster-monitoring-operator", "openshift-monitoring", cmo)
				if err != nil {
					return err
				}
				originalCMOReplicas = *cmo.Spec.Replicas
				cmo.Spec.Replicas = &zero
				return k8s.Update(ctx, cmo)
			})
			Expect(err).ToNot(HaveOccurred(), "failed to scale down cluster-monitoring-operator")
			fmt.Printf("Scaled down cluster-monitoring-operator from %d to 0 replicas\n", originalCMOReplicas)

			// Step 2: Scale down prometheus-operator with retry
			fmt.Println("Step 2: Scaling down prometheus-operator")
			var originalPOReplicas int32
			err = retry.RetryOnConflict(retry.DefaultRetry, func() error {
				po := &appsv1.Deployment{}
				err := k8s.Get(ctx, "prometheus-operator", "openshift-monitoring", po)
				if err != nil {
					return err
				}
				originalPOReplicas = *po.Spec.Replicas
				po.Spec.Replicas = &zero
				return k8s.Update(ctx, po)
			})
			Expect(err).ToNot(HaveOccurred(), "failed to scale down prometheus-operator")
			fmt.Printf("Scaled down prometheus-operator from %d to 0 replicas\n", originalPOReplicas)

			// Step 3: Scale down alertmanager-main with retry
			fmt.Println("Step 3: Scaling down alertmanager-main")
			var originalAMReplicas int32
			err = retry.RetryOnConflict(retry.DefaultRetry, func() error {
				sts := &appsv1.StatefulSet{}
				err := k8s.Get(ctx, "alertmanager-main", "openshift-monitoring", sts)
				if err != nil {
					return err
				}
				originalAMReplicas = *sts.Spec.Replicas
				sts.Spec.Replicas = &zero
				return k8s.Update(ctx, sts)
			})
			Expect(err).ToNot(HaveOccurred(), "failed to scale down alertmanager")
			fmt.Printf("Alertmanager scaled down from %d to 0 replicas. Waiting...\n", originalAMReplicas)

			time.Sleep(20 * time.Minute)

			logs, err = GetServiceLogs(ocmCli, cluster)
			Expect(err).ToNot(HaveOccurred(), "Failed to get service logs")
			logsAfter := logs.Items().Slice()

			lsResponseAfter, err := GetLimitedSupportReasons(ocme2eCli, clusterID)
			Expect(err).NotTo(HaveOccurred(), "Failed to get limited support reasons")
			lsReasonsAfter := lsResponseAfter.Items().Len()

			// Step 5: Scale alertmanager-main back up with retry
			fmt.Println("Step 5: Scaling alertmanager-main back up")
			err = retry.RetryOnConflict(retry.DefaultRetry, func() error {
				sts := &appsv1.StatefulSet{}
				err := k8s.Get(ctx, "alertmanager-main", "openshift-monitoring", sts)
				if err != nil {
					return err
				}
				replicas := originalAMReplicas
				sts.Spec.Replicas = &replicas
				return k8s.Update(ctx, sts)
			})
			Expect(err).ToNot(HaveOccurred(), "failed to scale up alertmanager")
			fmt.Printf("Alertmanager scaled back up to %d replicas\n", originalAMReplicas)

			// Step 6: Scale prometheus-operator back up with retry
			fmt.Println("Step 6: Scaling prometheus-operator back up")
			err = retry.RetryOnConflict(retry.DefaultRetry, func() error {
				po := &appsv1.Deployment{}
				err := k8s.Get(ctx, "prometheus-operator", "openshift-monitoring", po)
				if err != nil {
					return err
				}
				replicas := originalPOReplicas
				po.Spec.Replicas = &replicas
				return k8s.Update(ctx, po)
			})
			Expect(err).ToNot(HaveOccurred(), "failed to scale up prometheus-operator")
			fmt.Printf("Prometheus-operator scaled back up to %d replicas\n", originalPOReplicas)

			// Step 7: Scale cluster-monitoring-operator back up with retry
			fmt.Println("Step 7: Scaling cluster-monitoring-operator back up")
			err = retry.RetryOnConflict(retry.DefaultRetry, func() error {
				cmo := &appsv1.Deployment{}
				err := k8s.Get(ctx, "cluster-monitoring-operator", "openshift-monitoring", cmo)
				if err != nil {
					return err
				}
				replicas := originalCMOReplicas
				cmo.Spec.Replicas = &replicas
				return k8s.Update(ctx, cmo)
			})
			Expect(err).ToNot(HaveOccurred(), "failed to scale up cluster-monitoring-operator")
			fmt.Printf("Cluster-monitoring-operator scaled back up to %d replicas\n", originalCMOReplicas)

			Expect(logsAfter).To(HaveLen(len(logsBefore)), "Service logs count changed after scale down/up")
			Expect(lsReasonsAfter).To(Equal(lsReasonsBefore), "Limited support reasons changed after scale down/up")

			fmt.Println("Test completed: All components restored to original replica counts.")
		}
	})
})

//go:build osde2e
// +build osde2e

package osde2etests

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/onsi/ginkgo/v2"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v1beta1 "github.com/openshift/api/machine/v1beta1"
	awsinternal "github.com/openshift/configuration-anomaly-detection/pkg/aws"
	machineutil "github.com/openshift/configuration-anomaly-detection/pkg/investigations/utils/machine"
	"github.com/openshift/configuration-anomaly-detection/pkg/ocm"
	"github.com/openshift/configuration-anomaly-detection/test/e2e/utils"
	ocme2e "github.com/openshift/osde2e-common/pkg/clients/ocm"
	"github.com/openshift/osde2e-common/pkg/clients/openshift"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	pclient "sigs.k8s.io/controller-runtime/pkg/client"
	logger "sigs.k8s.io/controller-runtime/pkg/log"
)

var _ = Describe("Configuration Anomaly Detection", Ordered, func() {
	var (
		ocme2eCli    *ocme2e.Client
		ocmCli       ocm.Client
		k8s          *openshift.Client
		region       string
		provider     string
		clusterID    string
		testPdClient utils.TestPagerDutyClient
	)

	BeforeAll(func(ctx context.Context) {
		logger.SetLogger(ginkgo.GinkgoLogr)
		var err error
		ocmEnv := ocme2e.Stage
		ocmToken := os.Getenv("OCM_TOKEN")
		clientID := os.Getenv("CLIENT_ID")
		clientSecret := os.Getenv("CLIENT_SECRET")
		clusterID = os.Getenv("OCM_CLUSTER_ID")
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

		pdRoutingKey := os.Getenv("CAD_PAGERDUTY_ROUTING_KEY")
		Expect(pdRoutingKey).NotTo(BeEmpty(), "PAGERDUTY_ROUTING_KEY must be set")
		testPdClient = utils.NewClient(pdRoutingKey)
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
			ec2Wrapper := utils.NewEC2ClientWrapper(ec2Client)
			awsCli, err := awsinternal.NewClient(awsCfg)
			Expect(err).NotTo(HaveOccurred(), "Failed to create AWS client")
			clusterResource, err := ocme2eCli.ClustersMgmt().V1().Clusters().Cluster(clusterID).Get().Send()
			Expect(err).NotTo(HaveOccurred(), "Failed to fetch cluster from OCM")
			cluster := clusterResource.Body()
			infraID := cluster.InfraID()
			Expect(infraID).NotTo(BeEmpty(), "InfraID missing from cluster")
			sgID, err := awsCli.GetSecurityGroupID(infraID)
			Expect(err).NotTo(HaveOccurred(), "Failed to get security group ID")
			// Get limited support reasons before blocking egress
			lsResponseBefore, err := utils.GetLimitedSupportReasons(ocme2eCli, clusterID)
			Expect(err).NotTo(HaveOccurred(), "Failed to get limited support reasons")
			lsReasonsBefore := lsResponseBefore.Items().Len()
			ginkgo.GinkgoWriter.Printf("Limited support reasons before blocking egress: %d\n", lsReasonsBefore)
			ginkgo.GinkgoWriter.Printf("Blocking egress for security group: %s\n", sgID)
			// Block egress
			Expect(utils.BlockEgress(ctx, ec2Wrapper, sgID)).To(Succeed(), "Failed to block egress")
			ginkgo.GinkgoWriter.Printf("Egress blocked\n")

			// Clean up: restore egress - moved up to minimize risk of exits before cleanup
			defer func() {
				err := utils.RestoreEgress(ctx, ec2Wrapper, sgID)
				if err != nil {
					ginkgo.GinkgoWriter.Printf("Failed to restore egress: %v\n", err)
				} else {
					ginkgo.GinkgoWriter.Printf("Egress restored\n")
				}
			}()

			_, err = testPdClient.TriggerIncident("ClusterHasGoneMissing", clusterID)
			Expect(err).NotTo(HaveOccurred(), "Failed to trigger silent PagerDuty alert")

			time.Sleep(5 * time.Minute)

			lsResponseAfter, err := utils.GetLimitedSupportReasons(ocme2eCli, clusterID)
			Expect(err).NotTo(HaveOccurred(), "Failed to get limited support reasons")

			// Print the response data
			fmt.Println("Limited Support Response After Blocking Egress:")
			fmt.Printf("Total items: %d\n", lsResponseAfter.Items().Len())

			// Iterate through each item and print details
			items := lsResponseAfter.Items().Slice()
			for i, item := range items {
				fmt.Printf("Reason #%d:\n", i+1)
				fmt.Printf(" - Summary: %s\n", item.Summary())
				fmt.Printf(" - Details: %s\n", item.Details())
			}

			// Verify test result: Expect new limited support reasons to be found after blocking egress
			Expect(lsResponseAfter.Items().Len()).To(BeNumerically(">", lsReasonsBefore),
				"No new limited support reasons found after blocking egress")
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
			logs, err := utils.GetServiceLogs(ocmCli, cluster)
			Expect(err).ToNot(HaveOccurred(), "Failed to get service logs")
			logsBefore := logs.Items().Slice()

			lsResponseBefore, err := utils.GetLimitedSupportReasons(ocme2eCli, clusterID)
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

			_, err = testPdClient.TriggerIncident("ClusterHasGoneMissing", clusterID)
			Expect(err).NotTo(HaveOccurred(), "Failed to trigger silent PagerDuty alert")

			time.Sleep(1 * time.Minute)

			logs, err = utils.GetServiceLogs(ocmCli, cluster)
			Expect(err).ToNot(HaveOccurred(), "Failed to get service logs")
			logsAfter := logs.Items().Slice()

			lsResponseAfter, err := utils.GetLimitedSupportReasons(ocme2eCli, clusterID)
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

	It("AWS CCS: Cluster has gone missing - Infra nodes turned off", Label("aws", "ccs", "infra-nodes", "limited-support"), func(ctx context.Context) {
		if provider != "aws" {
			Skip("This test only runs on AWS clusters")
		}
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

		ginkgo.GinkgoWriter.Println("Getting limited support reasons before infra node shutdown...")
		lsResponseBefore, err := utils.GetLimitedSupportReasons(ocme2eCli, clusterID)
		Expect(err).NotTo(HaveOccurred(), "Failed to get limited support reasons")
		lsReasonsBefore := lsResponseBefore.Items().Len()

		ginkgo.GinkgoWriter.Printf("Limited support reasons before infra node shutdown: %d\n", lsReasonsBefore)

		var nodeList corev1.NodeList
		err = k8s.List(ctx, &nodeList)
		Expect(err).NotTo(HaveOccurred(), "Failed to list nodes")
		var instanceIDs []string
		for _, node := range nodeList.Items {
			if _, isInfra := node.Labels["node-role.kubernetes.io/infra"]; !isInfra {
				continue
			}
			providerID := node.Spec.ProviderID
			Expect(providerID).ToNot(BeEmpty(), "Infra node missing providerID")
			parts := strings.Split(providerID, "/")
			instanceIDs = append(instanceIDs, parts[len(parts)-1])
		}
		Expect(instanceIDs).NotTo(BeEmpty(), "No infrastructure EC2 instance IDs found")
		ginkgo.GinkgoWriter.Printf("Found %d infra node(s) with EC2 instance IDs: %v\n", len(instanceIDs), instanceIDs)

		// Setup deferred EC2 restart to ensure it happens regardless of test outcome
		defer func() {
			ginkgo.GinkgoWriter.Println("Restarting infra nodes regardless of test status...")
			_, err := ec2Client.StartInstances(ctx, &ec2.StartInstancesInput{
				InstanceIds: instanceIDs,
			})
			if err != nil {
				ginkgo.GinkgoWriter.Printf("Failed to start infra EC2 instances: %v\n", err)
				return
			}
			err = ec2.NewInstanceRunningWaiter(ec2Client).Wait(ctx, &ec2.DescribeInstancesInput{
				InstanceIds: instanceIDs,
			}, 10*time.Minute)
			if err != nil {
				ginkgo.GinkgoWriter.Printf("Infra EC2 instances did not start in time: %v\n", err)
				return
			}
			ginkgo.GinkgoWriter.Println("Infra nodes successfully restarted")
		}()

		ginkgo.GinkgoWriter.Println("Stopping infra nodes...")
		_, err = ec2Client.StopInstances(ctx, &ec2.StopInstancesInput{
			InstanceIds: instanceIDs,
		})
		Expect(err).NotTo(HaveOccurred(), "Failed to stop infra EC2 instances")
		err = ec2.NewInstanceStoppedWaiter(ec2Client).Wait(ctx, &ec2.DescribeInstancesInput{
			InstanceIds: instanceIDs,
		}, 6*time.Minute)
		Expect(err).NotTo(HaveOccurred(), "Infra EC2 instances did not stop in time")
		ginkgo.GinkgoWriter.Println("Infra nodes successfully stopped")

		_, err = testPdClient.TriggerIncident("ClusterHasGoneMissing", clusterID)
		Expect(err).NotTo(HaveOccurred(), "Failed to trigger silent PagerDuty alert")

		ginkgo.GinkgoWriter.Println("Sleeping for 2 minutes before checking limited support reasons...")
		time.Sleep(2 * time.Minute)

		lsResponseAfter, err := utils.GetLimitedSupportReasons(ocme2eCli, clusterID)
		Expect(err).NotTo(HaveOccurred(), "Failed to get limited support reasons")

		// Print the response data
		fmt.Println("Limited Support Response After Stopping Infra Nodes:")
		fmt.Printf("Total items: %d\n", lsResponseAfter.Items().Len())

		// Iterate through each item and print details
		items := lsResponseAfter.Items().Slice()
		for i, item := range items {
			fmt.Printf("Reason #%d:\n", i+1)
			fmt.Printf("  - Summary: %s\n", item.Summary())
			fmt.Printf("  - Details: %s\n", item.Details())
		}

		Expect(lsResponseAfter.Items().Len()).To(BeNumerically(">", lsReasonsBefore),
			"Expected more limited support reasons after infrastructure node shutdown")
	})

	It("AWS CCS: MachineHealthCheckUnterminatedShortCircuitSRE - node is NotReady", func(ctx context.Context) {
		if provider == "aws" {
			kubeConfigPath := os.Getenv("KUBECONFIG")
			kubeClient, err := utils.CreateClientFromKubeConfig(kubeConfigPath)
			if err != nil {
				log.Fatalf("Error creating Kubernetes client: %v", err)
			}

			// Fetch machine list in the 'openshift-machine-api' namespace
			machineList := &v1beta1.MachineList{}
			err = kubeClient.List(context.TODO(), machineList, &pclient.ListOptions{
				Namespace: machineutil.MachineNamespace,
			})
			Expect(err).ToNot(HaveOccurred(), "Failed to list machines")

			// Get nodes for the first machine
			machine := &machineList.Items[0]
			node, err := machineutil.GetNodeForMachine(ctx, kubeClient, *machine)
			Expect(err).NotTo(HaveOccurred(), "Failed to get Node for Machine")
			Expect(node).NotTo(BeNil(), "Node for Machine is nil")

			nodeName := node.Name
			originalNodeCount := len(machineList.Items)
			ginkgo.GinkgoWriter.Printf("Original node count: %d\n", originalNodeCount)

			// Simulate 'NotReady' condition for the node
			ginkgo.GinkgoWriter.Printf("Step 1: Changing status to NotReady for Node:: %s\n", nodeName)
			retryErr := retry.RetryOnConflict(retry.DefaultRetry, func() error {
				key := types.NamespacedName{Name: nodeName}
				n := &corev1.Node{}
				if err := kubeClient.Get(ctx, key, n); err != nil {
					return err
				}

				updated := false
				for i, cond := range n.Status.Conditions {
					if cond.Type == corev1.NodeReady {
						n.Status.Conditions[i].Status = corev1.ConditionFalse
						updated = true
						break
					}
				}
				if !updated {
					n.Status.Conditions = append(n.Status.Conditions, corev1.NodeCondition{
						Type:               corev1.NodeReady,
						Status:             corev1.ConditionFalse,
						LastHeartbeatTime:  metav1.Now(),
						LastTransitionTime: metav1.Now(),
					})
				}

				return kubeClient.Status().Update(ctx, n)
			})
			Expect(retryErr).NotTo(HaveOccurred(), "Failed to update Node to simulate NotReady condition")

			// Wait for fallback logic to take effect
			ginkgo.GinkgoWriter.Println("Step 2: Node set to NotReady. Triggering PagerDuty Alert. Waiting.....")

			_, err = testPdClient.TriggerIncident("MachineHealthCheckUnterminatedShortCircuitSRE", clusterID)
			Expect(err).NotTo(HaveOccurred(), "Failed to trigger silent PagerDuty alert")

			time.Sleep(5 * time.Second)

			// Polling every 30 seconds to check if the original number of nodes are in Ready state and not SchedulingDisabled
			checkInterval := 30 * time.Second
			timeout := 6 * time.Minute // Total time to wait for nodes to be Ready

			startTime := time.Now()
			for {
				// List all nodes in the cluster
				nodeList := &corev1.NodeList{}
				err = kubeClient.List(ctx, nodeList, &pclient.ListOptions{})
				Expect(err).NotTo(HaveOccurred(), "Failed to list nodes")

				// Check if the number of nodes is back to the original count
				currentNodeCount := len(nodeList.Items)
				if currentNodeCount > originalNodeCount {
					ginkgo.GinkgoWriter.Printf("Step 3: Found %d nodes, waiting for node count to match original %d...\n", currentNodeCount, originalNodeCount)
				}

				// Counting ready nodes and checking if all are in the Ready state (and not SchedulingDisabled)
				readyNodeCount := 0
				for _, n := range nodeList.Items {
					isReady := false
					// Check if node is Ready
					for _, cond := range n.Status.Conditions {
						if cond.Type == corev1.NodeReady && cond.Status == corev1.ConditionTrue {
							isReady = true
							break
						}
					}

					// Check if node is NOT SchedulingDisabled
					if isReady && !n.Spec.Unschedulable {
						readyNodeCount++
					}
				}

				// Log node status and count after every check
				ginkgo.GinkgoWriter.Printf("Step 4: Node status checked. Ready Node count: %d\n", readyNodeCount)

				if readyNodeCount == originalNodeCount && currentNodeCount == originalNodeCount {
					ginkgo.GinkgoWriter.Println("Step 5: All nodes are in Ready state and not SchedulingDisabled. Test passed.")
					break
				}

				if time.Since(startTime) > timeout {
					Expect(readyNodeCount).To(Equal(originalNodeCount), "Timed out waiting for all nodes to become Ready.")
					break
				}

				// If not all nodes are ready or if there are more nodes, wait for the next interval
				ginkgo.GinkgoWriter.Printf("Step 6: Not all nodes are Ready or node count mismatch. Waiting for %s...\n", checkInterval)
				time.Sleep(checkInterval)
			}

			ginkgo.GinkgoWriter.Println("Step 7: Test completed: Node NotReady condition simulated and checked.")
		}
	})

}, ginkgo.ContinueOnFailure)

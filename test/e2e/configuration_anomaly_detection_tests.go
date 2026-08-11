//go:build osde2e
// +build osde2e

package osde2etests

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/onsi/ginkgo/v2"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	ocmConfig "github.com/openshift-online/ocm-common/pkg/ocm/config"
	ocmConnBuilder "github.com/openshift-online/ocm-common/pkg/ocm/connection-builder"
	"github.com/openshift/configuration-anomaly-detection/pkg/investigations"
	"github.com/openshift/configuration-anomaly-detection/test/e2e/utils"
	ocme2e "github.com/openshift/osde2e-common/pkg/clients/ocm"
	logger "sigs.k8s.io/controller-runtime/pkg/log"
)

var _ = Describe("Configuration Anomaly Detection", Ordered, func() {
	var (
		ocme2eCli *ocme2e.Client
		// k8s       *openshift.Client
		// region       string
		clusterID    string
		testPdClient utils.TestPagerDutyClient
	)

	BeforeAll(func(ctx context.Context) {
		logger.SetLogger(ginkgo.GinkgoLogr)
		var err error
		ocmEnv := ocme2e.Stage
		clusterID = os.Getenv("OCM_CLUSTER_ID")

		Expect(clusterID).NotTo(BeEmpty(), "CLUSTER_ID must be set")

		cfg, err := ocmConfig.Load()
		connection, err := ocmConnBuilder.NewConnection().Config(cfg).AsAgent("cad-local-e2e-tests").Build()

		if err != nil {
			// Fall back to environment variables
			clientID := os.Getenv("OCM_CLIENT_ID")
			clientSecret := os.Getenv("OCM_CLIENT_SECRET")
			Expect(clientID).NotTo(BeEmpty(), "OCM_CLIENT_ID must be set")
			Expect(clientSecret).NotTo(BeEmpty(), "OCM_CLIENT_SECRET must be set")

			ocme2eCli, err = ocme2e.New(ctx, "", clientID, clientSecret, ocmEnv)
			Expect(err).ShouldNot(HaveOccurred(), "Unable to setup E2E OCM Client")
		} else {
			ocme2eCli = &ocme2e.Client{Connection: connection}
		}

		// k8s, err = openshift.New(ginkgo.GinkgoLogr)
		// Expect(err).ShouldNot(HaveOccurred(), "Unable to setup k8s client")

		// region, err = k8s.GetRegion(ctx)
		// Expect(err).NotTo(HaveOccurred(), "Could not determine region")
		//
		// provider, err = k8s.GetProvider(ctx)
		// Expect(err).NotTo(HaveOccurred(), "Could not determine provider")
		//
		// awsAccessKey := os.Getenv("AWS_ACCESS_KEY_ID")
		// awsSecretKey := os.Getenv("AWS_SECRET_ACCESS_KEY")
		// Expect(awsAccessKey).NotTo(BeEmpty(), "AWS access key not found")
		// Expect(awsSecretKey).NotTo(BeEmpty(), "AWS secret key not found")
		//
		// // This was added to allow for the tests to be executed locally/when session token is required
		// // os.Getenv will return "" if AWS_SESSION_TOKEN is not set
		// awsSessionToken := os.Getenv("AWS_SESSION_TOKEN")
		//
		// awsCfg, err = config.LoadDefaultConfig(ctx,
		// 	config.WithRegion(region),
		// 	config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
		// 		awsAccessKey,
		// 		awsSecretKey,
		// 		awsSessionToken,
		// 	)),
		// )
		// Expect(err).NotTo(HaveOccurred(), "Failed to create AWS config")
		//
		pdRoutingKey := os.Getenv("CAD_PAGERDUTY_ROUTING_KEY")
		Expect(pdRoutingKey).NotTo(BeEmpty(), "PAGERDUTY_ROUTING_KEY must be set")
		testPdClient = utils.NewClient(pdRoutingKey)
	})

	AfterAll(func() {
		if ocme2eCli != nil && ocme2eCli.Connection != nil {
			ocme2eCli.Connection.Close()
		}
	})

	It("should not add limited support reasons on a healthy cluster", Label("critical"), func(ctx context.Context) {
		// Get limited support reasons before
		lsResponseBefore, err := utils.GetLimitedSupportReasons(ocme2eCli, clusterID)
		Expect(err).NotTo(HaveOccurred(), "Failed to get limited support reasons")
		lsReasonsBefore := lsResponseBefore.Items().Len()
		ginkgo.GinkgoWriter.Printf("Limited support reasons before blocking egress: %d\n", lsReasonsBefore)

		// Trigger all investigations we have against the healthy cluster
		alertTitles := investigations.GetAvailableInvestigationsTitles()
		ginkgo.GinkgoWriter.Printf("Triggering %d investigations: %v\n", len(alertTitles), alertTitles)

		for _, alertTitle := range alertTitles {
			_, err = testPdClient.TriggerIncident(alertTitle, clusterID)
			Expect(err).NotTo(HaveOccurred(), "Failed to trigger PagerDuty alert for %s", alertTitle)
			ginkgo.GinkgoWriter.Printf("Triggered investigation for: %s\n", alertTitle)
		}

		// Wait - This needs to be long enough for the slowest investigation
		time.Sleep(5 * time.Minute)
		lsResponseAfter, err := utils.GetLimitedSupportReasons(ocme2eCli, clusterID)
		Expect(err).NotTo(HaveOccurred(), "Failed to get limited support reasons")
		fmt.Printf("Limited support reasons after running all investigations: %d\n", lsResponseAfter.Items().Len())

		// Iterate through each item and print details
		items := lsResponseAfter.Items().Slice()
		for i, item := range items {
			fmt.Printf("Reason #%d:\n", i+1)
			fmt.Printf(" - Summary: %s\n", item.Summary())
			fmt.Printf(" - Details: %s\n", item.Details())
		}

		// Expect no new limited support reasons
		Expect(lsResponseAfter.Items().Len()).To(BeNumerically("==", lsReasonsBefore), "No new limited support reasons found after running all investigations")
	})
})

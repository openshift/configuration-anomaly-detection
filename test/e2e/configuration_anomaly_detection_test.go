//go:build osde2e
// +build osde2e

package osde2etests

import (
	"context"
	"os"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/onsi/ginkgo/v2"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	ocme2e "github.com/openshift/osde2e-common/pkg/clients/ocm"
	"github.com/openshift/osde2e-common/pkg/clients/openshift"
	logger "sigs.k8s.io/controller-runtime/pkg/log"
)

var _ = Describe("Configuration Anomaly Detection", Ordered, func() {
	var (
		ocmCli   *ocme2e.Client
		k8s      *openshift.Client
		region   string
		provider string
	)

	ginkgo.BeforeAll(func(ctx context.Context) {
		logger.SetLogger(ginkgo.GinkgoLogr)

		var err error

		ocmEnv := ocme2e.Stage
		ocmToken := os.Getenv("OCM_TOKEN")
		clientID := os.Getenv("CLIENT_ID")
		clientSecret := os.Getenv("CLIENT_SECRET")
		ocmCli, err = ocme2e.New(ctx, ocmToken, clientID, clientSecret, ocmEnv)
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
			Expect(err).NotTo(HaveOccurred(), "Unable to get service logs for cluster")

			// TODO(SDE-4821): Add the following tests
			// AWS CCS: cluster has gone missing (no known misconfiguration)
			// AWS CCS: cluster has gone missing (blocked egress)
			// AWS CCS: cluster has gone missing (infra nodes turned off)
			// AWS CCS: monitoring error budget burn (misconfigured UWM configmap)
			// AWS CCS: monitoring errror budget burn (no known misconfiguration
			ocmCli.Connection.Close()
		}
	})

})

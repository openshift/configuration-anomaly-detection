package utils_test

import (
	"github.com/golang/mock/gomock"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	cmv1 "github.com/openshift-online/ocm-sdk-go/clustersmgmt/v1"
	"github.com/openshift/configuration-anomaly-detection/pkg/ocm"
	ocmmock "github.com/openshift/configuration-anomaly-detection/pkg/ocm/mock"
	"github.com/openshift/configuration-anomaly-detection/pkg/pagerduty"
	pdmock "github.com/openshift/configuration-anomaly-detection/pkg/pagerduty/mock"
	"github.com/openshift/configuration-anomaly-detection/pkg/utils"
)

var _ = Describe("utils", func() {
	var (
		mockCtrl  *gomock.Controller
		pdClient  pagerduty.Client
		ocmClient ocm.Client
	)
	BeforeEach(func() {
		mockCtrl = gomock.NewController(GinkgoT())
		pdClient = pdmock.NewMockClient(mockCtrl)
		ocmClient = ocmmock.NewMockClient(mockCtrl)
	})
	AfterEach(func() {
		mockCtrl.Finish()
	})
	Describe("EscalateAlertIfNotLS", func() {
		When("A cluster is not in limited support", func() {
			It("it should escalate the alert", func() {
				cluster, err := cmv1.NewCluster().Build()
				Expect(err).NotTo(HaveOccurred())

				ocmClient.(*ocmmock.MockClient).EXPECT().IsInLimitedSupport(gomock.Eq(cluster.ID())).Return(false, nil)
				pdClient.(*pdmock.MockClient).EXPECT().EscalateAlertWithNote(gomock.Any())

				gotErr := utils.EscalateAlertIfNotLS("escalationReason", cluster, pdClient, ocmClient)
				Expect(gotErr).NotTo(HaveOccurred())
				Expect(gotErr).NotTo(HaveOccurred())
			})
		})
		When("A cluster is in limited support", func() {
			It("it shouldn't escalate the alert", func() {
				status := cmv1.NewClusterStatus().LimitedSupportReasonCount(2)
				cluster, err := cmv1.NewCluster().Status(status).Build()
				Expect(err).NotTo(HaveOccurred())

				ocmClient.(*ocmmock.MockClient).EXPECT().IsInLimitedSupport(gomock.Eq(cluster.ID())).Return(true, nil)
				pdClient.(*pdmock.MockClient).EXPECT().SilenceAlertWithNote("Cluster is in limited support. Silencing instead of escalating.")

				gotErr := utils.EscalateAlertIfNotLS("escalationReason", cluster, pdClient, ocmClient)

				Expect(gotErr).NotTo(HaveOccurred())
			})
		})
	})
})

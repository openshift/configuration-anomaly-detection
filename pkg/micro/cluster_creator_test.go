package micro_test

import (
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	amv1 "github.com/openshift-online/ocm-sdk-go/accountsmgmt/v1"
	cmv1 "github.com/openshift-online/ocm-sdk-go/clustersmgmt/v1"
	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
	"github.com/openshift/configuration-anomaly-detection/pkg/micro"
	"github.com/openshift/configuration-anomaly-detection/pkg/notewriter"
	ocmmock "github.com/openshift/configuration-anomaly-detection/pkg/ocm/mock"
	"go.uber.org/mock/gomock"
)

var _ = Describe("ClusterCreator", func() {
	var (
		mockCtrl  *gomock.Controller
		ocmClient *ocmmock.MockClient
		cluster   *cmv1.Cluster
		notes     *notewriter.NoteWriter
	)

	BeforeEach(func() {
		logging.InitLogger("fatal", "", "")
		mockCtrl = gomock.NewController(GinkgoT())
		ocmClient = ocmmock.NewMockClient(mockCtrl)
		var err error
		cluster, err = cmv1.NewCluster().ID("test-id").Build()
		Expect(err).NotTo(HaveOccurred())
		notes = notewriter.New("test", logging.RawLogger)
	})

	AfterEach(func() {
		mockCtrl.Finish()
	})

	When("creator is found", func() {
		It("should return the account and not be Done", func() {
			account, _ := amv1.NewAccount().ID("user-123").Email("test@example.com").Build()
			ocmClient.EXPECT().GetCreatorFromCluster(gomock.Any()).Return(account, nil)

			result, err := micro.ClusterCreator(ocmClient, cluster, notes)
			Expect(err).NotTo(HaveOccurred())
			Expect(result.Done).To(BeFalse())
			Expect(result.Value).NotTo(BeNil())
			Expect(result.Value.ID()).To(Equal("user-123"))
			Expect(result.Value.Email()).To(Equal("test@example.com"))
		})
	})

	When("creator lookup fails", func() {
		It("should return error", func() {
			ocmClient.EXPECT().GetCreatorFromCluster(gomock.Any()).
				Return(nil, fmt.Errorf("OCM unavailable"))

			_, err := micro.ClusterCreator(ocmClient, cluster, notes)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("OCM unavailable"))
		})
	})
})

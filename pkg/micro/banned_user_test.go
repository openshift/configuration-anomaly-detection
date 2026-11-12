package micro_test

import (
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	cmv1 "github.com/openshift-online/ocm-sdk-go/clustersmgmt/v1"
	"github.com/openshift/configuration-anomaly-detection/pkg/executor"
	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
	"github.com/openshift/configuration-anomaly-detection/pkg/micro"
	"github.com/openshift/configuration-anomaly-detection/pkg/notewriter"
	"github.com/openshift/configuration-anomaly-detection/pkg/ocm"
	ocmmock "github.com/openshift/configuration-anomaly-detection/pkg/ocm/mock"
	"github.com/openshift/configuration-anomaly-detection/pkg/types"
	"go.uber.org/mock/gomock"
)

func hasActionType(actions []types.Action, actionType string) bool {
	for _, action := range actions {
		if action.Type() == actionType {
			return true
		}
	}
	return false
}

var _ = Describe("BannedUser", func() {
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

	When("user is banned due to export control", func() {
		It("should return Done with Escalate", func() {
			ocmClient.EXPECT().CheckIfUserBanned(gomock.Any()).
				Return(ocm.UserBannedError{Code: "export_control_compliance"})

			result, err := micro.BannedUser(ocmClient, cluster, notes)
			Expect(err).NotTo(HaveOccurred())
			Expect(result.Done).To(BeTrue())
			Expect(hasActionType(result.Actions, string(executor.ActionTypeEscalateIncident))).To(BeTrue())
			Expect(hasActionType(result.Actions, string(executor.ActionTypeSilenceIncident))).To(BeFalse())
		})
	})

	When("user is banned for other reasons", func() {
		It("should return Done with ServiceLog and Silence", func() {
			ocmClient.EXPECT().CheckIfUserBanned(gomock.Any()).
				Return(ocm.UserBannedError{Code: "terms_and_conditions"})

			result, err := micro.BannedUser(ocmClient, cluster, notes)
			Expect(err).NotTo(HaveOccurred())
			Expect(result.Done).To(BeTrue())
			Expect(hasActionType(result.Actions, string(executor.ActionTypeServiceLog))).To(BeTrue())
			Expect(hasActionType(result.Actions, string(executor.ActionTypeSilenceIncident))).To(BeTrue())
		})
	})

	When("ban check fails", func() {
		It("should return error", func() {
			ocmClient.EXPECT().CheckIfUserBanned(gomock.Any()).
				Return(fmt.Errorf("connection timeout"))

			_, err := micro.BannedUser(ocmClient, cluster, notes)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("connection timeout"))
		})
	})

	When("user is not banned", func() {
		It("should return not Done", func() {
			ocmClient.EXPECT().CheckIfUserBanned(gomock.Any()).Return(nil)

			result, err := micro.BannedUser(ocmClient, cluster, notes)
			Expect(err).NotTo(HaveOccurred())
			Expect(result.Done).To(BeFalse())
			Expect(notes.String()).To(ContainSubstring("not banned"))
		})
	})
})

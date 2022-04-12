package cad_test

import (
	"github.com/golang/mock/gomock"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/openshift/configuration-anomaly-detection/pkg/cad"
	mock "github.com/openshift/configuration-anomaly-detection/pkg/cad/mock"
)

var _ = Describe("CAD", func() {
	var (
		mockCtrl         *gomock.Controller
		pdMock           *mock.MockPagerDuty
		incidentID       string
		notes            string
		escalationPolicy string
	)

	BeforeEach(func() {
		mockCtrl = gomock.NewController(GinkgoT())
		pdMock = mock.NewMockPagerDuty(mockCtrl)
		incidentID = "test"
		notes = "Pretend this is a service log"
	})

	When("the customer caused the node shutdown", func() {
		It("should create no alert", func() {
			escalationPolicy = "Silent Test"
			pdMock.EXPECT().AddNote(incidentID, notes).Return(nil).Times(1)
			pdMock.EXPECT().MoveToEscalationPolicy(incidentID, escalationPolicy).Return(nil).Times(1)
			err := cad.SilenceAlert(pdMock, incidentID, notes)
			Expect(err).ShouldNot(HaveOccurred())
		})
	})

	When("the customer did not cause the node shutdown", func() {
		It("should create an alert for us", func() {
			escalationPolicy = "Openshift Escalation Policy"
			pdMock.EXPECT().AddNote(incidentID, notes).Return(nil).Times(1)
			pdMock.EXPECT().MoveToEscalationPolicy(incidentID, escalationPolicy).Return(nil).Times(1)
			err := cad.EscalateAlert(pdMock, incidentID, notes)
			Expect(err).ShouldNot(HaveOccurred())
		})
	})
})

package cad_test

import (
	"fmt"

	"github.com/golang/mock/gomock"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/openshift/configuration-anomaly-detection/pkg/services/cad"
	mock "github.com/openshift/configuration-anomaly-detection/pkg/services/cad/mock"
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

	When("attempting to escalate an alert", func() {
		It("should correctly update the incident", func() {
			escalationPolicy = "Openshift Escalation Policy"
			pdMock.EXPECT().AddNote(incidentID, notes).Return(nil).Times(1)
			pdMock.EXPECT().MoveToEscalationPolicy(incidentID, escalationPolicy).Return(nil).Times(1)
			err := cad.EscalateAlert(pdMock, incidentID, notes)
			Expect(err).ShouldNot(HaveOccurred())
		})
	})

	When("attaching a Note to the incident was not successful", func() {
		It("should fail with an error", func() {
			escalationPolicy = "Silent Test"
			pdMock.EXPECT().AddNote(incidentID, notes).Return(fmt.Errorf("error occured")).Times(1)
			err := cad.SilenceAlert(pdMock, incidentID, notes)
			Expect(err).Should(HaveOccurred())
		})
	})

	When("there is an error during MoveToEscalationPolicy", func() {
		It("should fail with an error while setting the escalation policy", func() {
			escalationPolicy = "Openshift Escalation Policy"
			pdMock.EXPECT().AddNote(incidentID, notes).Return(nil).Times(1)
			pdMock.EXPECT().MoveToEscalationPolicy(incidentID, escalationPolicy).
				Return(fmt.Errorf("error occured")).Times((1))
			err := cad.EscalateAlert(pdMock, incidentID, notes)
			Expect(err).Should(HaveOccurred())
		})
	})
})

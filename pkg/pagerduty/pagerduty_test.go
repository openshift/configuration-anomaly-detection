package pagerduty_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/openshift/configuration-anomaly-detection/pkg/pagerduty"

	sdk "github.com/PagerDuty/go-pagerduty"
)

var _ = Describe("Pagerduty", func() {

	Describe("MoveToEscalationPolicy", func() {
		var (
			mux              *http.ServeMux
			server           *httptest.Server
			client           *sdk.Client
			p                pagerduty.PagerDuty
			incident         pagerduty.Incident
			escalationPolicy pagerduty.EscalationPolicy
		)
		BeforeEach(func() {
			// Arrange
			mux = http.NewServeMux()
			server = httptest.NewServer(mux)
			client = defaultTestClient(server.URL, "fakeauthtokenstring")

			// each startup of PagerDuty we need to verify the user's email for future requests
			mux.HandleFunc("/users/me", func(w http.ResponseWriter, r *http.Request) {
				Expect(r.Method).To(Equal("GET"))
				_, err := w.Write([]byte(`{"user":{"email":"example@example.example"}}`))
				Expect(err).NotTo(HaveOccurred())
			})
			var err error // err is declared to make clear the p is not created here, but is global
			p, err = pagerduty.New(client)
			Expect(err).NotTo(HaveOccurred())

			incident = pagerduty.Incident{}
			escalationPolicy = pagerduty.EscalationPolicy{ID: "1234"}

		})

		When("The authentication token that is sent is invalid", func() {
			It("Should throw an error (401 unauthorized)", func() {
				//Arrange
				mux.HandleFunc("/incidents", func(w http.ResponseWriter, r *http.Request) {
					Expect(r.Method).To(Equal("PUT"))
					w.WriteHeader(http.StatusUnauthorized)
				})
				// Act
				err := p.MoveToEscalationPolicy(incident, escalationPolicy)
				// Assert
				Expect(err).Should(HaveOccurred())
				Expect(err).Should(MatchError(pagerduty.InvalidTokenErr{}))
			})
		})

		When("If sent input parameters are invalid", func() {
			It("Should throw an error (400 badRequest)", func() {
				//Arrange
				mux.HandleFunc("/incidents", func(w http.ResponseWriter, r *http.Request) {
					Expect(r.Method).To(Equal("PUT"))
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusBadRequest)
					_, err := w.Write([]byte(fmt.Sprintf(`{"error":{"code":%d}}`, pagerduty.InvalidInputParamsErrorCode)))
					Expect(err).NotTo(HaveOccurred())
				})
				// Act
				err := p.MoveToEscalationPolicy(incident, escalationPolicy)
				// Assert
				Expect(err).Should(HaveOccurred())

				Expect(err).Should(MatchError(pagerduty.InvalidInputParamsErr{}))

			})
		})

		When("The Escalation policy has succesfully changed", func() {
			It("Doesn't trigger an error", func() {
				//Arrange
				mux.HandleFunc("/incidents", func(w http.ResponseWriter, r *http.Request) {
					Expect(r.Method).To(Equal("PUT"))
					_, err := w.Write([]byte(`{"incidents": [{"title": "foo", "id": "1", "escalation_policy": {"id": "1234", "type": "escalation_policy_reference"}}]}`))
					Expect(err).ShouldNot(HaveOccurred())
				})
				// Act
				err := p.MoveToEscalationPolicy(incident, escalationPolicy)
				// Assert
				Expect(err).ShouldNot(HaveOccurred())
				Expect(err).Should(BeNil())
			})
		})
	})
})

/*
these were pulled from https://github.com/PagerDuty/go-pagerduty/blob/c6785b92c2c4e24a0009298ad2b9bc457e6df1e7/client.go, if you need the other functions feel free to re-import them
*/

func defaultTestClient(serverURL, authToken string) *sdk.Client {
	c := sdk.NewClient(authToken,
		sdk.WithAPIEndpoint(serverURL),
		sdk.WithV2EventsAPIEndpoint(serverURL))
	return c
}

// HTTPClient is an interface which declares the functionality we need from an
// HTTP client. This is to allow consumers to provide their own HTTP client as
// needed, without restricting them to only using *http.Client.
type HTTPClient interface {
	Do(*http.Request) (*http.Response, error)
}

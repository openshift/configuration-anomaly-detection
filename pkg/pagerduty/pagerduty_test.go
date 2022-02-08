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
	var (
		mux        *http.ServeMux
		server     *httptest.Server
		client     *sdk.Client
		p          pagerduty.PagerDuty
		incidentID string
	)
	BeforeEach(func() {
		// Arrange
		mux = http.NewServeMux()
		server = httptest.NewServer(mux)
		client = defaultTestClient(server.URL, "fakeauthtokenstring")

		// each startup of PagerDuty we need to verify the user's email for future requests
		mux.HandleFunc("/users/me", func(w http.ResponseWriter, r *http.Request) {
			Expect(r.Method).Should(Equal("GET"))
			fmt.Fprint(w, `{"user":{"email":"example@example.example"}}`)
		})
		var err error // err is declared to make clear the p is not created here, but is global
		p, err = pagerduty.New(client)
		Expect(err).ShouldNot(HaveOccurred())
	})
	Describe("MoveToEscalationPolicy", func() {
		var (
			escalationPolicyID string
		)
		BeforeEach(func() {
			escalationPolicyID = "1234"
		})

		When("The authentication token that is sent is invalid", func() {
			It("Should throw an error (401 unauthorized)", func() {
				//Arrange
				mux.HandleFunc("/incidents", func(w http.ResponseWriter, r *http.Request) {
					Expect(r.Method).Should(Equal("PUT"))
					w.WriteHeader(http.StatusUnauthorized)
				})
				// Act
				err := p.MoveToEscalationPolicy(incidentID, escalationPolicyID)
				// Assert
				Expect(err).Should(HaveOccurred())
				Expect(err).Should(MatchError(pagerduty.InvalidTokenErr{}))
			})
		})

		When("If sent input parameters are invalid", func() {
			It("Should throw an error (400 badRequest)", func() {
				//Arrange
				mux.HandleFunc("/incidents", func(w http.ResponseWriter, r *http.Request) {
					Expect(r.Method).Should(Equal("PUT"))
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusBadRequest)
					fmt.Fprintf(w, `{"error":{"code":%d}}`, pagerduty.InvalidInputParamsErrorCode)
				})
				// Act
				err := p.MoveToEscalationPolicy(incidentID, escalationPolicyID)
				// Assert
				Expect(err).Should(HaveOccurred())

				Expect(err).Should(MatchError(pagerduty.InvalidInputParamsErr{}))

			})
		})

		When("The Escalation policy has successfully changed", func() {
			It("Doesn't trigger an error", func() {
				//Arrange
				mux.HandleFunc("/incidents", func(w http.ResponseWriter, r *http.Request) {
					Expect(r.Method).Should(Equal("PUT"))
					fmt.Fprint(w, `{}`)
				})
				// Act
				err := p.MoveToEscalationPolicy(incidentID, escalationPolicyID)
				// Assert
				Expect(err).ShouldNot(HaveOccurred())
				Expect(err).Should(BeNil())
			})
		})
	})
	Describe("AssignToUser", func() {
		var (
			userID string
		)
		BeforeEach(func() {
			userID = "1234"
		})

		When("The authentication token that is sent is invalid", func() {
			It("Should throw an error (401 unauthorized)", func() {
				//Arrange
				mux.HandleFunc("/incidents", func(w http.ResponseWriter, r *http.Request) {
					Expect(r.Method).Should(Equal("PUT"))
					w.WriteHeader(http.StatusUnauthorized)
				})
				// Act
				err := p.AssignToUser(incidentID, userID)
				// Assert
				Expect(err).Should(HaveOccurred())
				Expect(err).Should(MatchError(pagerduty.InvalidTokenErr{}))
			})
		})

		When("If sent input parameters are invalid", func() {
			It("Should throw an error (400 badRequest)", func() {
				//Arrange
				mux.HandleFunc("/incidents", func(w http.ResponseWriter, r *http.Request) {
					Expect(r.Method).Should(Equal("PUT"))
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusBadRequest)
					fmt.Fprintf(w, `{"error":{"code":%d}}`, pagerduty.InvalidInputParamsErrorCode)
				})
				// Act
				err := p.AssignToUser(incidentID, userID)
				// Assert
				Expect(err).Should(HaveOccurred())

				Expect(err).Should(MatchError(pagerduty.InvalidInputParamsErr{}))

			})
		})

		When("The Assigned User has successfully changed", func() {
			It("Doesn't trigger an error", func() {
				//Arrange
				mux.HandleFunc("/incidents", func(w http.ResponseWriter, r *http.Request) {
					Expect(r.Method).Should(Equal("PUT"))
					fmt.Fprint(w, `{}`)
				})
				// Act
				err := p.AssignToUser(incidentID, userID)
				// Assert
				// Assert
				Expect(err).ShouldNot(HaveOccurred())
				Expect(err).Should(BeNil())
			})
		})
	})
	Describe("AcknowledgeIncident", func() {
		BeforeEach(func() {
		})

		When("The authentication token that is sent is invalid", func() {
			It("Should throw an error (401 unauthorized)", func() {
				//Arrange
				mux.HandleFunc("/incidents", func(w http.ResponseWriter, r *http.Request) {
					Expect(r.Method).Should(Equal("PUT"))
					w.WriteHeader(http.StatusUnauthorized)
				})
				// Act
				err := p.AcknowledgeIncident(incidentID)
				// Assert
				Expect(err).Should(HaveOccurred())
				Expect(err).Should(MatchError(pagerduty.InvalidTokenErr{}))
			})
		})

		When("If sent input parameters are invalid", func() {
			It("Should throw an error (400 badRequest)", func() {
				//Arrange
				mux.HandleFunc("/incidents", func(w http.ResponseWriter, r *http.Request) {
					Expect(r.Method).Should(Equal("PUT"))
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusBadRequest)
					fmt.Fprintf(w, `{"error":{"code":%d}}`, pagerduty.InvalidInputParamsErrorCode)
				})
				// Act
				err := p.AcknowledgeIncident(incidentID)
				// Assert
				Expect(err).Should(HaveOccurred())

				Expect(err).Should(MatchError(pagerduty.InvalidInputParamsErr{}))

			})
		})

		When("The incident has successfully acknowledged", func() {
			It("Doesn't trigger an error", func() {
				//Arrange
				mux.HandleFunc("/incidents", func(w http.ResponseWriter, r *http.Request) {
					Expect(r.Method).Should(Equal("PUT"))
					fmt.Fprint(w, `{}`)
				})
				// Act
				err := p.AcknowledgeIncident(incidentID)
				// Assert
				Expect(err).ShouldNot(HaveOccurred())
				Expect(err).Should(BeNil())
			})
		})
	})

	Describe("AddNote", func() {
		var (
			noteContent string
		)
		BeforeEach(func() {
			noteContent = "this is a test"
			// this is the only place that actually required a value to be set for the incidentID
			incidentID = "1234"

		})

		When("The authentication token that is sent is invalid", func() {
			It("Should throw an error (401 unauthorized)", func() {
				//Arrange
				mux.HandleFunc(fmt.Sprintf("/incidents/%s/notes", incidentID), func(w http.ResponseWriter, r *http.Request) {
					Expect(r.Method).Should(Equal("POST"))
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusUnauthorized)
					fmt.Fprint(w, `{}`)
				})
				// Act
				err := p.AddNote(incidentID, noteContent)
				// Assert
				Expect(err).Should(HaveOccurred())
				Expect(err).Should(MatchError(pagerduty.InvalidTokenErr{}))
			})
		})

		When("If sent input parameters are invalid", func() {
			It("Should throw an error (400 badRequest)", func() {
				//Arrange
				mux.HandleFunc(fmt.Sprintf("/incidents/%s/notes", incidentID), func(w http.ResponseWriter, r *http.Request) {
					Expect(r.Method).Should(Equal("POST"))
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusBadRequest)
					fmt.Fprintf(w, `{"error":{"code":%d}}`, pagerduty.InvalidInputParamsErrorCode)
				})
				// Act
				err := p.AddNote(incidentID, noteContent)
				// Assert
				Expect(err).Should(HaveOccurred())

				Expect(err).Should(MatchError(pagerduty.InvalidInputParamsErr{}))

			})
		})

		When("If the incident that needs to attach the note is doesn't exist", func() {
			It("Should throw an error (404 notFound)", func() {
				//Arrange
				mux.HandleFunc(fmt.Sprintf("/incidents/%s/notes", incidentID), func(w http.ResponseWriter, r *http.Request) {
					Expect(r.Method).Should(Equal("POST"))
					w.WriteHeader(http.StatusNotFound)
				})
				// Act
				err := p.AddNote(incidentID, noteContent)
				// Assert
				Expect(err).Should(HaveOccurred())

				Expect(err).Should(MatchError(pagerduty.IncidentNotFoundErr{}))

			})
		})

		When("The incident note was successfully added", func() {
			It("Doesn't trigger an error", func() {
				//Arrange
				mux.HandleFunc(fmt.Sprintf("/incidents/%s/notes", incidentID), func(w http.ResponseWriter, r *http.Request) {
					Expect(r.Method).Should(Equal("POST"))
					fmt.Fprint(w, `{}`)
				})
				// Act
				err := p.AddNote(incidentID, noteContent)
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

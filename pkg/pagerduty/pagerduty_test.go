package pagerduty

import (
	"fmt"
	"net/http"
	"net/http/httptest"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	sdk "github.com/PagerDuty/go-pagerduty"
	logging "github.com/openshift/configuration-anomaly-detection/pkg/logging"
)

func init() {
	logging.RawLogger = logging.InitLogger("info")
}

var _ = Describe("Pagerduty", func() {
	var (
		mux                *http.ServeMux
		server             *httptest.Server
		p                  *SdkClient
		incidentID         string
		escalationPolicyID string
		silencePolicyID    string
	)
	BeforeEach(func() {
		// Arrange
		mux = http.NewServeMux()
		server = httptest.NewServer(mux)
		silencePolicyID = "1234"
		// each startup of PagerDuty we need to verify the user's email for future requests
		mux.HandleFunc("/users/me", func(w http.ResponseWriter, r *http.Request) {
			Expect(r.Method).Should(Equal("GET"))
			_, _ = fmt.Fprint(w, `{"user":{"email":"example@example.example"}}`)
		})
		var err error // err is declared to make clear the p is not created here, but is global
		p, err = NewWithToken(
			silencePolicyID,
			[]byte(`{"event":{"id":"$ID","event_type":"incident.triggered","resource_type":"incident","occurred_at":"DATE","agent":{"html_url":"https://$PD_HOST/users/$USER_ID","id":"$USER_ID","self":"https://api.com/users/$USER_ID","summary":"$USERNAME","type":"user_reference"},"client":null,"data":{"id":"1234","type":"incident","self":"https://api.com/incidents/$INCIDENT_ID","html_url":"https://$PD_HOST/incidents/$INCIDENT_ID","number":"${INCIDENT_NUMBER}","status":"triggered","incident_key":"${INCIDENT_KEY}","created_at":"DATE","title":"${INCIDENT_TITLE}","service":{"html_url":"https://$PD_HOST/services/$SERVICE_ID","id":"$SERVICE_ID","self":"https://api.com/services/$SERVICE_ID","summary":"$SERVICE_NAME","type":"service_reference"},"assignees":[{"html_url":"https://$PD_HOST/users/$USER_ID_2","id":"$USER_ID_2","self":"https://api.com/users/$USER_ID_2","summary":"$USER_NAME_2","type":"user_reference"}],"escalation_policy":{"html_url":"https://$PD_HOST/escalation_policies/$EP_ID","id":"$EP_ID","self":"https://api.com/escalation_policies/$EP_ID","summary":"$EP_NAME","type":"escalation_policy_reference"},"teams":[],"priority":null,"urgency":"high","conference_bridge":null,"resolve_reason":null}}}`),
			"fakeathtokenstring",
			sdk.WithAPIEndpoint(server.URL),
			sdk.WithV2EventsAPIEndpoint(server.URL),
		)
		Expect(err).ShouldNot(HaveOccurred())
	})
	AfterEach(func() {
		// close the server (httptest.NewServer requested this in the code)
		server.Close()
	})
	Describe("MoveToEscalationPolicy", func() {
		When("The authentication token that is sent is invalid", func() {
			It("Should throw an error (401 unauthorized)", func() {
				// Arrange
				mux.HandleFunc("/incidents", func(w http.ResponseWriter, r *http.Request) {
					Expect(r.Method).Should(Equal("PUT"))
					w.WriteHeader(http.StatusUnauthorized)
				})
				// Act
				err := p.moveToEscalationPolicy(escalationPolicyID)
				// Assert
				Expect(err).Should(HaveOccurred())
				Expect(err).Should(MatchError(InvalidTokenError{}))
			})
		})

		When("If sent input parameters are invalid", func() {
			It("Should throw an error (400 badRequest)", func() {
				// Arrange
				mux.HandleFunc("/incidents", func(w http.ResponseWriter, r *http.Request) {
					Expect(r.Method).Should(Equal("PUT"))
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusBadRequest)
					_, _ = fmt.Fprintf(w, `{"error":{"code":%d}}`, InvalidInputParamsErrorCode)
				})
				// Act
				err := p.moveToEscalationPolicy(escalationPolicyID)
				// Assert
				Expect(err).Should(HaveOccurred())

				Expect(err).Should(MatchError(InvalidInputParamsError{}))
			})
		})

		When("The Escalation policy has successfully changed", func() {
			It("Doesn't trigger an error", func() {
				// Arrange
				mux.HandleFunc("/incidents", func(w http.ResponseWriter, r *http.Request) {
					Expect(r.Method).Should(Equal("PUT"))
					_, _ = fmt.Fprint(w, `{}`)
				})
				// Act
				err := p.moveToEscalationPolicy(escalationPolicyID)
				// Assert
				Expect(err).ShouldNot(HaveOccurred())
			})
		})
	})

	Describe("AddNote", func() {
		var noteContent string
		BeforeEach(func() {
			noteContent = "this is a test"
			// this is the only place that actually required a value to be set for the incidentID
			incidentID = "1234"
		})

		When("The authentication token that is sent is invalid", func() {
			It("Should throw an error (401 unauthorized)", func() {
				// Arrange
				mux.HandleFunc(fmt.Sprintf("/incidents/%s/notes", incidentID), func(w http.ResponseWriter, r *http.Request) {
					Expect(r.Method).Should(Equal("POST"))
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusUnauthorized)
					_, _ = fmt.Fprint(w, `{}`)
				})
				// Act
				err := p.AddNote(noteContent)
				// Assert
				Expect(err).Should(HaveOccurred())
				Expect(err).Should(MatchError(InvalidTokenError{}))
			})
		})

		When("If sent input parameters are invalid", func() {
			It("Should throw an error (400 badRequest)", func() {
				// Arrange
				mux.HandleFunc(fmt.Sprintf("/incidents/%s/notes", incidentID), func(w http.ResponseWriter, r *http.Request) {
					Expect(r.Method).Should(Equal("POST"))
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusBadRequest)
					_, _ = fmt.Fprintf(w, `{"error":{"code":%d}}`, InvalidInputParamsErrorCode)
				})
				// Act
				err := p.AddNote(noteContent)
				// Assert
				Expect(err).Should(HaveOccurred())

				Expect(err).Should(MatchError(InvalidInputParamsError{}))
			})
		})

		When("If the incident that is passed to the function doesn't exist", func() {
			It("Should throw an error (404 notFound)", func() {
				// Arrange
				mux.HandleFunc(fmt.Sprintf("/incidents/%s/notes", incidentID), func(w http.ResponseWriter, r *http.Request) {
					Expect(r.Method).Should(Equal("POST"))
					w.WriteHeader(http.StatusNotFound)
				})
				// Act
				err := p.AddNote(noteContent)
				// Assert
				Expect(err).Should(HaveOccurred())
				Expect(err).Should(MatchError(IncidentNotFoundError{}))
			})
		})

		When("The incident note was successfully added", func() {
			It("Doesn't trigger an error", func() {
				// Arrange
				mux.HandleFunc(fmt.Sprintf("/incidents/%s/notes", incidentID), func(w http.ResponseWriter, r *http.Request) {
					Expect(r.Method).Should(Equal("POST"))
					_, _ = fmt.Fprint(w, `{}`)
				})
				// Act
				err := p.AddNote(noteContent)
				// Assert
				Expect(err).ShouldNot(HaveOccurred())
			})
		})
	})

	Describe("GetAlerts", func() {
		BeforeEach(func() {
			incidentID = "1234"
		})

		When("The authentication token that is sent is invalid", func() {
			It("Should throw an error (401 unauthorized)", func() {
				// Arrange
				mux.HandleFunc(fmt.Sprintf("/incidents/%s/alerts", incidentID), func(w http.ResponseWriter, r *http.Request) {
					Expect(r.Method).Should(Equal("GET"))
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusUnauthorized)
					_, _ = fmt.Fprint(w, `{}`)
				})
				// Act
				_, err := p.GetAlertsForIncident(incidentID)
				// Assert
				Expect(err).Should(HaveOccurred())
				Expect(err).Should(MatchError(InvalidTokenError{}))
			})
		})

		When("If sent input parameters are invalid", func() {
			It("Should throw an error (400 badRequest)", func() {
				// Arrange
				mux.HandleFunc(fmt.Sprintf("/incidents/%s/alerts", incidentID), func(w http.ResponseWriter, r *http.Request) {
					Expect(r.Method).Should(Equal("GET"))
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusBadRequest)
					_, _ = fmt.Fprintf(w, `{"error":{"code":%d}}`, InvalidInputParamsErrorCode)
				})
				// Act
				_, err := p.GetAlertsForIncident(incidentID)
				// Assert
				Expect(err).Should(HaveOccurred())

				Expect(err).Should(MatchError(InvalidInputParamsError{}))
			})
		})

		When("If the incident that is passed to the function doesn't exist", func() {
			It("Should throw an error (404 notFound)", func() {
				// Arrange
				mux.HandleFunc(fmt.Sprintf("/incidents/%s/alerts", incidentID), func(w http.ResponseWriter, r *http.Request) {
					Expect(r.Method).Should(Equal("GET"))
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusNotFound)
					_, _ = fmt.Fprint(w, `{}`)
				})
				// Act
				_, err := p.GetAlertsForIncident(incidentID)
				// Assert
				Expect(err).Should(HaveOccurred())

				Expect(err).Should(MatchError(IncidentNotFoundError{}))
			})
		})

		When("The incident alerts (standard format with custom_details.cluster_id) were successfully pulled", func() {
			It("Doesn't trigger an error and extracts the correct data out", func() {
				// Arrange
				mux.HandleFunc(fmt.Sprintf("/incidents/%s/alerts", incidentID), func(w http.ResponseWriter, r *http.Request) {
					// CHGM format of
					_, _ = fmt.Fprint(w, `{"alerts":[{"id":"123456","body":{"details":{"cluster_id": "123456"}}}]}`)
				})
				// Act
				res, err1 := p.GetAlertsForIncident(incidentID)
				alertsDetails, err2 := p.GetAlertListDetails(res)

				// Assert
				Expect(err1).ShouldNot(HaveOccurred())
				Expect(err2).ShouldNot(HaveOccurred())
				Expect(alertsDetails).Should(HaveLen(1))
				Expect(alertsDetails[0].ID).Should(Equal("123456"))
				Expect(alertsDetails[0].ClusterID).Should(Equal("123456"))
			})
		})
	})

	Describe("NewWithToken", func() {
		When("the payload is empty", func() {
			It("should fail on UnmarshalError", func() {
				_, err := NewWithToken(
					silencePolicyID,
					[]byte(``),
					"fakeathtokenstring",
					sdk.WithAPIEndpoint(server.URL),
					sdk.WithV2EventsAPIEndpoint(server.URL),
				)
				Expect(err).To(HaveOccurred())
			})
		})
		When("the payload contains invalid payload data (sent as a sample webhook data)", func() {
			It("should fail on json marshalling error", func() {
				_, err := NewWithToken(
					silencePolicyID,
					[]byte(`{"event":{"id":"$ID","event_type":"pagey.ping","resource_type":"pagey","occurred_at":"DATE","agent":null,"client":null,"data":{"message":"Hello from your friend Pagey!","type":"ping"}}}`),
					"fakeathtokenstring",
					sdk.WithAPIEndpoint(server.URL),
					sdk.WithV2EventsAPIEndpoint(server.URL),
				)
				Expect(err).Should(MatchError(UnmarshalError{}))
			})
		})
		When("the payload is missing the event type", func() {
			It("should fail on json marshalling error", func() {
				_, err := NewWithToken(
					silencePolicyID,
					[]byte(`{"event":{"id":"$ID","resource_type":"pagey","occurred_at":"DATE","agent":null,"client":null,"data":{"message":"Hello from your friend Pagey!","type":"ping"}}}`),
					"fakeathtokenstring",
					sdk.WithAPIEndpoint(server.URL),
					sdk.WithV2EventsAPIEndpoint(server.URL),
				)
				Expect(err).Should(MatchError(UnmarshalError{}))
			})
		})
		When("the payload is missing the data field", func() {
			It("should fail on json marshalling error", func() {
				_, err := NewWithToken(
					silencePolicyID,
					[]byte(`{"event":{"id":"$ID","event_type":"pagey.ping","resource_type":"pagey","occurred_at":"DATE","agent":null,"client":null}}`),
					"fakeathtokenstring",
					sdk.WithAPIEndpoint(server.URL),
					sdk.WithV2EventsAPIEndpoint(server.URL),
				)
				Expect(err).Should(MatchError(UnmarshalError{}))
			})
		})
	})
	Describe("Receiver", func() {
		Describe("RetrieveClusterID", func() {
			When("the payload path points to a sanitized payload and the api does not have the alert + incident", func() {
				It("should succeed and pull the clusterid", func() {
					// Arrange
					p, _ := NewWithToken(
						silencePolicyID,
						[]byte(`{"event":{"id":"$ID","event_type":"incident.triggered","resource_type":"incident","occurred_at":"DATE","agent":{"html_url":"https://$PD_HOST/users/$USER_ID","id":"$USER_ID","self":"https://api.com/users/$USER_ID","summary":"$USERNAME","type":"user_reference"},"client":null,"data":{"id":"1234","type":"incident","self":"https://api.com/incidents/$INCIDENT_ID","html_url":"https://$PD_HOST/incidents/$INCIDENT_ID","number":"${INCIDENT_NUMBER}","status":"triggered","incident_key":"${INCIDENT_KEY}","created_at":"DATE","title":"${INCIDENT_TITLE}","service":{"html_url":"https://$PD_HOST/services/$SERVICE_ID","id":"$SERVICE_ID","self":"https://api.com/services/$SERVICE_ID","summary":"$SERVICE_NAME","type":"service_reference"},"assignees":[{"html_url":"https://$PD_HOST/users/$USER_ID_2","id":"$USER_ID_2","self":"https://api.com/users/$USER_ID_2","summary":"$USER_NAME_2","type":"user_reference"}],"escalation_policy":{"html_url":"https://$PD_HOST/escalation_policies/$EP_ID","id":"$EP_ID","self":"https://api.com/escalation_policies/$EP_ID","summary":"$EP_NAME","type":"escalation_policy_reference"},"teams":[],"priority":null,"urgency":"high","conference_bridge":null,"resolve_reason":null}}}`),
						"fakeathtokenstring",
						sdk.WithAPIEndpoint(server.URL),
						sdk.WithV2EventsAPIEndpoint(server.URL),
					)
					// Act
					_, err := p.RetrieveClusterID()
					// Assert
					Expect(err).Should(MatchError(IncidentNotFoundError{}))
				})
			})
			When("the payload is valid and the api does have the alert + incident", func() {
				It("should succeed and pull the clusterID", func() {
					// Arrange
					mux.HandleFunc(fmt.Sprintf("/incidents/%s/alerts", incidentID), func(w http.ResponseWriter, r *http.Request) {
						// Standard alert format of
						_, _ = fmt.Fprint(w, `{"alerts":[{"id":"1234","body":{"details":{"cluster_id": "654321"}}}]}`)
					})
					// Act
					res, err := p.RetrieveClusterID()
					// Assert
					Expect(err).ShouldNot(HaveOccurred())
					Expect(res).Should(Equal("654321"))
				})
			})
			When("[BACKWARDS COMPATIBILITY: OSD-18006] the payload contains the cluster_id in the notes field", func() {
				It("should succeed and pull the clusterID", func() {
					// Arrange
					mux.HandleFunc(fmt.Sprintf("/incidents/%s/alerts", incidentID), func(w http.ResponseWriter, r *http.Request) {
						// Standard alert format of
						_, _ = fmt.Fprint(w, `{"alerts":[{"id":"1234","body":{"details":{"notes":"cluster_id: 654321"}}}]}`)
					})
					// Act
					res, err := p.RetrieveClusterID()
					// Assert
					Expect(err).ShouldNot(HaveOccurred())
					Expect(res).Should(Equal("654321"))
				})
			})
			When("the alert body does not have a 'details' field", func() {
				It("should raise an error", func() {
					mux.HandleFunc(fmt.Sprintf("/incidents/%s/alerts", incidentID), func(w http.ResponseWriter, r *http.Request) {
						// Standard alert format of
						_, _ = fmt.Fprint(w, `{"alerts":[{"id":"1234","body":{"describe":{"chicken": 1.75},"steak":true}}]}`)
					})
					// Act
					_, err := p.RetrieveClusterID()
					// Assert
					Expect(err).Should(HaveOccurred())
				})
			})
			When("the '.details' field is of the wrong type", func() {
				It("should raise an error", func() {
					mux.HandleFunc(fmt.Sprintf("/incidents/%s/alerts", incidentID), func(w http.ResponseWriter, r *http.Request) {
						_, _ = fmt.Fprint(w, `{"alerts":[{"id":"1234","body":{"details":"bad details"}}]}`)
					})

					_, err := p.RetrieveClusterID()
					Expect(err).Should(HaveOccurred())
				})
			})
		})
	})
})

/*
these were pulled from https://github.com/PagerDuty/go-pagerduty/blob/c6785b92c2c4e24a0009298ad2b9bc457e6df1e7/client.go, if you need the other functions feel free to re-import them
*/

// HTTPClient is an interface which declares the functionality we need from an
// HTTP client. This is to allow consumers to provide their own HTTP client as
// needed, without restricting them to only using *http.Client.
type HTTPClient interface {
	Do(*http.Request) (*http.Response, error)
}

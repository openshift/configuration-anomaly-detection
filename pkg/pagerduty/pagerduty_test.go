package pagerduty_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing/fstest"

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
		p          pagerduty.Client
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
	AfterEach(func() {
		// close the server (httptest.NewServer requested this in the code)
		server.Close()
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
				// Arrange
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
				// Arrange
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
				// Arrange
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
				// Arrange
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
				// Arrange
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
				// Arrange
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
				// Arrange
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
				// Arrange
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
				// Arrange
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
				// Arrange
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
				// Arrange
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

		When("If the incident that is passed to the function doesn't exist", func() {
			It("Should throw an error (404 notFound)", func() {
				// Arrange
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
				// Arrange
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
					fmt.Fprint(w, `{}`)
				})
				// Act
				_, err := p.GetAlerts(incidentID)
				// Assert
				Expect(err).Should(HaveOccurred())
				Expect(err).Should(MatchError(pagerduty.InvalidTokenErr{}))
			})
		})

		When("If sent input parameters are invalid", func() {
			It("Should throw an error (400 badRequest)", func() {
				// Arrange
				mux.HandleFunc(fmt.Sprintf("/incidents/%s/alerts", incidentID), func(w http.ResponseWriter, r *http.Request) {
					Expect(r.Method).Should(Equal("GET"))
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusBadRequest)
					fmt.Fprintf(w, `{"error":{"code":%d}}`, pagerduty.InvalidInputParamsErrorCode)
				})
				// Act
				_, err := p.GetAlerts(incidentID)
				// Assert
				Expect(err).Should(HaveOccurred())

				Expect(err).Should(MatchError(pagerduty.InvalidInputParamsErr{}))

			})
		})

		When("If the incident that is passed to the function doesn't exist", func() {
			It("Should throw an error (404 notFound)", func() {
				// Arrange
				mux.HandleFunc(fmt.Sprintf("/incidents/%s/alerts", incidentID), func(w http.ResponseWriter, r *http.Request) {
					Expect(r.Method).Should(Equal("GET"))
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusNotFound)
					fmt.Fprint(w, `{}`)
				})
				// Act
				_, err := p.GetAlerts(incidentID)
				// Assert
				Expect(err).Should(HaveOccurred())

				Expect(err).Should(MatchError(pagerduty.IncidentNotFoundErr{}))
			})
		})

		When("The incident alerts (CHGM format) were successfully pulled", func() {
			It("Doesn't trigger an error and extracts the correct data out", func() {
				// Arrange
				mux.HandleFunc(fmt.Sprintf("/incidents/%s/alerts", incidentID), func(w http.ResponseWriter, r *http.Request) {
					// CHGM format of
					fmt.Fprint(w, `{"alerts":[{"id":"123456","body":{"details":{"notes":"cluster_id: 123456"}}}]}`)
				})
				// Act
				res, err := p.GetAlerts(incidentID)
				// Assert
				Expect(err).ShouldNot(HaveOccurred())
				Expect(err).Should(BeNil())
				Expect(res).Should(HaveLen(1))
				Expect(res[0].ID).Should(Equal("123456"))
				Expect(res[0].ExternalID).Should(Equal("123456"))

			})
		})
	})

	Describe("CreateNewAlert", func() {
		var (
			serviceID string
			dmsIntegrationID string
		)
		BeforeEach(func(){
			serviceID = "service-id-12345"
			dmsIntegrationID = "integration-id-12345"
		})
		When("The service cannot be retrieved", func(){
			It("should return a ServiceNotFoundErr", func() {
				err := p.CreateNewAlert("empty-description", "empty-details", "nonexistent-service")
				Expect(err).To(HaveOccurred())
				Expect(err).To(MatchError(pagerduty.ServiceNotFoundErr{}))
			})
		})
		When("The service has no Dead Man's Snitch integrations", func(){
			It("should return an IntegrationNotFoundErr", func(){
				mux.HandleFunc(fmt.Sprintf("/services/%s", serviceID), func(w http.ResponseWriter, r *http.Request) {
					fmt.Fprintf(w, `{"service":{"id":"%s","integrations":[]}}`, serviceID)
				})
				err := p.CreateNewAlert("empty-description", "empty-details", serviceID)
				Expect(err).To(HaveOccurred())
				Expect(err).To(MatchError(pagerduty.IntegrationNotFoundErr{}))
			})
		})
		When("The event creation fails", func(){
			It("should return a CreateEventErr", func() {
				mux.HandleFunc(fmt.Sprintf("/services/%s", serviceID), func(w http.ResponseWriter, r *http.Request) {
					fmt.Fprintf(w, `{"service":{"id":"%s","integrations":[{"id":"%s"}]}}`, serviceID, dmsIntegrationID)
				})
				mux.HandleFunc(fmt.Sprintf("/services/%s/integrations/%s", serviceID, dmsIntegrationID), func(w http.ResponseWriter, r *http.Request) {
					fmt.Fprintf(w, `{"integration":{"id":"%s","name":"%s"}}`, dmsIntegrationID, pagerduty.CADIntegrationName)
				})
				err := p.CreateNewAlert("empty-description", "empty-details", serviceID)
				Expect(err).To(HaveOccurred())
				Expect(err).To(MatchError(pagerduty.CreateEventErr{}))
			})
		})
	})

	Describe("ExtractExternalIDFromCGHMAlertBody", func() {
		var alertBody map[string]interface{}
		BeforeEach(func() {
			alertBody = map[string]interface{}{}
		})

		When("the input object does not have a 'notes' field", func() {
			It("should raise an 'AlertBodyDoesNotHaveNotesFieldErr' error", func() {
				// Arrange
				alertBody = map[string]interface{}{
					"describe": struct {
						source string
						price  float64
					}{"chicken", 1.75},
					"steak": true,
				}
				// Act
				_, err := p.ExtractIDFromCHGM(alertBody)
				// Assert
				Expect(err).Should(HaveOccurred())
				Expect(err).Should(MatchError(pagerduty.AlertBodyExternalParseErr{FailedProperty: ".details"}))
			})
		})

		When("the '.details' field is of the wrong type", func() {
			It("should raise a 'AlertBodyExternalCastErr' error", func() {
				// Arrange
				alertBody = map[string]interface{}{
					"details": "bad details",
				}
				expectedErr := pagerduty.AlertBodyExternalCastErr{
					FailedProperty:     ".details",
					ExpectedType:       "map[string]interface{}",
					ActualType:         "string",
					ActualBodyResource: "bad details",
				}
				// Act
				_, err := p.ExtractIDFromCHGM(alertBody)
				// Assert
				Expect(err).Should(HaveOccurred())
				Expect(err).Should(MatchError(expectedErr))
			})
		})
		When("the '.details.notes' field is of the wrong type", func() {
			It("should raise a 'AlertBodyExternalCastErr' error", func() {
				// Arrange
				alertBody = map[string]interface{}{
					"details": map[string]interface{}{
						"notes": map[string]interface{}{
							"hello": "world",
						},
					},
				}
				expectedErr := pagerduty.AlertBodyExternalCastErr{
					FailedProperty:     ".details.notes",
					ExpectedType:       "string",
					ActualType:         "map[string]interface {}",
					ActualBodyResource: "map[hello:world]",
				}
				// Act
				_, err := p.ExtractIDFromCHGM(alertBody)
				// Assert
				Expect(err).Should(HaveOccurred())
				Expect(err).Should(MatchError(expectedErr))
			})
		})

		When("the notes field is improperly parsed by the 'yaml' package", func() {
			It("should raise a 'NotesParseErr' error", func() {
				// Arrange
				alertBody = map[string]interface{}{
					"details": map[string]interface{}{
						"notes": "chicken",
					},
				}
				// Act
				_, err := p.ExtractIDFromCHGM(alertBody)
				// Assert
				Expect(err).Should(HaveOccurred())
				Expect(err).Should(MatchError(pagerduty.NotesParseErr{}))
			})
		})

		When("the notes field has a clusterid", func() {
			It("should be returned correctly", func() {
				// Arrange
				alertBody = map[string]interface{}{
					"details": map[string]interface{}{
						"notes": `cluster_id: "12345"`,
					},
				}
				// Act
				res, err := p.ExtractIDFromCHGM(alertBody)
				// Assert
				Expect(err).ShouldNot(HaveOccurred())
				Expect(res).Should(Equal("12345"))
			})
		})
	})
	Describe("Receiver", func() {
		Describe("ExtractExternalIDFromPayload", func() {
			var (
				fs fstest.MapFS
			)
			BeforeEach(func() {
				// Arrange
				fs = fstest.MapFS{}
			})

			When("the payload path is empty", func() {
				It("should fail on FileNotFoundErr", func() {
					// Arrange
					// Act
					_, err := p.ExtractExternalIDFromPayload("", fs)
					// Assert
					Expect(err).Should(MatchError(pagerduty.FileNotFoundErr{}))
				})
			})

			When("the payload path points to a file not on the filesystem", func() {
				It("should fail on FileNotFoundErr", func() {
					// Arrange
					// Act
					_, err := p.ExtractExternalIDFromPayload("bla", fs)
					// Assert
					Expect(err).Should(MatchError(pagerduty.FileNotFoundErr{}))
				})
			})

			When("the payload path points to an empty file", func() {
				It("should fail on json marshalling error", func() {
					// Arrange
					fs = fstest.MapFS{
						"payload.json": {
							Data: []byte(""),
						},
					}
					// Act
					_, err := p.ExtractExternalIDFromPayload("payload.json", fs)
					// Assert
					Expect(err).Should(MatchError(pagerduty.UnmarshalErr{}))
				})
			})

			When("the payload path points to an empty json struct", func() {
				It("should fail on json marshalling error", func() {
					// Arrange
					fs = fstest.MapFS{
						"payload.json": {
							Data: []byte("{}"),
						},
					}
					// Act
					_, err := p.ExtractExternalIDFromPayload("payload.json", fs)
					// Assert
					Expect(err).Should(MatchError(pagerduty.UnmarshalErr{}))
				})
			})

			When("the payload path points to a fake payload data (sent as a sample webhook data)", func() {
				It("should fail on json marshalling error", func() {
					// Arrange
					fs = fstest.MapFS{
						"payload.json": {
							Data: []byte(`{"event":{"id":"$ID","event_type":"pagey.ping","resource_type":"pagey","occurred_at":"DATE","agent":null,"client":null,"data":{"message":"Hello from your friend Pagey!","type":"ping"}}}`),
						},
					}
					// Act
					_, err := p.ExtractExternalIDFromPayload("payload.json", fs)
					// Assert
					Expect(err).Should(MatchError(pagerduty.UnmarshalErr{}))
				})
			})

			When("the payload path points to a sanitized payload and the api does not have the alert + incident", func() {
				It("should succeed and pull the externalid", func() {
					// Arrange
					fs = fstest.MapFS{
						"payload.json": {
							Data: []byte(`{"event":{"id":"$ID","event_type":"incident.triggered","resource_type":"incident","occurred_at":"DATE","agent":{"html_url":"https://$PD_HOST/users/$USER_ID","id":"$USER_ID","self":"https://api.pagerduty.com/users/$USER_ID","summary":"$USERNAME","type":"user_reference"},"client":null,"data":{"id":"1234","type":"incident","self":"https://api.pagerduty.com/incidents/$INCIDENT_ID","html_url":"https://$PD_HOST/incidents/$INCIDENT_ID","number":"${INCIDENT_NUMBER}","status":"triggered","incident_key":"${INCIDENT_KEY}","created_at":"DATE","title":"${INCIDENT_TITLE}","service":{"html_url":"https://$PD_HOST/services/$SERVICE_ID","id":"$SERVICE_ID","self":"https://api.pagerduty.com/services/$SERVICE_ID","summary":"$SERVICE_NAME","type":"service_reference"},"assignees":[{"html_url":"https://$PD_HOST/users/$USER_ID_2","id":"$USER_ID_2","self":"https://api.pagerduty.com/users/$USER_ID_2","summary":"$USER_NAME_2","type":"user_reference"}],"escalation_policy":{"html_url":"https://$PD_HOST/escalation_policies/$EP_ID","id":"$EP_ID","self":"https://api.pagerduty.com/escalation_policies/$EP_ID","summary":"$EP_NAME","type":"escalation_policy_reference"},"teams":[],"priority":null,"urgency":"high","conference_bridge":null,"resolve_reason":null}}}`),
						},
					}
					// Act
					_, err := p.ExtractExternalIDFromPayload("payload.json", fs)
					// Assert
					Expect(err).Should(MatchError(pagerduty.IncidentNotFoundErr{}))
				})
			})

			When("the payload path points to a sanitized payload and the api does not have the alert + incident", func() {
				It("should succeed and pull the externalid", func() {
					// Arrange
					mux.HandleFunc(fmt.Sprintf("/incidents/%s/alerts", incidentID), func(w http.ResponseWriter, r *http.Request) {
						// CHGM format of
						fmt.Fprint(w, `{"alerts":[{"id":"123456","body":{"details":{"notes":"cluster_id: 654321"}}}]}`)
					})
					fs = fstest.MapFS{
						"payload.json": {
							Data: []byte(`{"event":{"id":"$ID","event_type":"incident.triggered","resource_type":"incident","occurred_at":"DATE","agent":{"html_url":"https://$PD_HOST/users/$USER_ID","id":"$USER_ID","self":"https://api.pagerduty.com/users/$USER_ID","summary":"$USERNAME","type":"user_reference"},"client":null,"data":{"id":"1234","type":"incident","self":"https://api.pagerduty.com/incidents/$INCIDENT_ID","html_url":"https://$PD_HOST/incidents/$INCIDENT_ID","number":"${INCIDENT_NUMBER}","status":"triggered","incident_key":"${INCIDENT_KEY}","created_at":"DATE","title":"${INCIDENT_TITLE}","service":{"html_url":"https://$PD_HOST/services/$SERVICE_ID","id":"$SERVICE_ID","self":"https://api.pagerduty.com/services/$SERVICE_ID","summary":"$SERVICE_NAME","type":"service_reference"},"assignees":[{"html_url":"https://$PD_HOST/users/$USER_ID_2","id":"$USER_ID_2","self":"https://api.pagerduty.com/users/$USER_ID_2","summary":"$USER_NAME_2","type":"user_reference"}],"escalation_policy":{"html_url":"https://$PD_HOST/escalation_policies/$EP_ID","id":"$EP_ID","self":"https://api.pagerduty.com/escalation_policies/$EP_ID","summary":"$EP_NAME","type":"escalation_policy_reference"},"teams":[],"priority":null,"urgency":"high","conference_bridge":null,"resolve_reason":null}}}`),
						},
					}
					// Act
					res, err := p.ExtractExternalIDFromPayload("payload.json", fs)
					// Assert
					Expect(err).ShouldNot(HaveOccurred())
					Expect(res).Should(Equal("654321"))
				})
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

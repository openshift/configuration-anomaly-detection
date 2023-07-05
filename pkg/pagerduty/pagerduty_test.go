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
		mux                *http.ServeMux
		server             *httptest.Server
		p                  *pagerduty.SdkClient
		incidentID         string
		escalationPolicyID string
		silencePolicyID    string
	)
	BeforeEach(func() {
		// Arrange
		mux = http.NewServeMux()
		server = httptest.NewServer(mux)
		escalationPolicyID = "1234"
		silencePolicyID = "1234"
		// each startup of PagerDuty we need to verify the user's email for future requests
		mux.HandleFunc("/users/me", func(w http.ResponseWriter, r *http.Request) {
			Expect(r.Method).Should(Equal("GET"))
			fmt.Fprint(w, `{"user":{"email":"example@example.example"}}`)
		})
		var err error // err is declared to make clear the p is not created here, but is global
		p, err = pagerduty.NewWithToken(
			escalationPolicyID,
			silencePolicyID,
			[]byte(`{"event":{"id":"$ID","event_type":"incident.triggered","resource_type":"incident","occurred_at":"DATE","agent":{"html_url":"https://$PD_HOST/users/$USER_ID","id":"$USER_ID","self":"https://api.pagerduty.com/users/$USER_ID","summary":"$USERNAME","type":"user_reference"},"client":null,"data":{"id":"1234","type":"incident","self":"https://api.pagerduty.com/incidents/$INCIDENT_ID","html_url":"https://$PD_HOST/incidents/$INCIDENT_ID","number":"${INCIDENT_NUMBER}","status":"triggered","incident_key":"${INCIDENT_KEY}","created_at":"DATE","title":"${INCIDENT_TITLE}","service":{"html_url":"https://$PD_HOST/services/$SERVICE_ID","id":"$SERVICE_ID","self":"https://api.pagerduty.com/services/$SERVICE_ID","summary":"$SERVICE_NAME","type":"service_reference"},"assignees":[{"html_url":"https://$PD_HOST/users/$USER_ID_2","id":"$USER_ID_2","self":"https://api.pagerduty.com/users/$USER_ID_2","summary":"$USER_NAME_2","type":"user_reference"}],"escalation_policy":{"html_url":"https://$PD_HOST/escalation_policies/$EP_ID","id":"$EP_ID","self":"https://api.pagerduty.com/escalation_policies/$EP_ID","summary":"$EP_NAME","type":"escalation_policy_reference"},"teams":[],"priority":null,"urgency":"high","conference_bridge":null,"resolve_reason":null}}}`),
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
				err := p.MoveToEscalationPolicy(escalationPolicyID)
				// Assert
				Expect(err).Should(HaveOccurred())
				Expect(err).Should(MatchError(pagerduty.InvalidTokenError{}))
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
				err := p.MoveToEscalationPolicy(escalationPolicyID)
				// Assert
				Expect(err).Should(HaveOccurred())

				Expect(err).Should(MatchError(pagerduty.InvalidInputParamsError{}))
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
				err := p.MoveToEscalationPolicy(escalationPolicyID)
				// Assert
				Expect(err).ShouldNot(HaveOccurred())
			})
		})
	})
	Describe("AssignToUser", func() {
		var userID string
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
				err := p.AssignToUser(userID)
				// Assert
				Expect(err).Should(HaveOccurred())
				Expect(err).Should(MatchError(pagerduty.InvalidTokenError{}))
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
				err := p.AssignToUser(userID)
				// Assert
				Expect(err).Should(HaveOccurred())

				Expect(err).Should(MatchError(pagerduty.InvalidInputParamsError{}))
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
				err := p.AssignToUser(userID)
				// Assert
				Expect(err).ShouldNot(HaveOccurred())
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
				err := p.AcknowledgeIncident()
				// Assert
				Expect(err).Should(HaveOccurred())
				Expect(err).Should(MatchError(pagerduty.InvalidTokenError{}))
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
				err := p.AcknowledgeIncident()
				// Assert
				Expect(err).Should(HaveOccurred())

				Expect(err).Should(MatchError(pagerduty.InvalidInputParamsError{}))
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
				err := p.AcknowledgeIncident()
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
					fmt.Fprint(w, `{}`)
				})
				// Act
				err := p.AddNote(noteContent)
				// Assert
				Expect(err).Should(HaveOccurred())
				Expect(err).Should(MatchError(pagerduty.InvalidTokenError{}))
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
				err := p.AddNote(noteContent)
				// Assert
				Expect(err).Should(HaveOccurred())

				Expect(err).Should(MatchError(pagerduty.InvalidInputParamsError{}))
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
				Expect(err).Should(MatchError(pagerduty.IncidentNotFoundError{}))
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
					fmt.Fprint(w, `{}`)
				})
				// Act
				_, err := p.GetAlerts()
				// Assert
				Expect(err).Should(HaveOccurred())
				Expect(err).Should(MatchError(pagerduty.InvalidTokenError{}))
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
				_, err := p.GetAlerts()
				// Assert
				Expect(err).Should(HaveOccurred())

				Expect(err).Should(MatchError(pagerduty.InvalidInputParamsError{}))
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
				_, err := p.GetAlerts()
				// Assert
				Expect(err).Should(HaveOccurred())

				Expect(err).Should(MatchError(pagerduty.IncidentNotFoundError{}))
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
				res, err := p.GetAlerts()
				// Assert
				Expect(err).ShouldNot(HaveOccurred())
				Expect(res).Should(HaveLen(1))
				Expect(res[0].ID).Should(Equal("123456"))
				Expect(res[0].ExternalID).Should(Equal("123456"))
			})
		})
	})

	Describe("CreateNewAlert", func() {
		var (
			serviceID        string
			dmsIntegrationID string
			newAlert         pagerduty.NewAlert
		)
		BeforeEach(func() {
			serviceID = "service-id-12345"
			dmsIntegrationID = "integration-id-12345"
			newAlert = pagerduty.NewAlert{
				Description: "empty-description",
				Details: pagerduty.NewAlertDetails{
					ClusterID:  "testcluster",
					Error:      "",
					Resolution: "",
					SOP:        "",
				},
			}
		})
		When("The service cannot be retrieved", func() {
			It("should return a ServiceNotFoundError", func() {
				err := p.CreateNewAlert(newAlert, serviceID)
				Expect(err).To(HaveOccurred())
				Expect(err).To(MatchError(pagerduty.ServiceNotFoundError{}))
			})
		})
		When("The service has no Dead Man's Snitch integrations", func() {
			It("should return an IntegrationNotFoundError", func() {
				mux.HandleFunc(fmt.Sprintf("/services/%s", serviceID), func(w http.ResponseWriter, r *http.Request) {
					fmt.Fprintf(w, `{"service":{"id":"%s","integrations":[]}}`, serviceID)
				})
				err := p.CreateNewAlert(newAlert, serviceID)
				Expect(err).To(HaveOccurred())
				Expect(err).To(MatchError(pagerduty.IntegrationNotFoundError{}))
			})
		})
		When("The event creation fails", func() {
			It("should return a CreateEventError", func() {
				mux.HandleFunc(fmt.Sprintf("/services/%s", serviceID), func(w http.ResponseWriter, r *http.Request) {
					fmt.Fprintf(w, `{"service":{"id":"%s","integrations":[{"id":"%s"}]}}`, serviceID, dmsIntegrationID)
				})
				mux.HandleFunc(fmt.Sprintf("/services/%s/integrations/%s", serviceID, dmsIntegrationID), func(w http.ResponseWriter, r *http.Request) {
					fmt.Fprintf(w, `{"integration":{"id":"%s","name":"%s"}}`, dmsIntegrationID, pagerduty.CADIntegrationName)
				})
				err := p.CreateNewAlert(newAlert, serviceID)
				Expect(err).To(HaveOccurred())
				Expect(err).To(MatchError(pagerduty.CreateEventError{}))
			})
		})
	})
	Describe("NewWithToken", func() {
		When("the payload is empty", func() {
			It("should fail on UnmarshalError", func() {
				_, err := pagerduty.NewWithToken(
					escalationPolicyID,
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
				_, err := pagerduty.NewWithToken(
					escalationPolicyID,
					silencePolicyID,
					[]byte(`{"event":{"id":"$ID","event_type":"pagey.ping","resource_type":"pagey","occurred_at":"DATE","agent":null,"client":null,"data":{"message":"Hello from your friend Pagey!","type":"ping"}}}`),
					"fakeathtokenstring",
					sdk.WithAPIEndpoint(server.URL),
					sdk.WithV2EventsAPIEndpoint(server.URL),
				)
				Expect(err).Should(MatchError(pagerduty.UnmarshalError{}))
			})
		})
		When("the payload is missing the event type", func() {
			It("should fail on json marshalling error", func() {
				_, err := pagerduty.NewWithToken(
					escalationPolicyID,
					silencePolicyID,
					[]byte(`{"event":{"id":"$ID","resource_type":"pagey","occurred_at":"DATE","agent":null,"client":null,"data":{"message":"Hello from your friend Pagey!","type":"ping"}}}`),
					"fakeathtokenstring",
					sdk.WithAPIEndpoint(server.URL),
					sdk.WithV2EventsAPIEndpoint(server.URL),
				)
				Expect(err).Should(MatchError(pagerduty.UnmarshalError{}))
			})
		})
		When("the payload is missing the data field", func() {
			It("should fail on json marshalling error", func() {
				_, err := pagerduty.NewWithToken(
					escalationPolicyID,
					silencePolicyID,
					[]byte(`{"event":{"id":"$ID","event_type":"pagey.ping","resource_type":"pagey","occurred_at":"DATE","agent":null,"client":null}}`),
					"fakeathtokenstring",
					sdk.WithAPIEndpoint(server.URL),
					sdk.WithV2EventsAPIEndpoint(server.URL),
				)
				Expect(err).Should(MatchError(pagerduty.UnmarshalError{}))
			})
		})
	})

	// Describe("ExtractExternalIDFromCGHMAlertBody", func() {
	// 	var alertBody map[string]interface{}
	// 	BeforeEach(func() {
	// 		alertBody = map[string]interface{}{}
	// 	})

	// 	When("the '.details' field is of the wrong type", func() {
	// 		It("should raise a 'AlertBodyExternalCastError' error", func() {
	// 			// Arrange
	// 			alertBody = map[string]interface{}{
	// 				"details": "bad details",
	// 			}
	// 			expectedErr := pagerduty.AlertBodyExternalCastError{
	// 				FailedProperty:     ".details",
	// 				ExpectedType:       "map[string]interface{}",
	// 				ActualType:         "string",
	// 				ActualBodyResource: "bad details",
	// 			}
	// 			// Act
	// 			_, err := p.ExtractIDFromCHGM(alertBody)
	// 			// Assert
	// 			Expect(err).Should(HaveOccurred())
	// 			Expect(err).Should(MatchError(expectedErr))
	// 		})
	// 	})
	// 	When("the '.details.notes' field is of the wrong type", func() {
	// 		It("should raise a 'AlertBodyExternalCastError' error", func() {
	// 			// Arrange
	// 			alertBody = map[string]interface{}{
	// 				"details": map[string]interface{}{
	// 					"notes": map[string]interface{}{
	// 						"hello": "world",
	// 					},
	// 				},
	// 			}
	// 			expectedErr := pagerduty.AlertBodyExternalCastError{
	// 				FailedProperty:     ".details.notes",
	// 				ExpectedType:       "string",
	// 				ActualType:         "map[string]interface {}",
	// 				ActualBodyResource: "map[hello:world]",
	// 			}
	// 			// Act
	// 			_, err := p.ExtractIDFromCHGM(alertBody)
	// 			// Assert
	// 			Expect(err).Should(HaveOccurred())
	// 			Expect(err).Should(MatchError(expectedErr))
	// 		})
	// 	})

	// 	When("the notes field is improperly parsed by the 'yaml' package", func() {
	// 		It("should raise a 'NotesParseError' error", func() {
	// 			// Arrange
	// 			alertBody = map[string]interface{}{
	// 				"details": map[string]interface{}{
	// 					"notes": "chicken",
	// 				},
	// 			}
	// 			// Act
	// 			_, err := p.ExtractIDFromCHGM(alertBody)
	// 			// Assert
	// 			Expect(err).Should(HaveOccurred())
	// 			Expect(err).Should(MatchError(pagerduty.NotesParseError{}))
	// 		})
	// 	})

	// 	When("the notes field has a clusterid", func() {
	// 		It("should be returned correctly", func() {
	// 			// Arrange
	// 			alertBody = map[string]interface{}{
	// 				"details": map[string]interface{}{
	// 					"notes": `cluster_id: "12345"`,
	// 				},
	// 			}
	// 			// Act
	// 			res, err := p.ExtractIDFromCHGM(alertBody)
	// 			// Assert
	// 			Expect(err).ShouldNot(HaveOccurred())
	// 			Expect(res).Should(Equal("12345"))
	// 		})
	// 	})
	// })
	Describe("Receiver", func() {
		Describe("RetrieveExternalClusterID", func() {
			When("the payload path points to a sanitized payload and the api does not have the alert + incident", func() {
				It("should succeed and pull the externalid", func() {
					// Arrange
					p, _ := pagerduty.NewWithToken(
						escalationPolicyID,
						silencePolicyID,
						[]byte(`{"event":{"id":"$ID","event_type":"incident.triggered","resource_type":"incident","occurred_at":"DATE","agent":{"html_url":"https://$PD_HOST/users/$USER_ID","id":"$USER_ID","self":"https://api.pagerduty.com/users/$USER_ID","summary":"$USERNAME","type":"user_reference"},"client":null,"data":{"id":"1234","type":"incident","self":"https://api.pagerduty.com/incidents/$INCIDENT_ID","html_url":"https://$PD_HOST/incidents/$INCIDENT_ID","number":"${INCIDENT_NUMBER}","status":"triggered","incident_key":"${INCIDENT_KEY}","created_at":"DATE","title":"${INCIDENT_TITLE}","service":{"html_url":"https://$PD_HOST/services/$SERVICE_ID","id":"$SERVICE_ID","self":"https://api.pagerduty.com/services/$SERVICE_ID","summary":"$SERVICE_NAME","type":"service_reference"},"assignees":[{"html_url":"https://$PD_HOST/users/$USER_ID_2","id":"$USER_ID_2","self":"https://api.pagerduty.com/users/$USER_ID_2","summary":"$USER_NAME_2","type":"user_reference"}],"escalation_policy":{"html_url":"https://$PD_HOST/escalation_policies/$EP_ID","id":"$EP_ID","self":"https://api.pagerduty.com/escalation_policies/$EP_ID","summary":"$EP_NAME","type":"escalation_policy_reference"},"teams":[],"priority":null,"urgency":"high","conference_bridge":null,"resolve_reason":null}}}`),
						"fakeathtokenstring",
						sdk.WithAPIEndpoint(server.URL),
						sdk.WithV2EventsAPIEndpoint(server.URL),
					)
					// Act
					_, err := p.RetrieveExternalClusterID()
					// Assert
					Expect(err).Should(MatchError(pagerduty.IncidentNotFoundError{}))
				})
			})
			When("the payload is valid and the api does have the alert + incident", func() {
				It("should succeed and pull the externalid", func() {
					// Arrange
					mux.HandleFunc(fmt.Sprintf("/incidents/%s/alerts", incidentID), func(w http.ResponseWriter, r *http.Request) {
						// CHGM format of
						fmt.Fprint(w, `{"alerts":[{"id":"1234","body":{"details":{"notes":"cluster_id: 654321"}}}]}`)
					})
					// Act
					res, err := p.RetrieveExternalClusterID()
					// Assert
					Expect(err).ShouldNot(HaveOccurred())
					Expect(res).Should(Equal("654321"))
				})
			})
			When("the alert body does not have a 'details' field", func() {
				It("should raise an 'AlertBodyDoesNotHaveDetailsFieldErr' error", func() {
					mux.HandleFunc(fmt.Sprintf("/incidents/%s/alerts", incidentID), func(w http.ResponseWriter, r *http.Request) {
						// CHGM format of
						fmt.Fprint(w, `{"alerts":[{"id":"1234","body":{"describe":{"chicken": 1.75},"steak":true}}]}`)
					})
					// Act
					_, err := p.RetrieveExternalClusterID()
					// Assert
					Expect(err).Should(HaveOccurred())
					Expect(err).Should(MatchError(pagerduty.AlertBodyExternalParseError{FailedProperty: ".details"}))
				})
			})
			When("the '.details' field is of the wrong type", func() {
				It("should raise a 'AlertBodyExternalCastError' error", func() {
					mux.HandleFunc(fmt.Sprintf("/incidents/%s/alerts", incidentID), func(w http.ResponseWriter, r *http.Request) {
						fmt.Fprint(w, `{"alerts":[{"id":"1234","body":{"details":"bad details"}}]}`)
					})
					expectedErr := pagerduty.AlertBodyExternalCastError{
						FailedProperty:     ".details",
						ExpectedType:       "map[string]interface{}",
						ActualType:         "string",
						ActualBodyResource: "bad details",
					}

					_, err := p.RetrieveExternalClusterID()

					Expect(err).Should(HaveOccurred())
					Expect(err).Should(MatchError(expectedErr))
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

package pagerduty

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	sdk "github.com/PagerDuty/go-pagerduty"
)

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
				err := p.MoveToEscalationPolicy(escalationPolicyID)
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
				err := p.MoveToEscalationPolicy(escalationPolicyID)
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
				err := p.MoveToEscalationPolicy(escalationPolicyID)
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

func TestParseFiringJSON(t *testing.T) {
	tests := []struct {
		name          string
		input         string
		expectedCount int
		expectErr     bool
	}{
		{
			name:          "single alert",
			input:         mustMarshal([]FiringAlert{{Labels: map[string]string{"alertname": "KubePersistentVolumeFillingUp", "namespace": "openshift-monitoring", "severity": "critical"}}}),
			expectedCount: 1,
		},
		{
			name:          "empty string",
			input:         "",
			expectedCount: 0,
		},
		{
			name:      "invalid JSON",
			input:     "not json",
			expectErr: true,
		},
		{
			name:          "empty array",
			input:         "[]",
			expectedCount: 0,
		},
		{
			name:          "multiple firing alerts",
			input:         mustMarshal([]FiringAlert{{Labels: map[string]string{"alertname": "Alert1", "namespace": "ns1"}}, {Labels: map[string]string{"alertname": "Alert2", "namespace": "ns2"}}}),
			expectedCount: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseFiringJSON(tt.input)

			if tt.expectErr {
				if err == nil {
					t.Error("Expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
			if len(result) != tt.expectedCount {
				t.Errorf("Expected %d alerts, got %d", tt.expectedCount, len(result))
			}
		})
	}
}

// TestParseFiringJSONFromRealPDResponse simulates how PagerDuty's API actually
// delivers firing_json — as deserialized JSON ([]interface{}) not a string.
// Test data is from a real ConfigureAlertmanagerOperatorOfflineSRE alert with
// sensitive fields scrubbed.
func TestParseFiringJSONFromRealPDResponse(t *testing.T) {
	// This is what Go's encoding/json produces when it deserializes the PD alert
	// body — firing_json is []interface{}, num_firing is float64, not strings.
	scrubbedPDAlertBody := `{
		"alert_name": "ConfigureAlertmanagerOperatorOfflineSRE",
		"cluster_id": "test-cluster-id-0000-0000-000000000000",
		"firing": [
			{
				"annotations": {},
				"endsAt": "0001-01-01T00:00:00Z",
				"fingerprint": "abc123",
				"labels": {
					"alertname": "ConfigureAlertmanagerOperatorOfflineSRE",
					"namespace": "openshift-monitoring",
					"openshift_io_alert_source": "platform",
					"prometheus": "openshift-monitoring/k8s",
					"service": "configure-alertmanager-operator",
					"severity": "critical"
				},
				"startsAt": "2026-07-23T20:19:08.743Z",
				"status": "firing"
			}
		],
		"firing_json": [
			{
				"annotations": {},
				"endsAt": "0001-01-01T00:00:00Z",
				"fingerprint": "abc123",
				"labels": {
					"alertname": "ConfigureAlertmanagerOperatorOfflineSRE",
					"namespace": "openshift-monitoring",
					"openshift_io_alert_source": "platform",
					"prometheus": "openshift-monitoring/k8s",
					"service": "configure-alertmanager-operator",
					"severity": "critical"
				},
				"startsAt": "2026-07-23T20:19:08.743Z",
				"status": "firing"
			}
		],
		"link": "https://github.com/openshift/ops-sop/tree/master/v4/alerts/ConfigureAlertmanagerOperatorOfflineSRE.md",
		"num_firing": 1,
		"num_resolved": 0,
		"ocm_link": "https://console.redhat.com/openshift/details/test-cluster-id",
		"region": "us-east-1",
		"resolved": null
	}`

	// Deserialize the same way Go's PD SDK does — into map[string]interface{}
	var details map[string]interface{}
	if err := json.Unmarshal([]byte(scrubbedPDAlertBody), &details); err != nil {
		t.Fatalf("Failed to unmarshal test data: %v", err)
	}

	// Verify firing_json is []interface{}, not string — this is the bug we caught
	if _, ok := details["firing_json"].(string); ok {
		t.Fatal("firing_json should be []interface{} after JSON deserialization, not string")
	}
	if _, ok := details["firing_json"].([]interface{}); !ok {
		t.Fatalf("firing_json should be []interface{}, got %T", details["firing_json"])
	}

	// Verify num_firing is float64, not string
	if _, ok := details["num_firing"].(string); ok {
		t.Fatal("num_firing should be float64 after JSON deserialization, not string")
	}

	// Test stringFromDetails handles numeric values
	numFiring := stringFromDetails(details, "num_firing")
	if numFiring != "1" {
		t.Errorf("stringFromDetails(num_firing) = %q, want \"1\"", numFiring)
	}
	numResolved := stringFromDetails(details, "num_resolved")
	if numResolved != "0" {
		t.Errorf("stringFromDetails(num_resolved) = %q, want \"0\"", numResolved)
	}

	// Test stringFromDetails still works for actual strings
	link := stringFromDetails(details, "link")
	if link != "https://github.com/openshift/ops-sop/tree/master/v4/alerts/ConfigureAlertmanagerOperatorOfflineSRE.md" {
		t.Errorf("stringFromDetails(link) = %q, want SOP URL", link)
	}

	// Test the firing_json extraction path — re-marshal []interface{} then parse
	raw := details["firing_json"]
	jsonBytes, err := json.Marshal(raw)
	if err != nil {
		t.Fatalf("Failed to re-marshal firing_json: %v", err)
	}

	alerts, err := ParseFiringJSON(string(jsonBytes))
	if err != nil {
		t.Fatalf("ParseFiringJSON failed: %v", err)
	}
	if len(alerts) != 1 {
		t.Fatalf("Expected 1 alert, got %d", len(alerts))
	}

	alert := alerts[0]
	if alert.Labels["alertname"] != "ConfigureAlertmanagerOperatorOfflineSRE" {
		t.Errorf("alertname = %q, want ConfigureAlertmanagerOperatorOfflineSRE", alert.Labels["alertname"])
	}
	if alert.Labels["namespace"] != "openshift-monitoring" {
		t.Errorf("namespace = %q, want openshift-monitoring", alert.Labels["namespace"])
	}
	if alert.Labels["severity"] != "critical" {
		t.Errorf("severity = %q, want critical", alert.Labels["severity"])
	}
	if alert.StartsAt != "2026-07-23T20:19:08.743Z" {
		t.Errorf("startsAt = %q, want 2026-07-23T20:19:08.743Z", alert.StartsAt)
	}
}

// TestParseFiringJSONMultiAlertIncident verifies parsing when a single PD
// incident contains multiple firing alerts with different alertnames — a
// real-world scenario where alerts group into one incident.
func TestParseFiringJSONMultiAlertIncident(t *testing.T) {
	multiAlertDetails := `{
		"firing_json": [
			{
				"labels": {
					"alertname": "KubePersistentVolumeFillingUp",
					"namespace": "openshift-monitoring",
					"persistentvolumeclaim": "prometheus-data-prometheus-k8s-0",
					"severity": "critical"
				},
				"annotations": {
					"summary": "PersistentVolume is filling up.",
					"runbook_url": "https://github.com/openshift/ops-sop/blob/master/v4/alerts/KubePersistentVolumeFillingUp.md"
				},
				"startsAt": "2026-07-23T10:00:00.000Z",
				"status": "firing"
			},
			{
				"labels": {
					"alertname": "KubePersistentVolumeFillingUp",
					"namespace": "openshift-monitoring",
					"persistentvolumeclaim": "prometheus-data-prometheus-k8s-1",
					"severity": "critical"
				},
				"annotations": {
					"summary": "PersistentVolume is filling up.",
					"runbook_url": "https://github.com/openshift/ops-sop/blob/master/v4/alerts/KubePersistentVolumeFillingUp.md"
				},
				"startsAt": "2026-07-23T10:01:00.000Z",
				"status": "firing"
			},
			{
				"labels": {
					"alertname": "PrometheusRemoteWriteBehind",
					"namespace": "openshift-monitoring",
					"severity": "warning"
				},
				"annotations": {
					"summary": "Prometheus remote write is behind.",
					"runbook_url": "https://github.com/openshift/ops-sop/blob/master/v4/alerts/PrometheusRemoteWriteBehind.md"
				},
				"startsAt": "2026-07-23T10:05:00.000Z",
				"status": "firing"
			}
		],
		"num_firing": 3
	}`

	var details map[string]interface{}
	if err := json.Unmarshal([]byte(multiAlertDetails), &details); err != nil {
		t.Fatalf("Failed to unmarshal test data: %v", err)
	}

	// Re-marshal the []interface{} back to JSON (simulating the extraction path)
	jsonBytes, err := json.Marshal(details["firing_json"])
	if err != nil {
		t.Fatalf("Failed to re-marshal firing_json: %v", err)
	}

	alerts, err := ParseFiringJSON(string(jsonBytes))
	if err != nil {
		t.Fatalf("ParseFiringJSON failed: %v", err)
	}

	if len(alerts) != 3 {
		t.Fatalf("Expected 3 alerts, got %d", len(alerts))
	}

	// Verify different alertnames are preserved
	alertNames := map[string]int{}
	for _, a := range alerts {
		alertNames[a.Labels["alertname"]]++
	}
	if alertNames["KubePersistentVolumeFillingUp"] != 2 {
		t.Errorf("Expected 2 KubePersistentVolumeFillingUp alerts, got %d", alertNames["KubePersistentVolumeFillingUp"])
	}
	if alertNames["PrometheusRemoteWriteBehind"] != 1 {
		t.Errorf("Expected 1 PrometheusRemoteWriteBehind alert, got %d", alertNames["PrometheusRemoteWriteBehind"])
	}

	// Verify annotations (including runbook_url) are preserved
	if alerts[0].Annotations["runbook_url"] != "https://github.com/openshift/ops-sop/blob/master/v4/alerts/KubePersistentVolumeFillingUp.md" {
		t.Errorf("runbook_url not preserved on first alert")
	}
	if alerts[2].Annotations["runbook_url"] != "https://github.com/openshift/ops-sop/blob/master/v4/alerts/PrometheusRemoteWriteBehind.md" {
		t.Errorf("runbook_url not preserved on third alert")
	}
}

func mustMarshal(v interface{}) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(b)
}

/*
these were pulled from https://github.com/PagerDuty/go-pagerduty/blob/c6785b92c2c4e24a0009298ad2b9bc457e6df1e7/client.go, if you need the other functions feel free to re-import them
*/

// HTTPClient is an interface which declares the functionality we need from an
// HTTP client. This is to allow consumers to provide their own HTTP client as
// needed, without restricting them to only using *http.Client.
type HTTPClient interface {
	Do(*http.Request) (*http.Response, error)
}

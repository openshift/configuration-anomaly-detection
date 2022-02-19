package main

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"

	sdk "github.com/PagerDuty/go-pagerduty"
)

func main() {
	//Encode the data
	p := sdk.WebhookPayload{
		ID:    "123abc",
		Event: "hi321",
		Incident: sdk.IncidentDetails{
			IncidentNumber: 1324,
			Title:          "hello!",
		},
		LogEntries: []sdk.LogEntry{{
			CommonLogEntryField: sdk.CommonLogEntryField{},
			Incident: sdk.Incident{
				IncidentNumber: 5678,
				Title:          "goodbye?",
			},
			Service: sdk.APIObject{
				ID:   "s123",
				Type: "service_reference",
			},
			User: sdk.APIObject{
				ID:   "u123",
				Type: "user_reference",
			},
		}},
	}
	postBody, err := json.Marshal(p)
	if err != nil {
		// %w is not supported in log.Fatalf :(
		log.Fatalf("cannot marshal WebhookPayload: %v", err)
	}
	requestBody := bytes.NewBuffer(postBody)
	//Leverage Go's HTTP Post function to make request
	// use postman-echo.com/post to show we can send and recieve
	//resp, err := http.Post("https://postman-echo.com/post", "application/json", responseBody)
	resp, err := http.Post("http://localhost:8080", "application/json", requestBody)

	//Handle Error
	if err != nil {
		log.Fatalf("An Error Occured %v", err)
	}
	defer resp.Body.Close()
	//Read the response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatalln(err)
	}
	sb := string(body)
	log.Printf(sb)
}

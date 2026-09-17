package aws_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	cloudtrail "github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	cloudtrailtypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"go.uber.org/mock/gomock"

	cadaws "github.com/openshift/configuration-anomaly-detection/pkg/aws"
	awsmock "github.com/openshift/configuration-anomaly-detection/pkg/aws/mock"
)

func TestCollectCloudTrailEventsBoundsAndDeduplicates(t *testing.T) {
	ctrl := gomock.NewController(t)
	client := awsmock.NewMockCloudTrailAPI(ctrl)
	start := time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)
	end := start.Add(2 * time.Hour)
	next := "next"
	client.EXPECT().LookupEvents(gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, in *cloudtrail.LookupEventsInput, _ ...func(*cloudtrail.Options)) (*cloudtrail.LookupEventsOutput, error) {
		if in.MaxResults == nil || *in.MaxResults != 50 || !in.StartTime.Equal(start) || !in.EndTime.Equal(end) {
			t.Fatalf("unexpected fixed lookup window or page size: %#v", in)
		}
		return &cloudtrail.LookupEventsOutput{Events: []cloudtrailtypes.Event{
			{EventId: awsv2.String("one"), CloudTrailEvent: awsv2.String(`{"eventID":"one","eventName":"CreateThing","secret":"remove"}`)},
			{EventId: awsv2.String("one"), CloudTrailEvent: awsv2.String(`{"eventID":"one","eventName":"duplicate"}`)},
		}, NextToken: &next}, nil
	}).Times(1)
	client.EXPECT().LookupEvents(gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, in *cloudtrail.LookupEventsInput, _ ...func(*cloudtrail.Options)) (*cloudtrail.LookupEventsOutput, error) {
		if in.NextToken == nil || *in.NextToken != next {
			t.Fatalf("next token was not carried forward")
		}
		return &cloudtrail.LookupEventsOutput{Events: []cloudtrailtypes.Event{
			{EventId: awsv2.String("two"), CloudTrailEvent: awsv2.String(`{"eventID":"two","requestParameters":{"password":"remove","name":"kept"}}`)},
		}}, nil
	}).Times(1)

	c := &cadaws.SdkClient{CloudtrailClient: client}
	got, err := c.CollectCloudTrailEvents(context.Background(), cadaws.CloudTrailCollectionOptions{StartTime: start, EndTime: end, MaxEvents: 10, Sleep: func(context.Context, time.Duration) error { return nil }})
	if err != nil {
		t.Fatalf("CollectCloudTrailEvents() error = %v", err)
	}
	if got.Status != "complete" || got.StopReason != "pagination_exhausted" || got.EventCount != 2 {
		t.Fatalf("unexpected collection metadata: %+v", got)
	}
	var first, second map[string]any
	if err := json.Unmarshal(got.Events[0].Data, &first); err != nil {
		t.Fatal(err)
	}
	if _, ok := first["secret"]; ok {
		t.Fatal("sensitive field was retained")
	}
	if err := json.Unmarshal(got.Events[1].Data, &second); err != nil {
		t.Fatal(err)
	}
	if _, ok := second["requestParameters"].(map[string]any)["password"]; ok {
		t.Fatal("nested sensitive field was retained")
	}
}

func TestCollectCloudTrailEventsReturnsPartialOnPageFailure(t *testing.T) {
	ctrl := gomock.NewController(t)
	client := awsmock.NewMockCloudTrailAPI(ctrl)
	next := "next"
	client.EXPECT().LookupEvents(gomock.Any(), gomock.Any()).Return(&cloudtrail.LookupEventsOutput{Events: []cloudtrailtypes.Event{{EventId: awsv2.String("one")}}, NextToken: &next}, nil)
	client.EXPECT().LookupEvents(gomock.Any(), gomock.Any()).Return(nil, errors.New("throttled")).Times(3)
	c := &cadaws.SdkClient{CloudtrailClient: client}
	got, err := c.CollectCloudTrailEvents(context.Background(), cadaws.CloudTrailCollectionOptions{Sleep: func(context.Context, time.Duration) error { return nil }})
	if err == nil {
		t.Fatal("expected page failure")
	}
	if got.Status != "partial" || got.StopReason != "api_error" || got.EventCount != 1 {
		t.Fatalf("unexpected partial collection: %+v", got)
	}
}

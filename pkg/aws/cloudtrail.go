package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	cloudtrail "github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	cloudtrailtypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
)

const (
	CloudTrailPageSize    = 50
	CloudTrailMaxEvents   = 2000
	CloudTrailMaxLookback = 120 * time.Minute
)

type CloudTrailCollectionOptions struct {
	StartTime time.Time
	EndTime   time.Time
	MaxEvents int
	MaxBytes  int
	// AccountID and Region describe the account/region scope queried. They are
	// metadata only; LookupEvents uses the credentials and region on the client.
	AccountID string
	Region    string
	Sleep     func(context.Context, time.Duration) error
}

type CloudTrailEvent struct {
	Data                 json.RawMessage
	EventID              string     `json:"event_id,omitempty"`
	EventTime            *time.Time `json:"event_time,omitempty"`
	RawDetailParseFailed bool       `json:"raw_detail_parse_failed,omitempty"`
}

type CloudTrailCollection struct {
	Status              string            `json:"status"`
	StopReason          string            `json:"stop_reason"`
	StartTime           time.Time         `json:"start_time"`
	EndTime             time.Time         `json:"end_time"`
	CollectedAt         time.Time         `json:"collected_at"`
	AccountID           string            `json:"account_id,omitempty"`
	Region              string            `json:"region,omitempty"`
	EventCount          int               `json:"event_count"`
	ByteCount           int               `json:"byte_count"`
	MalformedEventCount int               `json:"malformed_event_count"`
	Events              []CloudTrailEvent `json:"events"`
	ErrorCategory       string            `json:"error_category,omitempty"`
}

// CollectCloudTrailEvents retrieves the newest management events in one fixed
// window. The returned collection is useful even when the final page fails.
func (c *SdkClient) CollectCloudTrailEvents(ctx context.Context, options CloudTrailCollectionOptions) (CloudTrailCollection, error) {
	now := time.Now().UTC()
	if options.EndTime.IsZero() {
		options.EndTime = now
	}
	if options.StartTime.IsZero() {
		options.StartTime = options.EndTime.Add(-CloudTrailMaxLookback)
	}
	if options.MaxEvents <= 0 || options.MaxEvents > CloudTrailMaxEvents {
		options.MaxEvents = CloudTrailMaxEvents
	}
	if options.MaxBytes < 0 {
		options.MaxBytes = 0
	}
	if options.Sleep == nil {
		options.Sleep = sleepContext
	}

	collection := CloudTrailCollection{
		Status: "complete", StopReason: "pagination_exhausted", StartTime: options.StartTime.UTC(),
		EndTime: options.EndTime.UTC(), CollectedAt: now, AccountID: options.AccountID,
		Region: options.Region, Events: make([]CloudTrailEvent, 0),
	}
	if c.CloudtrailClient == nil {
		collection.Status, collection.StopReason, collection.ErrorCategory = "unavailable", "api_error", "client_unavailable"
		return collection, fmt.Errorf("cloudtrail client is nil")
	}

	seenTokens := map[string]struct{}{}
	seenEvents := map[string]struct{}{}
	var token *string
	firstPage := true
	for {
		if err := ctx.Err(); err != nil {
			collection.Status, collection.StopReason, collection.ErrorCategory = statusForPartial(collection), "timeout", "context_canceled"
			return collection, err
		}
		if !firstPage {
			if err := options.Sleep(ctx, 500*time.Millisecond); err != nil {
				collection.Status, collection.StopReason, collection.ErrorCategory = statusForPartial(collection), "timeout", "context_canceled"
				return collection, err
			}
		}
		firstPage = false
		input := &cloudtrail.LookupEventsInput{StartTime: awsv2.Time(options.StartTime), EndTime: awsv2.Time(options.EndTime), MaxResults: awsv2.Int32(CloudTrailPageSize), NextToken: token}
		output, err := lookupWithRetry(ctx, c.CloudtrailClient, input)
		if err != nil {
			if ctx.Err() != nil {
				collection.Status, collection.StopReason, collection.ErrorCategory = statusForPartial(collection), "timeout", "context_canceled"
				return collection, ctx.Err()
			}
			collection.Status, collection.StopReason, collection.ErrorCategory = statusForPartial(collection), "api_error", "lookup_events_failed"
			return collection, err
		}
		for _, event := range output.Events {
			id := awsv2.ToString(event.EventId)
			if id != "" {
				if _, ok := seenEvents[id]; ok {
					continue
				}
				seenEvents[id] = struct{}{}
			}
			if len(collection.Events) >= options.MaxEvents {
				collection.Status, collection.StopReason = "partial", "event_limit"
				return collection, nil
			}
			item, malformed := normalizeCloudTrailEvent(event)
			if collection.AccountID == "" {
				if accountID, ok := item["recipientAccountId"].(string); ok {
					collection.AccountID = accountID
				}
			}
			line, marshalErr := json.Marshal(item)
			if marshalErr != nil {
				continue
			}
			if options.MaxBytes > 0 && collection.ByteCount+len(line)+1 > options.MaxBytes {
				collection.Status, collection.StopReason = "partial", "byte_limit"
				return collection, nil
			}
			collection.Events = append(collection.Events, CloudTrailEvent{Data: line, EventID: id, EventTime: event.EventTime, RawDetailParseFailed: malformed})
			collection.EventCount = len(collection.Events)
			collection.ByteCount += len(line) + 1
			if malformed {
				collection.MalformedEventCount++
			}
		}
		if len(collection.Events) >= options.MaxEvents && output.NextToken != nil && awsv2.ToString(output.NextToken) != "" {
			collection.Status, collection.StopReason = "partial", "event_limit"
			return collection, nil
		}
		if output.NextToken == nil || awsv2.ToString(output.NextToken) == "" {
			return collection, nil
		}
		next := awsv2.ToString(output.NextToken)
		if _, ok := seenTokens[next]; ok {
			collection.Status, collection.StopReason, collection.ErrorCategory = statusForPartial(collection), "api_error", "repeated_pagination_token"
			return collection, fmt.Errorf("cloudtrail returned a repeated pagination token")
		}
		seenTokens[next] = struct{}{}
		token = output.NextToken
	}
}

func lookupWithRetry(ctx context.Context, client CloudTrailAPI, input *cloudtrail.LookupEventsInput) (*cloudtrail.LookupEventsOutput, error) {
	var err error
	for attempt := 0; attempt < 3; attempt++ {
		var output *cloudtrail.LookupEventsOutput
		output, err = client.LookupEvents(ctx, input)
		if err == nil {
			return output, nil
		}
		if attempt < 2 {
			// Keep every retry at least 500ms after the previous request. Together
			// with the page pacing this stays within LookupEvents' two-per-second limit.
			delay := 500 * time.Millisecond
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return nil, ctx.Err()
			case <-timer.C:
			}
		}
	}
	return nil, err
}

func normalizeCloudTrailEvent(event cloudtrailtypes.Event) (map[string]any, bool) {
	if event.CloudTrailEvent != nil {
		var value map[string]any
		if err := json.Unmarshal([]byte(*event.CloudTrailEvent), &value); err == nil {
			return sanitizeCloudTrailMap(value), false
		}
	}
	return sanitizeCloudTrailMap(map[string]any{
		"eventID": awsv2.ToString(event.EventId), "eventName": awsv2.ToString(event.EventName),
		"eventSource": awsv2.ToString(event.EventSource), "eventTime": event.EventTime,
		"readOnly": awsv2.ToString(event.ReadOnly), "userName": awsv2.ToString(event.Username),
	}), true
}

func sanitizeCloudTrailMap(input map[string]any) map[string]any {
	return sanitizeCloudTrailMapWithContext(input, false)
}

var safeCloudTrailValue = regexp.MustCompile(`^(arn:aws:[^\s]+|arn:aws-us-gov:[^\s]+|arn:aws-cn:[^\s]+|(?:i|vpc|subnet|sg|eni|nat|igw|rtb|vol|snap|ami|acl|route|lb|targetgroup)-[A-Za-z0-9._:/-]+|[a-z]{2}(?:-gov)?-[a-z]+-\d)$`)

func sanitizeCloudTrailMapWithContext(input map[string]any, restricted bool) map[string]any {
	output := make(map[string]any, len(input))
	for key, value := range input {
		lower := strings.ToLower(key)
		if strings.Contains(lower, "secret") || strings.Contains(lower, "password") || strings.Contains(lower, "token") || strings.Contains(lower, "credential") || strings.Contains(lower, "accesskey") || lower == "authorization" {
			continue
		}
		childRestricted := restricted || lower == "requestparameters" || lower == "responseelements" || lower == "additionaleventdata"
		switch typed := value.(type) {
		case map[string]any:
			output[key] = sanitizeCloudTrailMapWithContext(typed, childRestricted)
		case []any:
			items := make([]any, 0, len(typed))
			for _, item := range typed {
				if sanitized, ok := sanitizeCloudTrailValue(item, childRestricted); ok {
					items = append(items, sanitized)
				}
			}
			output[key] = items
		case string:
			if !restricted || safeCloudTrailValue.MatchString(typed) {
				output[key] = typed
			}
		default:
			if !restricted {
				output[key] = value
			}
		}
	}
	return output
}

func sanitizeCloudTrailValue(value any, restricted bool) (any, bool) {
	switch typed := value.(type) {
	case map[string]any:
		return sanitizeCloudTrailMapWithContext(typed, restricted), true
	case []any:
		items := make([]any, 0, len(typed))
		for _, item := range typed {
			if sanitized, ok := sanitizeCloudTrailValue(item, restricted); ok {
				items = append(items, sanitized)
			}
		}
		return items, true
	case string:
		if !restricted || safeCloudTrailValue.MatchString(typed) {
			return typed, true
		}
		return nil, false
	default:
		return value, !restricted
	}
}

func statusForPartial(collection CloudTrailCollection) string {
	if len(collection.Events) == 0 {
		return "unavailable"
	}
	return "partial"
}

func sleepContext(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

package backplanemock

import (
	"context"
	"time"

	cmv1 "github.com/openshift-online/ocm-sdk-go/clustersmgmt/v1"
	bpapi "github.com/openshift/backplane-api/pkg/client"
	"github.com/openshift/configuration-anomaly-detection/pkg/backplane"
	"github.com/segmentio/ksuid"
)

// MockClient is a stub implementation of the backplane client
type MockClient struct{}

func (m *MockClient) CreateReport(_ context.Context, _ string, summary string, reportData string) (*bpapi.Report, error) {
	return &bpapi.Report{
		Summary:   summary,
		Data:      reportData,
		ReportId:  ksuid.New().String(),
		CreatedAt: time.Now(),
	}, nil
}

func (m *MockClient) GetRestConfig(_ context.Context, _ string, _ string, _ bool) (*backplane.RestConfig, error) {
	return &backplane.RestConfig{
		Cleaner: backplane.CleanerFunc(func() error { return nil }),
	}, nil
}

func (m *MockClient) GetAWSCredentials(_ context.Context, _ string, region string) (*backplane.AWSCredentials, error) {
	return &backplane.AWSCredentials{
		AccessKeyID:     "mock-access-key-id",
		SecretAccessKey: "mock-secret-access-key",
		SessionToken:    "mock-session-token",
		Expiration:      time.Now().Add(1 * time.Hour).String(),
		Region:          region,
	}, nil
}

func (m *MockClient) GetIsolatedAWSCredentials(_ context.Context, cluster *cmv1.Cluster, _ string, _ string) (*backplane.AWSCredentials, error) {
	region := "us-east-1"
	if cluster != nil && cluster.Region() != nil {
		region = cluster.Region().ID()
	}
	return &backplane.AWSCredentials{
		AccessKeyID:     "mock-isolated-access-key-id",
		SecretAccessKey: "mock-isolated-secret-access-key",
		SessionToken:    "mock-isolated-session-token",
		Expiration:      time.Now().Add(1 * time.Hour).String(),
		Region:          region,
	}, nil
}

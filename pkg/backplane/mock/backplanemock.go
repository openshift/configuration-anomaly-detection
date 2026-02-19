package backplanemock

import (
	"context"
	"time"

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

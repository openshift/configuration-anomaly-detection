package reports

import (
	"context"
	"fmt"
	"testing"
	"time"

	bpapi "github.com/openshift/backplane-api/pkg/client"
	"github.com/stretchr/testify/assert"
)

const mockReportId = "abc-123"

func Test_NewReport(t *testing.T) {
	input := &Input{
		ClusterID: "123-456-789",
		Summary:   "a test report",
		Data:      "some test data",
	}
	ctx := context.Background()

	report, err := New(ctx, &mock{}, input)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, "123-456-789", report.ClusterID)

	note := report.GenerateStringForNoteWriter()
	assert.Equal(t, fmt.Sprintf("CAD created a cluster report, access it with the following command:\n"+
		"osdctl cluster reports get --cluster-id 123-456-789 --report-id %s", mockReportId), note)
}

type mock struct{}

func (m *mock) CreateReport(_ context.Context, _ string, summary string, reportData string) (*bpapi.Report, error) {
	return &bpapi.Report{
		CreatedAt: time.Now(),
		ReportId:  mockReportId,
		Summary:   summary,
		Data:      reportData,
	}, nil
}

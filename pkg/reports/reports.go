package reports

import (
	"context"
	"fmt"

	"github.com/openshift/configuration-anomaly-detection/pkg/backplane"
)

type ClusterReport struct {
	ReportID  string
	ClusterID string
}

type Input struct {
	ClusterID string
	Summary   string
	Data      string
}

// New creates a new ClusterReport via the backplane-api, and returns a serialized instance that can be used from
// within an investigation.
func New(ctx context.Context, bpClient backplane.Client, input *Input) (*ClusterReport, error) {
	reportResp, err := bpClient.CreateReport(ctx, input.ClusterID, input.Summary, input.Data)
	if err != nil {
		return nil, fmt.Errorf("error creating report: %w", err)
	}

	return &ClusterReport{
		ClusterID: input.ClusterID,
		ReportID:  reportResp.ReportId,
	}, nil
}

// GenerateStringForNoteWriter returns a formatted string to be used with the notewriter package for
// appending to PagerDuty notes.
func (c *ClusterReport) GenerateStringForNoteWriter() string {
	return fmt.Sprintf("CAD created a cluster report, access it with the following command:\n"+
		"osdctl cluster reports get --cluster-id %s --report-id %s", c.ClusterID, c.ReportID)
}

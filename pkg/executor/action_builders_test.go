package executor

import (
	"testing"

	servicelogsv1 "github.com/openshift-online/ocm-sdk-go/servicelogs/v1"
	"github.com/stretchr/testify/assert"
)

func Test_NewBackplaneReportAction(t *testing.T) {
	clusterID := "123-456-789"
	summary := "Test cluster report"
	data := "some test data"

	action := NewBackplaneReportAction(clusterID, summary, data).Build()

	assert.NotNil(t, action)
	backplaneAction, ok := action.(*BackplaneReportAction)
	assert.True(t, ok, "action should be of type *BackplaneReportAction")
	assert.Equal(t, clusterID, backplaneAction.ClusterID)
	assert.Equal(t, summary, backplaneAction.Summary)
	assert.Equal(t, data, backplaneAction.Data)
}

func Test_BackplaneReportActionBuilder_AllFields(t *testing.T) {
	clusterID := "prod-cluster-001"
	summary := "Configuration drift detected"
	data := `{"issue": "configuration mismatch", "severity": "high"}`

	action := NewBackplaneReportAction(clusterID, summary, data).Build()

	backplaneAction := action.(*BackplaneReportAction)
	assert.Equal(t, "prod-cluster-001", backplaneAction.ClusterID)
	assert.Equal(t, "Configuration drift detected", backplaneAction.Summary)
	assert.Equal(t, `{"issue": "configuration mismatch", "severity": "high"}`, backplaneAction.Data)
}

func Test_BackplaneReportActionBuilder_Type(t *testing.T) {
	action := NewBackplaneReportAction("cluster-123", "Test", "data").Build()

	backplaneAction := action.(*BackplaneReportAction)
	assert.Equal(t, string(ActionTypeBackplaneReport), backplaneAction.Type())
}

func Test_ServiceLogAction_Validate_RequiredFields(t *testing.T) {
	action := NewServiceLogAction("", "").Build()
	err := action.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Summary is required")

	action = NewServiceLogAction(servicelogsv1.SeverityCritical, "").Build()
	err = action.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Summary is required")

	action = NewServiceLogAction("", "some summary").Build()
	err = action.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Severity is required")

	action = NewServiceLogAction(servicelogsv1.SeverityCritical, "valid summary").Build()
	assert.NoError(t, action.Validate())
}

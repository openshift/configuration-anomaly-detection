package cpd

import (
	"strings"
	"testing"

	servicelogsv1 "github.com/openshift-online/ocm-sdk-go/servicelogs/v1"
	"gotest.tools/v3/assert"
)

func TestNewBYOVPCRoutingSL(t *testing.T) {
	docLink := "https://docs.example.com"
	sl := newBYOVPCRoutingSL(docLink)

	assert.Equal(t, servicelogsv1.SeverityImportant, sl.Severity)
	assert.Equal(t, "SREManualAction", sl.ServiceName)
	assert.Equal(t, "Installation blocked: Missing route to internet", sl.Summary)
	assert.Assert(t, !sl.InternalOnly)
	assert.Assert(t, strings.Contains(sl.Description, docLink))
}

func TestNewBYOVPCRoutingSL_DefaultDocLink(t *testing.T) {
	sl := newBYOVPCRoutingSL("")
	assert.Assert(t, strings.Contains(sl.Description, "docs."))
}

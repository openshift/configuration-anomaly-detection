package types

import (
	cmv1 "github.com/openshift-online/ocm-sdk-go/clustersmgmt/v1"
	"github.com/openshift/configuration-anomaly-detection/pkg/backplane"
	"github.com/openshift/configuration-anomaly-detection/pkg/notewriter"
	"github.com/openshift/configuration-anomaly-detection/pkg/ocm"
	"github.com/openshift/configuration-anomaly-detection/pkg/pagerduty"
	"go.uber.org/zap"
)

// ExecutionContext provides resources needed by actions during execution
type ExecutionContext struct {
	// Cluster being operated on
	Cluster *cmv1.Cluster

	// Client instances
	OCMClient       ocm.Client
	PDClient        pagerduty.Client
	BackplaneClient backplane.Client

	// NoteWriter for appending action results to notes
	Notes *notewriter.NoteWriter

	// Metadata
	InvestigationName string

	// Logger for action execution
	Logger *zap.SugaredLogger
}

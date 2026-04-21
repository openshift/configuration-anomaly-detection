package types

// FilterContext holds fields from multiple sources (OCM, PagerDuty) that can be
// used to evaluate filter expressions when deciding whether an action should run
// for a given alert/cluster combination.
//
// Fields are plain strings so that filter evaluation does not depend on SDK types.
// Not all fields will be populated in every context — for example, PagerDuty fields
// are empty when running via the manual CLI, and OCM fields that require additional
// API calls (OrganizationID, OwnerEmail) may be empty if those calls fail.
type FilterContext struct {
	// --- OCM Cluster fields ---

	// ClusterID is the OCM internal cluster identifier.
	ClusterID string

	// ClusterName is the human-readable cluster name.
	ClusterName string

	// OrganizationID is the OCM organization that owns the cluster's subscription.
	OrganizationID string

	// OwnerID is the OCM account ID of the subscription creator.
	OwnerID string

	// OwnerEmail is the email address of the subscription creator.
	OwnerEmail string

	// CloudProvider is the cloud provider identifier (e.g. "aws", "gcp").
	CloudProvider string

	// HCP indicates whether the cluster is a Hosted Control Plane cluster.
	HCP bool

	// ClusterState is the current cluster state (e.g. "ready", "uninstalling").
	ClusterState string

	// --- PagerDuty fields ---

	// AlertName is the name of the alert as matched by investigation.AlertTitle().
	AlertName string

	// AlertTitle is the full PagerDuty incident title.
	AlertTitle string

	// ServiceName is the PagerDuty service summary (e.g. "prod-deadmanssnitch").
	ServiceName string
}

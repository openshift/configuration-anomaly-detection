package micro

import (
	"errors"

	cmv1 "github.com/openshift-online/ocm-sdk-go/clustersmgmt/v1"
	"github.com/openshift/configuration-anomaly-detection/pkg/executor"
	"github.com/openshift/configuration-anomaly-detection/pkg/notewriter"
	"github.com/openshift/configuration-anomaly-detection/pkg/ocm"
	"github.com/openshift/configuration-anomaly-detection/pkg/types"
)

// BannedUser checks whether the cluster owner is banned via the OCM ban API.
// For callers that need the ban code to branch on (e.g., export control),
// use ClusterCreator + CheckBan instead.
func BannedUser(ocmClient ocm.Client, cluster *cmv1.Cluster, notes *notewriter.NoteWriter) (Result, error) {
	userBannedErr := ocm.UserBannedError{}
	err := ocmClient.CheckIfUserBanned(cluster)

	switch {
	case errors.As(err, &userBannedErr) && userBannedErr.Code == "export_control_compliance":
		notes.AppendWarning("%v", err)
		return Result{
			Done: true,
			Actions: []types.Action{
				executor.Escalate("Export Control Compliance ban detected, please refer to the SOP."),
			},
		}, nil

	case errors.As(err, &userBannedErr):
		sl := ocm.NewOCMBannedUserServiceLog()
		notes.AppendWarning("%v", err)
		notes.AppendWarning("Sending out Service Log (%s)", sl.Summary)
		return Result{
			Done: true,
			Actions: []types.Action{
				executor.NewServiceLogAction(sl.Severity, sl.Summary).
					WithDescription(sl.Description).
					WithServiceName(sl.ServiceName).
					Build(),
				executor.Silence("Banned OCM user - service log sent to customer"),
			},
		}, nil

	case err != nil:
		return Result{}, err
	}

	notes.AppendSuccess("User is not banned.")
	return Result{Done: false}, nil
}

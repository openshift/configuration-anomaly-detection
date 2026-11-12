package testutil

import "github.com/openshift/configuration-anomaly-detection/pkg/types"

func HasActionType(actions []types.Action, actionType string) bool {
	for _, action := range actions {
		if action.Type() == actionType {
			return true
		}
	}
	return false
}

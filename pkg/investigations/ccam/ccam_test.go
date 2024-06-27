package ccam

import (
	"errors"
	"testing"
)

func TestEvaluateRandomError(t *testing.T) {
	timeoutError := errors.New("credentials are there, error is different: timeout")
	err := Evaluate(nil, errors.New("timeout"), nil, nil, "")
	if err.Error() != timeoutError.Error() {
		t.Fatalf("Expected error %v, but got %v", timeoutError, err)
	}
}

func TestCustomerRemovedPermissions(t *testing.T) {
	tests := []struct {
		name          string
		errorMessage  string
		expectedMatch bool
	}{
		{
			name:          "Matching error 1",
			errorMessage:  "unable to query aws credentials from backplane: failed to determine if cluster is using isolated backlpane access: failed to get sts support jump role ARN for cluster 28testqvq0jpo1hsrch6gvbc0123test: failed to get STS Support Jump Role for cluster 28testqvq0jpo1hsrch6gvbc0qgqtest, status is 404, identifier is '404', code is 'CLUSTERS-MGMT-404' and operation identifier is 'teste1d1-3844-46f7-82d4-643c5aeeca53': Failed to find trusted relationship to support role 'RH-Technical-Support-Access'",
			expectedMatch: true,
		},
		{
			name:          "Matching error 2",
			errorMessage:  "unable to query aws credentials from backplane: failed to determine if cluster is using isolated backlpane access: failed to get sts support jump role ARN for cluster test9tm92uu49s29plim5dn1sbc1test: failed to get STS Support Jump Role for cluster test9tm92uu49s29plim5dn1sbc1test, status is 404, identifier is '404', code is 'CLUSTERS-MGMT-404' and operation identifier is 'testf5f3-6591-452f-98cb-3943edf4test': Support role, used with cluster 'test9tm92uu49s29plim5dn1sbc1test', does not exist in the customer's AWS account",
			expectedMatch: true,
		},
		{
			name:          "Matching error 3",
			errorMessage:  "something could not assume support role in customer's account: AccessDenied: something",
			expectedMatch: true,
		},
		{
			name:          "Non-matching error",
			errorMessage:  "Some timeout error",
			expectedMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			match := customerRemovedPermissions(tt.errorMessage)
			if match != tt.expectedMatch {
				t.Errorf("customerRemovedPermissions() = %v, expectedMatch %v", match, tt.expectedMatch)
			}
		})
	}
}

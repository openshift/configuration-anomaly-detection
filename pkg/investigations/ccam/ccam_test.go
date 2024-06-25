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

package mustgathercritical

import (
	"testing"
)

func TestInvestigation_Name(t *testing.T) {
	inv := &Investigation{}
	if got := inv.Name(); got != "mustgathercritical" {
		t.Errorf("Name() = %q, want %q", got, "mustgathercritical")
	}
}

func TestInvestigation_AlertTitle(t *testing.T) {
	inv := &Investigation{}
	if got := inv.AlertTitle(); got != "CreateMustGatherCritical" {
		t.Errorf("AlertTitle() = %q, want %q", got, "CreateMustGatherCritical")
	}
}

func TestInvestigation_Description(t *testing.T) {
	inv := &Investigation{}
	if got := inv.Description(); got == "" {
		t.Error("Description() should not be empty")
	}
}

func TestInvestigation_IsExperimental(t *testing.T) {
	inv := &Investigation{}
	if inv.IsExperimental() {
		t.Error("IsExperimental() should return false")
	}
}

func TestInvestigation_Run(t *testing.T) {
	t.Skip("Not tested - delegates to mustgather.Investigation.Run which is tested in the mustgather package")
}

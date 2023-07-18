package cpd_test

import (
	"fmt"
	"testing"

	"github.com/openshift/configuration-anomaly-detection/pkg/investigations/cpd"
)

func TestNoCPDTitle(t *testing.T) {
	alertTitle := "johnnysts.s1.devshift.org has gone missing"
	_, err := cpd.GetCPDAlertInternalID(alertTitle)

	// This should not find an ID hence return an error
	if err == nil {
		t.Fail()
	}
}

func TestNoCPDTitleModified(t *testing.T) {
	alertTitle := "johnnysts.s1.devshift.org uhc-broken has gone missing"
	_, err := cpd.GetCPDAlertInternalID(alertTitle)

	// This should not find an ID hence return an error
	if err == nil {
		t.Fail()
	}
}

func TestCPDTitle(t *testing.T) {
	id := "1234k6tnqp7306a6sefn4m41sdp7qsh6"
	alertTitle := fmt.Sprintf("[FIRING:1] ClusterProvisioningDelay - production hivep05ue1 uhc-production-%s hive-controllers hive (testcluster ProvisionFailed metrics production openshift-v4.13.4 hive aws openshift-customer-monitoring/app-sre BootstrapFailed high srep)", id)
	foundID, err := cpd.GetCPDAlertInternalID(alertTitle)
	if err != nil {
		t.Fail()
	}

	if foundID != id {
		t.Fail()
	}
}

func TestCPDTitleStaging(t *testing.T) {
	id := "1234k6tnqp7306a6sefn4m41sdp7qsh6"
	alertTitle := fmt.Sprintf("[FIRING:1] ClusterProvisioningDelay - staging hivep05ue1 uhc-staging-%s hive-controllers hive (testcluster ProvisionFailed metrics production openshift-v4.13.4 hive aws openshift-customer-monitoring/app-sre BootstrapFailed high srep)", id)
	foundID, err := cpd.GetCPDAlertInternalID(alertTitle)
	if err != nil {
		t.Fail()
	}

	if foundID != id {
		t.Fail()
	}
}

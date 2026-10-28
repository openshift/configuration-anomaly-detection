//go:build live

// Live check against a real cluster using the current kubeconfig (e.g. after
// `ocm backplane login <cluster>`). Bypasses CAD's backplane remediation flow,
// so it validates the checks and verdict without the AMS access-review step.
//
//	go test -tags live -run TestLive -v ./pkg/investigations/upgradecontrolplaneupgradetimeoutsre/
package upgradecontrolplaneupgradetimeoutsre

import (
	"context"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	policyv1 "k8s.io/api/policy/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
)

func TestLive(t *testing.T) {
	cfg, err := config.GetConfig()
	if err != nil {
		t.Fatalf("kubeconfig: %v", err)
	}
	s := testScheme()
	_ = policyv1.AddToScheme(s)
	_ = appsv1.AddToScheme(s)

	k8s, err := client.New(cfg, client.Options{Scheme: s})
	if err != nil {
		t.Fatalf("client: %v", err)
	}

	ctx := context.Background()
	inv := &Investigation{}
	state := upgradeState{}
	notes := newNotes()

	inv.checkClusterVersion(ctx, k8s, &state, notes)
	inv.checkClusterOperators(ctx, k8s, &state, notes)
	inv.checkMachineConfigPools(ctx, k8s, &state, notes)
	notes.AppendWarning("Likely blocker: %s", classify(state))

	t.Logf("\n%s", notes.String())
}

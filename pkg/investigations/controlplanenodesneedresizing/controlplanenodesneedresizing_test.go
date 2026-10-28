package controlplanenodesneedresizing

import "testing"

func TestNodeFromAlert(t *testing.T) {
	if got := nodeFromAlert("ControlPlaneNodesNeedResizingSRE node=master-0"); got != "master-0" {
		t.Fatalf("got %q", got)
	}
	if got := nodeFromAlert("no node here"); got != "" {
		t.Fatalf("got %q", got)
	}
	if got := nodeFromAlert("instance=10.0.0.1:9100 node=master-0"); got != "master-0" {
		t.Fatalf("got %q", got)
	}
}

func TestFormatRankingPutsHeavyPodFirst(t *testing.T) {
	usages := []podUsage{
		{namespace: "openshift-kube-apiserver", name: "idle", cpuMilli: 10, memBytes: 20 * 1024 * 1024},
		{namespace: "my-app", name: "heavy", cpuMilli: 50, memBytes: 800 * 1024 * 1024},
	}
	got := formatRanking("master-0", 70, 80, true, usages)
	heavy := indexOf(got, "1. my-app/heavy")
	idle := indexOf(got, "2. openshift-kube-apiserver/idle")
	if heavy < 0 || idle < 0 || heavy > idle {
		t.Fatalf("ranking:\n%s", got)
	}
	if indexOf(got, "(customer)") < 0 || indexOf(got, "(platform)") < 0 {
		t.Fatalf("missing kind:\n%s", got)
	}
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

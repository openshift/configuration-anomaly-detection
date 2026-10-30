package controlplanenodesneedresizing

import "testing"

const (
	testMaster0    = "master-0"
	testMaster1    = "master-1"
	testHeavy      = "heavy"
	testPlatformNS = "openshift-kube-apiserver"
	testCustomerNS = "my-app"
)

func TestNodeFromAlert(t *testing.T) {
	if got := nodeFromAlert("ControlPlaneNodesNeedResizingSRE node=" + testMaster0); got != testMaster0 {
		t.Fatalf("got %q", got)
	}
	if got := nodeFromAlert("no node here"); got != "" {
		t.Fatalf("got %q", got)
	}
	if got := nodeFromAlert("instance=10.0.0.1:9100 node=" + testMaster0); got != testMaster0 {
		t.Fatalf("got %q", got)
	}
}

func TestFormatRankingPutsHeavyPodFirst(t *testing.T) {
	usages := []podUsage{
		{namespace: testPlatformNS, name: "idle", cpuMilli: 10, memBytes: 20 * 1024 * 1024},
		{namespace: testCustomerNS, name: testHeavy, cpuMilli: 50, memBytes: 800 * 1024 * 1024},
	}
	got := formatRanking(testMaster0, 70, 80, true, usages)
	heavy := indexOf(got, "1. "+testCustomerNS+"/"+testHeavy)
	idle := indexOf(got, "2. "+testPlatformNS+"/idle")
	if heavy < 0 || idle < 0 || heavy > idle {
		t.Fatalf("ranking:\n%s", got)
	}
	if indexOf(got, "(customer)") < 0 || indexOf(got, "(platform)") < 0 {
		t.Fatalf("missing kind:\n%s", got)
	}
}

func TestIdentifyCauseFromAlertTitleWithoutNode(t *testing.T) {
	title := "ControlPlaneNodesNeedResizingSRE critical"
	if nodeFromAlert(title) != "" {
		t.Fatal("this alert title must not name a node")
	}
	got := identifyCause(title, []masterSample{
		{
			name: testMaster0, cpuPercent: 10, memPercent: 12,
			pods: []podUsage{{namespace: testPlatformNS, name: "quiet", node: testMaster0, memBytes: 50 * 1024 * 1024, cpuMilli: 5}},
		},
		{
			name: testMaster1, cpuPercent: 80, memPercent: 40,
			pods: []podUsage{
				{namespace: testPlatformNS, name: "kas", node: testMaster1, memBytes: 100 * 1024 * 1024, cpuMilli: 20},
				{namespace: testCustomerNS, name: testHeavy, node: testMaster1, memBytes: 900 * 1024 * 1024, cpuMilli: 50},
			},
		},
		{
			name: "master-2", cpuPercent: 30, memPercent: 90,
			pods: []podUsage{{namespace: "customer-ns", name: "lighter", node: "master-2", memBytes: 200 * 1024 * 1024, cpuMilli: 10}},
		},
	})
	if !got.Found || got.Node != testMaster1 || got.Namespace != testCustomerNS || got.Name != testHeavy || got.Kind != "customer" {
		t.Fatalf("%+v", got)
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

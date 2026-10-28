package etcddatabasequotalowspace

import "testing"

func member(id, leader uint64, db, inUse int64) endpointStatus {
	var row endpointStatus
	row.Status.Header.MemberID = id
	row.Status.Leader = leader
	row.Status.DbSize = db
	row.Status.DbSizeInUse = inUse
	return row
}

func TestDecideDefragNothingToReclaim(t *testing.T) {
	before := []endpointStatus{member(1, 1, 200<<20, 180<<20)}
	got := decideDefrag(before, nil, nil)
	if got.kind != defragNoReclaim {
		t.Fatalf("kind %v", got.kind)
	}
}

func TestDecideDefragSuccessSilences(t *testing.T) {
	before := []endpointStatus{member(1, 1, 2<<30, 200<<20)}
	after := []endpointStatus{member(1, 1, 220<<20, 200<<20)}
	got := decideDefrag(before, after, nil)
	if got.kind != defragSucceeded {
		t.Fatalf("kind %v", got.kind)
	}
}

func TestDecideDefragNoDropEscalates(t *testing.T) {
	before := []endpointStatus{member(1, 1, 2<<30, 200<<20)}
	after := []endpointStatus{member(1, 1, 2<<30, 200<<20)}
	got := decideDefrag(before, after, nil)
	if got.kind != defragFailed {
		t.Fatalf("kind %v", got.kind)
	}
}

func TestDefragOrderLeaderLast(t *testing.T) {
	rows := []endpointStatus{
		member(1, 1, 1, 1),
		member(2, 1, 1, 1),
		member(3, 1, 1, 1),
	}
	ordered := defragOrder(rows)
	if ordered[len(ordered)-1].Status.Header.MemberID != 1 {
		t.Fatalf("leader not last: %+v", ordered)
	}
}

func TestParseEndpointStatus(t *testing.T) {
	raw := `[{"Endpoint":"https://10.0.0.1:2379","Status":{"header":{"member_id":1},"leader":1,"dbSize":300,"dbSizeInUse":100}}]`
	rows, err := parseEndpointStatus(raw)
	if err != nil {
		t.Fatal(err)
	}
	if reclaimableBytes(rows) != 200 {
		t.Fatalf("reclaimable %d", reclaimableBytes(rows))
	}
}

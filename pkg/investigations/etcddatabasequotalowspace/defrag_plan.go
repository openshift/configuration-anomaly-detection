package etcddatabasequotalowspace

import (
	"encoding/json"
	"fmt"
	"strings"
)

const (
	// etcdQuotaBytes is the default 8GiB backend quota. The critical alert fires at 85%.
	etcdQuotaBytes = 8 * 1024 * 1024 * 1024
	// minReclaimBytes is the smallest fragmentation worth a defrag.
	minReclaimBytes = 100 * 1024 * 1024
	quotaHighWater  = 85
)

// endpointStatus is one row of `etcdctl endpoint status -w json`.
type endpointStatus struct {
	Endpoint string `json:"Endpoint"`
	Status   struct {
		Header struct {
			MemberID uint64 `json:"member_id"`
		} `json:"header"`
		Leader      uint64 `json:"leader"`
		DbSize      int64  `json:"dbSize"`
		DbSizeInUse int64  `json:"dbSizeInUse"`
	} `json:"Status"`
}

type defragKind int

const (
	defragNoReclaim defragKind = iota
	defragSucceeded
	defragFailed
)

// defragDecision is what CAD does after it knows whether a defrag can help.
type defragDecision struct {
	kind defragKind
}

func parseEndpointStatus(raw string) ([]endpointStatus, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("empty etcdctl endpoint status")
	}
	var rows []endpointStatus
	if err := json.Unmarshal([]byte(raw), &rows); err != nil {
		return nil, fmt.Errorf("parsing etcdctl endpoint status: %w", err)
	}
	if len(rows) == 0 {
		return nil, fmt.Errorf("etcdctl endpoint status returned no members")
	}
	return rows, nil
}

func reclaimableBytes(rows []endpointStatus) int64 {
	var total int64
	for _, row := range rows {
		gap := row.Status.DbSize - row.Status.DbSizeInUse
		if gap > 0 {
			total += gap
		}
	}
	return total
}

func worthDefrag(rows []endpointStatus) bool {
	return reclaimableBytes(rows) >= minReclaimBytes
}

func atQuota(rows []endpointStatus) bool {
	for _, row := range rows {
		if row.Status.DbSize <= 0 {
			continue
		}
		if row.Status.DbSize*100/etcdQuotaBytes >= quotaHighWater {
			return true
		}
	}
	return false
}

func sizeDropped(before, after []endpointStatus) bool {
	return totalDBSize(after) < totalDBSize(before)
}

func totalDBSize(rows []endpointStatus) int64 {
	var total int64
	for _, row := range rows {
		total += row.Status.DbSize
	}
	return total
}

// defragOrder returns non-leaders first and the leader last.
func defragOrder(rows []endpointStatus) []endpointStatus {
	var followers, leaders []endpointStatus
	for _, row := range rows {
		if row.Status.Header.MemberID != 0 && row.Status.Header.MemberID == row.Status.Leader {
			leaders = append(leaders, row)
			continue
		}
		followers = append(followers, row)
	}
	return append(followers, leaders...)
}

// decideDefrag maps a measured before/after into the three ticket outcomes.
// A nil after with a nil err means defrag was not attempted.
func decideDefrag(before []endpointStatus, after []endpointStatus, defragErr error) defragDecision {
	if !worthDefrag(before) {
		return defragDecision{kind: defragNoReclaim}
	}
	if defragErr != nil || after == nil || !sizeDropped(before, after) || atQuota(after) {
		return defragDecision{kind: defragFailed}
	}
	return defragDecision{kind: defragSucceeded}
}

func customersAreLargest(top []NamespaceSize) bool {
	if len(top) == 0 {
		return false
	}
	ns := top[0].Namespace
	return !strings.HasPrefix(ns, "openshift-") && !strings.HasPrefix(ns, "kube-")
}

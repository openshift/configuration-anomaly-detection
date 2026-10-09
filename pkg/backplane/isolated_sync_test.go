package backplane

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// This file guards pkg/backplane/isolated.go against divergence from the upstream
// backplane-cli code it was copied from:
// https://github.com/openshift/backplane-cli/blob/main/cmd/ocm-backplane/cloud/common.go
//
// isolated.go is an *adaptation* of upstream (different package, methods on
// ClientImpl, added retry logic, console helpers dropped), so it cannot be
// compared to upstream byte-for-byte. Instead we pin the SHA-256 of the upstream
// file we last synced against (upstreamContentSHA256) and hash the live upstream
// file. When they differ, upstream has changed since our last sync and isolated.go
// may need to be updated to match.
//
//
// RE-SYNC PROCEDURE when TestUpstreamCommonGoUnchanged fails:
//  1. Review the upstream changes to common.go:
//     https://github.com/openshift/backplane-cli/commits/main/cmd/ocm-backplane/cloud/common.go
//  2. Port any relevant changes into isolated.go.
//  3. Update upstreamContentSHA256 below to the new hash. The failing test prints
//     the exact value to paste in; or compute it yourself with:
//       curl -sSfL "https://raw.githubusercontent.com/openshift/backplane-cli/main/cmd/ocm-backplane/cloud/common.go" | sha256sum

const (
	// upstreamContentSHA256 is the SHA-256 of the backplane-cli common.go that
	// isolated.go is currently synced to. It is the single source of truth for the
	// synced revision
	upstreamContentSHA256 = "b1db294bd7e84026efffaa69dda599fe190b0550a5200fdb8ff10e742d9e20ec"

	upstreamRawURL = "https://raw.githubusercontent.com/openshift/backplane-cli/main/cmd/ocm-backplane/cloud/common.go"

	upstreamFetchTimeout     = 20 * time.Second
	skipUpstreamSyncCheckEnv = "SKIP_UPSTREAM_SYNC_CHECK"
)

// TestUpstreamCommonGoUnchanged fails whenever upstream backplane-cli's common.go
// differs from the revision isolated.go was synced against, signalling that
// isolated.go should be reviewed and re-synced.
//
// It requires network access to raw.githubusercontent.com. When the fetch fails
// (offline/air-gapped CI) the test skips rather than failing spuriously, so it
// only ever fails on a confirmed upstream change. Set SKIP_UPSTREAM_SYNC_CHECK=1
// to opt out entirely.
func TestUpstreamCommonGoUnchanged(t *testing.T) {
	if os.Getenv(skipUpstreamSyncCheckEnv) != "" {
		t.Skipf("%s set; skipping upstream drift check", skipUpstreamSyncCheckEnv)
	}

	ctx, cancel := context.WithTimeout(context.Background(), upstreamFetchTimeout)
	defer cancel()

	liveSHA, err := upstreamCommonGoSHA256(ctx)
	if err != nil {
		t.Skipf("could not fetch upstream common.go (%v); skipping drift check. "+
			"This test only fails on a confirmed upstream change.", err)
	}

	require.Equalf(t, upstreamContentSHA256, liveSHA,
		"\n"+
			"=====================================================================\n"+
			"UPSTREAM DRIFT: backplane-cli common.go has changed since it was synced.\n"+
			"=====================================================================\n"+
			"\n"+
			"pkg/backplane/isolated.go is a copy of upstream backplane-cli:\n"+
			"  %s\n"+
			"\n"+
			"  synced-to sha256 : %s\n"+
			"  upstream  sha256 : %s\n"+
			"\n"+
			"TO RESOLVE (in the configuration-anomaly-detection repo):\n"+
			"  1. Review what changed upstream:\n"+
			"     https://github.com/openshift/backplane-cli/commits/main/cmd/ocm-backplane/cloud/common.go\n"+
			"  2. Port any relevant changes into pkg/backplane/isolated.go.\n"+
			"  3. In pkg/backplane/isolated_sync_test.go, set the new pinned hash:\n"+
			"       upstreamContentSHA256 = %q\n"+
			"     (the value above after 'upstream sha256'; or recompute with:\n"+
			"       curl -sSfL %q | sha256sum)\n"+
			"  4. Commit isolated.go + isolated_sync_test.go together.\n"+
			"\n"+
			"If upstream changed in a way that does NOT affect isolated.go, just do\n"+
			"steps 3-4 to re-pin.\n"+
			"=====================================================================",
		upstreamRawURL, upstreamContentSHA256, liveSHA, liveSHA, upstreamRawURL)
}

// upstreamCommonGoSHA256 returns the SHA-256 of the live upstream common.go.
func upstreamCommonGoSHA256(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, upstreamRawURL, nil)
	if err != nil {
		return "", err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("fetching upstream returned status %d", resp.StatusCode)
	}

	h := sha256.New()
	if _, err := io.Copy(h, resp.Body); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

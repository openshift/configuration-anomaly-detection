package k8sclient

import (
	"errors"
	"strings"
)

var ErrAPIServerUnavailable = errors.New("kubernetes API server unavailable")

// isAPIServerUnavailable detects common symptoms of an unreachable API server.
func isAPIServerUnavailable(err error) bool {
	errStr := err.Error()
	return strings.Contains(errStr, "TLS handshake timeout") ||
		strings.Contains(errStr, "connection refused") ||
		strings.Contains(errStr, "i/o timeout") ||
		strings.Contains(errStr, "dial tcp")
}

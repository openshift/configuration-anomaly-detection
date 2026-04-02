// Package utils contains utility functions
package utils

import (
	"context"
	"fmt"
	"time"

	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
)

// WithRetriesContext runs a function with configurable retries and exponential backoff,
// while respecting context cancellation. return immediately if the context is
// cancelled or times out during a backoff wait. In such a case, most recent error is wrapped.
func WithRetriesContext(ctx context.Context, count int, initialBackoff time.Duration, fn func() error) error {
	var err error
	for i := 0; i < count; i++ {
		if i > 0 {
			logging.Warnf("Retry %d/%d: %s", i, count-1, err.Error())

			select {
			case <-ctx.Done():
				return fmt.Errorf("context cancelled during retry backoff (last error: %w): %w", err, ctx.Err())
			case <-time.After(initialBackoff):
			}

			initialBackoff *= 2
		}

		err = fn()
		if err == nil {
			if i > 0 {
				logging.Infof("Succeeded on attempt %d/%d", i+1, count)
			}
			return nil
		}
	}
	return fmt.Errorf("failed after %d attempts: %w", count, err)
}

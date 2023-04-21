// Package utils contains utility functions
package utils

import (
	"fmt"
	"time"
)

// WithRetries runs a function with up to 10 retries on error
func WithRetries(fn func() error) error {
	const defaultRetries = 10
	const defaultInitialBackoff = time.Second * 2

	return WithRetriesConfigurable(defaultRetries, defaultInitialBackoff, fn)
}

// WithRetriesConfigurable runs a function with a configurable retry count and backoff interval on error
func WithRetriesConfigurable(count int, initialBackoff time.Duration, fn func() error) error {
	var err error
	for i := 0; i < count; i++ {
		if i > 0 {
			fmt.Printf("Retry %d: %s \n", i, err.Error())
			time.Sleep(initialBackoff)
			initialBackoff *= 2
		}
		err = fn()
		if err == nil {
			return nil
		}
	}
	return fmt.Errorf("failed after %d retries: %w", count, err)
}

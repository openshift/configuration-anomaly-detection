package utils

import (
	"fmt"
	"time"
)

// Retry will retry a function with a backoff
func Retry(count int, sleep time.Duration, fn func() error) error {
	var err error
	for i := 0; i < count; i++ {
		if i > 0 {
			fmt.Printf("Retry %d: %s \n", i, err.Error())
			time.Sleep(sleep)
			sleep *= 2
		}
		err = fn()
		if err == nil {
			return nil
		}
	}
	return fmt.Errorf("failed after %d retries: %w", count, err)
}

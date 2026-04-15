package utils

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestWithRetriesContext_SucceedsFirstAttempt(t *testing.T) {
	attempts := 0
	err := WithRetriesContext(context.Background(), 3, 10*time.Millisecond, func() error {
		attempts++
		return nil
	})
	if err != nil {
		t.Errorf("expected no error, got: %v", err)
	}
	if attempts != 1 {
		t.Errorf("expected 1 attempt, got %d", attempts)
	}
}

func TestWithRetriesContext_SucceedsOnRetry(t *testing.T) {
	attempts := 0
	err := WithRetriesContext(context.Background(), 3, 10*time.Millisecond, func() error {
		attempts++
		if attempts < 3 {
			return errors.New("transient error")
		}
		return nil
	})
	if err != nil {
		t.Errorf("expected no error, got: %v", err)
	}
	if attempts != 3 {
		t.Errorf("expected 3 attempts, got %d", attempts)
	}
}

func TestWithRetriesContext_ExhaustsAllRetries(t *testing.T) {
	attempts := 0
	originalErr := errors.New("persistent error")
	err := WithRetriesContext(context.Background(), 3, 10*time.Millisecond, func() error {
		attempts++
		return originalErr
	})

	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if attempts != 3 {
		t.Errorf("expected 3 attempts, got %d", attempts)
	}
	if !strings.Contains(err.Error(), "failed after 3 attempts") {
		t.Errorf("expected error message to contain 'failed after 3 attempts', got: %v", err)
	}
	if !errors.Is(err, originalErr) {
		t.Errorf("expected wrapped error to contain original error")
	}
}

func TestWithRetriesContext_RespectsContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	attempts := 0

	err := WithRetriesContext(ctx, 5, 1*time.Second, func() error {
		attempts++
		if attempts == 1 {
			// Cancel context after first failure, so the backoff wait is interrupted
			cancel()
		}
		return errors.New("transient error")
	})

	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if attempts != 1 {
		t.Errorf("expected 1 attempt before context cancellation, got %d", attempts)
	}
	if !strings.Contains(err.Error(), "context cancelled during retry backoff") {
		t.Errorf("expected context cancellation error, got: %v", err)
	}
	if !strings.Contains(err.Error(), "transient error") {
		t.Errorf("expected last operation error in message, got: %v", err)
	}
}

func TestWithRetriesContext_RespectsContextTimeout(t *testing.T) {
	// Create a context that times out before the backoff completes
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	attempts := 0
	err := WithRetriesContext(ctx, 5, 1*time.Second, func() error {
		attempts++
		return errors.New("transient error")
	})

	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if attempts != 1 {
		t.Errorf("expected 1 attempt before context timeout, got %d", attempts)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("expected context.DeadlineExceeded in error chain, got: %v", err)
	}
}

func TestWithRetriesContext_ExponentialBackoff(t *testing.T) {
	attempts := 0
	timestamps := []time.Time{}

	err := WithRetriesContext(context.Background(), 3, 50*time.Millisecond, func() error {
		attempts++
		timestamps = append(timestamps, time.Now())
		return errors.New("transient error")
	})

	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if len(timestamps) != 3 {
		t.Fatalf("expected 3 timestamps, got %d", len(timestamps))
	}

	// First retry should wait ~50ms
	firstBackoff := timestamps[1].Sub(timestamps[0])
	if firstBackoff < 40*time.Millisecond || firstBackoff > 150*time.Millisecond {
		t.Errorf("first backoff expected ~50ms, got %v", firstBackoff)
	}

	// Second retry should wait ~100ms (doubled)
	secondBackoff := timestamps[2].Sub(timestamps[1])
	if secondBackoff < 80*time.Millisecond || secondBackoff > 250*time.Millisecond {
		t.Errorf("second backoff expected ~100ms, got %v", secondBackoff)
	}
}

func TestWithRetriesContext_SingleAttempt(t *testing.T) {
	attempts := 0
	originalErr := errors.New("single attempt error")
	err := WithRetriesContext(context.Background(), 1, 10*time.Millisecond, func() error {
		attempts++
		return originalErr
	})

	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if attempts != 1 {
		t.Errorf("expected 1 attempt, got %d", attempts)
	}
	if !errors.Is(err, originalErr) {
		t.Errorf("expected wrapped error to contain original error")
	}
}

func TestWithRetriesContext_AlreadyCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	attempts := 0
	err := WithRetriesContext(ctx, 3, 10*time.Millisecond, func() error {
		attempts++
		return errors.New("should not retry")
	})

	// The first attempt runs (context is checked during backoff, not before fn call)
	// But after the first failure, the backoff wait sees the cancelled context
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if attempts != 1 {
		t.Errorf("expected 1 attempt with already-cancelled context, got %d", attempts)
	}
}

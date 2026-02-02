package transport

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Test error types for retry classification
var (
	errRetryable    = errors.New("retryable error")
	errNotRetryable = errors.New("not retryable error")
)

func TestRetryConfigDefaults(t *testing.T) {
	t.Parallel()
	t.Log("Testing DefaultRetryConfig returns expected default values")
	cfg := DefaultRetryConfig()

	if cfg.InitialDelay != time.Second {
		t.Errorf("InitialDelay = %v, want %v", cfg.InitialDelay, time.Second)
	}
	if cfg.MaxDelay != 30*time.Second {
		t.Errorf("MaxDelay = %v, want %v", cfg.MaxDelay, 30*time.Second)
	}
	if cfg.Multiplier != 2.0 {
		t.Errorf("Multiplier = %v, want %v", cfg.Multiplier, 2.0)
	}
	if cfg.MaxAttempts != 10 {
		t.Errorf("MaxAttempts = %v, want %v", cfg.MaxAttempts, 10)
	}
	if cfg.Jitter != 0.1 {
		t.Errorf("Jitter = %v, want %v", cfg.Jitter, 0.1)
	}
}

func TestIsRetryable(t *testing.T) {
	t.Parallel()
	t.Log("Testing IsRetryable correctly classifies errors as retryable or not")
	tests := []struct {
		name      string
		err       error
		retryable bool
	}{
		{"nil error", nil, false},
		{"DOCANotConnected", ErrDOCANotConnected, true},
		{"DOCAConnectionReset", ErrDOCAConnectionReset, true},
		{"DOCAAgain", ErrDOCAAgain, true},
		{"DOCAInProgress", ErrDOCAInProgress, true},
		{"DOCAInvalidValue", ErrDOCAInvalidValue, false},
		{"DOCANotPermitted", ErrDOCANotPermitted, false},
		{"DOCANotSupported", ErrDOCANotSupported, false},
		{"wrapped retryable", errors.Join(errRetryable, ErrDOCANotConnected), true},
		{"generic error", errors.New("generic error"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Logf("Verifying %s returns retryable=%v", tt.name, tt.retryable)
			got := IsRetryable(tt.err)
			if got != tt.retryable {
				t.Errorf("IsRetryable(%v) = %v, want %v", tt.err, got, tt.retryable)
			}
		})
	}
}

func TestRetrySuccessFirstAttempt(t *testing.T) {
	t.Parallel()
	t.Log("Testing Retry succeeds on first attempt when function returns nil")
	cfg := RetryConfig{
		InitialDelay: 10 * time.Millisecond,
		MaxDelay:     100 * time.Millisecond,
		Multiplier:   2.0,
		MaxAttempts:  3,
		Jitter:       0,
	}

	var attempts int32
	err := Retry(context.Background(), cfg, func() error {
		atomic.AddInt32(&attempts, 1)
		return nil
	})

	if err != nil {
		t.Errorf("Retry returned error: %v", err)
	}
	if attempts != 1 {
		t.Errorf("attempts = %d, want 1", attempts)
	}
}

func TestRetrySuccessAfterFailures(t *testing.T) {
	t.Parallel()
	t.Log("Testing Retry succeeds after retrying through initial failures")
	cfg := RetryConfig{
		InitialDelay: 1 * time.Millisecond,
		MaxDelay:     10 * time.Millisecond,
		Multiplier:   2.0,
		MaxAttempts:  5,
		Jitter:       0,
	}

	var attempts int32
	err := Retry(context.Background(), cfg, func() error {
		n := atomic.AddInt32(&attempts, 1)
		if n < 3 {
			return ErrDOCANotConnected // Retryable error
		}
		return nil
	})

	if err != nil {
		t.Errorf("Retry returned error: %v", err)
	}
	if attempts != 3 {
		t.Errorf("attempts = %d, want 3", attempts)
	}
}

func TestRetryNonRetryableError(t *testing.T) {
	t.Parallel()
	t.Log("Testing Retry returns immediately for non-retryable errors")
	cfg := RetryConfig{
		InitialDelay: 1 * time.Millisecond,
		MaxDelay:     10 * time.Millisecond,
		Multiplier:   2.0,
		MaxAttempts:  5,
		Jitter:       0,
	}

	var attempts int32
	err := Retry(context.Background(), cfg, func() error {
		atomic.AddInt32(&attempts, 1)
		return ErrDOCAInvalidValue // Non-retryable
	})

	if !errors.Is(err, ErrDOCAInvalidValue) {
		t.Errorf("Retry error = %v, want ErrDOCAInvalidValue", err)
	}
	if attempts != 1 {
		t.Errorf("attempts = %d, want 1 (non-retryable should not retry)", attempts)
	}
}

func TestRetryMaxAttempts(t *testing.T) {
	t.Parallel()
	t.Log("Testing Retry stops after reaching max attempts with ErrMaxRetriesExceeded")
	cfg := RetryConfig{
		InitialDelay: 1 * time.Millisecond,
		MaxDelay:     10 * time.Millisecond,
		Multiplier:   2.0,
		MaxAttempts:  3,
		Jitter:       0,
	}

	var attempts int32
	err := Retry(context.Background(), cfg, func() error {
		atomic.AddInt32(&attempts, 1)
		return ErrDOCANotConnected // Always fail with retryable error
	})

	if !errors.Is(err, ErrMaxRetriesExceeded) {
		t.Errorf("Retry error = %v, want ErrMaxRetriesExceeded", err)
	}
	if attempts != 3 {
		t.Errorf("attempts = %d, want 3", attempts)
	}
}

func TestRetryContextCancellation(t *testing.T) {
	t.Parallel()
	t.Log("Testing Retry respects context cancellation during retry loop")
	cfg := RetryConfig{
		InitialDelay: 100 * time.Millisecond,
		MaxDelay:     1 * time.Second,
		Multiplier:   2.0,
		MaxAttempts:  10,
		Jitter:       0,
	}

	ctx, cancel := context.WithCancel(context.Background())
	var attempts int32

	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	err := Retry(ctx, cfg, func() error {
		atomic.AddInt32(&attempts, 1)
		return ErrDOCANotConnected
	})

	if !errors.Is(err, context.Canceled) {
		t.Errorf("Retry error = %v, want context.Canceled", err)
	}
}

func TestRetryExponentialBackoff(t *testing.T) {
	t.Parallel()
	t.Log("Testing Retry uses exponential backoff between attempts")
	cfg := RetryConfig{
		InitialDelay: 10 * time.Millisecond,
		MaxDelay:     100 * time.Millisecond,
		Multiplier:   2.0,
		MaxAttempts:  4,
		Jitter:       0,
	}

	var times []time.Time
	var mu sync.Mutex

	start := time.Now()
	Retry(context.Background(), cfg, func() error {
		mu.Lock()
		times = append(times, time.Now())
		mu.Unlock()
		return ErrDOCANotConnected
	})

	// Verify delays increased: 0ms, 10ms, 20ms, 40ms
	// Total time should be approximately 70ms
	elapsed := time.Since(start)
	if elapsed < 60*time.Millisecond {
		t.Errorf("Elapsed time %v is too short (expected ~70ms)", elapsed)
	}
	if elapsed > 150*time.Millisecond {
		t.Errorf("Elapsed time %v is too long (expected ~70ms)", elapsed)
	}
}

func TestRetryMaxDelayRespected(t *testing.T) {
	t.Parallel()
	t.Log("Testing Retry caps delays at MaxDelay")
	cfg := RetryConfig{
		InitialDelay: 50 * time.Millisecond,
		MaxDelay:     50 * time.Millisecond, // Same as initial = constant delay
		Multiplier:   2.0,
		MaxAttempts:  3,
		Jitter:       0,
	}

	start := time.Now()
	Retry(context.Background(), cfg, func() error {
		return ErrDOCANotConnected
	})
	elapsed := time.Since(start)

	// 2 delays of 50ms each (after attempts 1 and 2)
	expected := 100 * time.Millisecond
	if elapsed < 80*time.Millisecond || elapsed > 150*time.Millisecond {
		t.Errorf("Elapsed time %v outside expected range around %v", elapsed, expected)
	}
}

// Circuit Breaker Tests

func TestCircuitBreakerDefaults(t *testing.T) {
	t.Parallel()
	t.Log("Testing DefaultCircuitBreakerConfig returns expected default values")
	cfg := DefaultCircuitBreakerConfig()

	if cfg.FailureThreshold != 5 {
		t.Errorf("FailureThreshold = %d, want 5", cfg.FailureThreshold)
	}
	if cfg.ResetTimeout != 60*time.Second {
		t.Errorf("ResetTimeout = %v, want 60s", cfg.ResetTimeout)
	}
}

func TestCircuitBreakerInitialState(t *testing.T) {
	t.Parallel()
	t.Log("Testing new circuit breaker starts in closed state")
	cb := NewCircuitBreaker(DefaultCircuitBreakerConfig())
	if cb.State() != CircuitClosed {
		t.Errorf("Initial state = %v, want %v", cb.State(), CircuitClosed)
	}
}

func TestCircuitBreakerOpensAfterThreshold(t *testing.T) {
	t.Parallel()
	t.Log("Testing circuit breaker opens after failure threshold is reached")
	cfg := CircuitBreakerConfig{
		FailureThreshold: 3,
		ResetTimeout:     100 * time.Millisecond,
	}
	cb := NewCircuitBreaker(cfg)

	// Execute 3 failing operations
	for i := 0; i < 3; i++ {
		cb.Execute(func() error {
			return ErrDOCANotConnected
		})
	}

	if cb.State() != CircuitOpen {
		t.Errorf("State after %d failures = %v, want %v", 3, cb.State(), CircuitOpen)
	}
}

func TestCircuitBreakerRejectsWhenOpen(t *testing.T) {
	t.Parallel()
	t.Log("Testing circuit breaker rejects calls without executing when open")
	cfg := CircuitBreakerConfig{
		FailureThreshold: 2,
		ResetTimeout:     1 * time.Second,
	}
	cb := NewCircuitBreaker(cfg)

	// Trip the breaker
	for i := 0; i < 2; i++ {
		cb.Execute(func() error {
			return ErrDOCANotConnected
		})
	}

	// Next call should be rejected without executing
	called := false
	err := cb.Execute(func() error {
		called = true
		return nil
	})

	if called {
		t.Error("Function was called when circuit was open")
	}
	if !errors.Is(err, ErrCircuitOpen) {
		t.Errorf("Error = %v, want ErrCircuitOpen", err)
	}
}

func TestCircuitBreakerHalfOpenAfterTimeout(t *testing.T) {
	t.Parallel()
	t.Log("Testing circuit breaker transitions to half-open after reset timeout")
	cfg := CircuitBreakerConfig{
		FailureThreshold: 2,
		ResetTimeout:     50 * time.Millisecond,
	}
	cb := NewCircuitBreaker(cfg)

	// Trip the breaker
	for i := 0; i < 2; i++ {
		cb.Execute(func() error {
			return ErrDOCANotConnected
		})
	}

	// Wait for reset timeout
	time.Sleep(60 * time.Millisecond)

	if cb.State() != CircuitHalfOpen {
		t.Errorf("State after timeout = %v, want %v", cb.State(), CircuitHalfOpen)
	}
}

func TestCircuitBreakerClosesOnSuccessInHalfOpen(t *testing.T) {
	t.Parallel()
	t.Log("Testing circuit breaker closes on successful call in half-open state")
	cfg := CircuitBreakerConfig{
		FailureThreshold: 2,
		ResetTimeout:     50 * time.Millisecond,
	}
	cb := NewCircuitBreaker(cfg)

	// Trip the breaker
	for i := 0; i < 2; i++ {
		cb.Execute(func() error {
			return ErrDOCANotConnected
		})
	}

	// Wait for reset timeout
	time.Sleep(60 * time.Millisecond)

	// Successful call in half-open should close the circuit
	err := cb.Execute(func() error {
		return nil
	})

	if err != nil {
		t.Errorf("Execute returned error: %v", err)
	}
	if cb.State() != CircuitClosed {
		t.Errorf("State after success = %v, want %v", cb.State(), CircuitClosed)
	}
}

func TestCircuitBreakerReopensOnFailureInHalfOpen(t *testing.T) {
	t.Parallel()
	t.Log("Testing circuit breaker reopens on failed call in half-open state")
	cfg := CircuitBreakerConfig{
		FailureThreshold: 2,
		ResetTimeout:     50 * time.Millisecond,
	}
	cb := NewCircuitBreaker(cfg)

	// Trip the breaker
	for i := 0; i < 2; i++ {
		cb.Execute(func() error {
			return ErrDOCANotConnected
		})
	}

	// Wait for reset timeout
	time.Sleep(60 * time.Millisecond)

	// Failing call in half-open should reopen the circuit
	cb.Execute(func() error {
		return ErrDOCANotConnected
	})

	if cb.State() != CircuitOpen {
		t.Errorf("State after failure = %v, want %v", cb.State(), CircuitOpen)
	}
}

func TestCircuitBreakerReset(t *testing.T) {
	t.Parallel()
	t.Log("Testing circuit breaker Reset() returns to closed state")
	cfg := CircuitBreakerConfig{
		FailureThreshold: 2,
		ResetTimeout:     1 * time.Second,
	}
	cb := NewCircuitBreaker(cfg)

	// Trip the breaker
	for i := 0; i < 2; i++ {
		cb.Execute(func() error {
			return ErrDOCANotConnected
		})
	}

	if cb.State() != CircuitOpen {
		t.Errorf("State before reset = %v, want %v", cb.State(), CircuitOpen)
	}

	cb.Reset()

	if cb.State() != CircuitClosed {
		t.Errorf("State after reset = %v, want %v", cb.State(), CircuitClosed)
	}
}

func TestCircuitBreakerSuccessResetsFailureCount(t *testing.T) {
	t.Parallel()
	t.Log("Testing circuit breaker resets failure count on successful call")
	cfg := CircuitBreakerConfig{
		FailureThreshold: 3,
		ResetTimeout:     1 * time.Second,
	}
	cb := NewCircuitBreaker(cfg)

	// Two failures
	for i := 0; i < 2; i++ {
		cb.Execute(func() error {
			return ErrDOCANotConnected
		})
	}

	// One success should reset counter
	cb.Execute(func() error {
		return nil
	})

	// Two more failures should not trip the breaker
	for i := 0; i < 2; i++ {
		cb.Execute(func() error {
			return ErrDOCANotConnected
		})
	}

	if cb.State() != CircuitClosed {
		t.Errorf("State = %v, want %v (success should have reset failure count)", cb.State(), CircuitClosed)
	}
}

func TestCircuitBreakerConcurrency(t *testing.T) {
	t.Parallel()
	t.Log("Testing circuit breaker is safe for concurrent access")
	cfg := CircuitBreakerConfig{
		FailureThreshold: 100,
		ResetTimeout:     1 * time.Second,
	}
	cb := NewCircuitBreaker(cfg)

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				cb.Execute(func() error {
					return ErrDOCANotConnected
				})
			}
		}()
	}

	wg.Wait()

	// After 500 failures, circuit should be open
	if cb.State() != CircuitOpen {
		t.Errorf("State after concurrent failures = %v, want %v", cb.State(), CircuitOpen)
	}
}

// ============================================================================
// CircuitState.String() Tests
// ============================================================================

func TestCircuitStateString(t *testing.T) {
	t.Parallel()
	t.Log("Testing CircuitState.String() returns human-readable names")
	tests := []struct {
		state    CircuitState
		expected string
	}{
		{CircuitClosed, "closed"},
		{CircuitOpen, "open"},
		{CircuitHalfOpen, "half-open"},
		{CircuitState(99), "unknown"}, // Unknown state
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			got := tt.state.String()
			if got != tt.expected {
				t.Errorf("CircuitState(%d).String() = %q, want %q", tt.state, got, tt.expected)
			}
		})
	}
}

// ============================================================================
// NewCircuitBreaker edge cases
// ============================================================================

func TestNewCircuitBreaker_ZeroConfig(t *testing.T) {
	t.Parallel()
	t.Log("Testing NewCircuitBreaker applies defaults for zero-value config")
	cfg := CircuitBreakerConfig{
		FailureThreshold: 0,
		ResetTimeout:     0,
	}
	cb := NewCircuitBreaker(cfg)

	// Verify defaults were applied
	if cb.cfg.FailureThreshold != 5 {
		t.Errorf("FailureThreshold = %d, want 5 (default)", cb.cfg.FailureThreshold)
	}
	if cb.cfg.ResetTimeout != 60*time.Second {
		t.Errorf("ResetTimeout = %v, want 60s (default)", cb.cfg.ResetTimeout)
	}
}

func TestNewCircuitBreaker_NegativeValues(t *testing.T) {
	t.Parallel()
	t.Log("Testing NewCircuitBreaker applies defaults for negative config values")
	cfg := CircuitBreakerConfig{
		FailureThreshold: -5,
		ResetTimeout:     -time.Second,
	}
	cb := NewCircuitBreaker(cfg)

	if cb.cfg.FailureThreshold != 5 {
		t.Errorf("FailureThreshold = %d, want 5 (default)", cb.cfg.FailureThreshold)
	}
	if cb.cfg.ResetTimeout != 60*time.Second {
		t.Errorf("ResetTimeout = %v, want 60s (default)", cb.cfg.ResetTimeout)
	}
}

// ============================================================================
// Retry edge cases
// ============================================================================

func TestRetry_ZeroMaxAttempts(t *testing.T) {
	t.Parallel()
	t.Log("Testing Retry treats zero MaxAttempts as 1")
	cfg := RetryConfig{
		MaxAttempts: 0,
	}

	var attempts int32
	Retry(context.Background(), cfg, func() error {
		atomic.AddInt32(&attempts, 1)
		return nil
	})

	if attempts != 1 {
		t.Errorf("attempts = %d, want 1 (zero max attempts should be treated as 1)", attempts)
	}
}

func TestRetry_NegativeMaxAttempts(t *testing.T) {
	t.Parallel()
	t.Log("Testing Retry treats negative MaxAttempts as 1")
	cfg := RetryConfig{
		MaxAttempts: -5,
	}

	var attempts int32
	Retry(context.Background(), cfg, func() error {
		atomic.AddInt32(&attempts, 1)
		return nil
	})

	if attempts != 1 {
		t.Errorf("attempts = %d, want 1 (negative max attempts should be treated as 1)", attempts)
	}
}

func TestRetry_ContextCancelledBeforeFirstAttempt(t *testing.T) {
	t.Parallel()
	t.Log("Testing Retry returns context.Canceled without executing when context already cancelled")
	cfg := RetryConfig{
		InitialDelay: time.Second,
		MaxAttempts:  3,
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	var attempts int32
	err := Retry(ctx, cfg, func() error {
		atomic.AddInt32(&attempts, 1)
		return nil
	})

	if !errors.Is(err, context.Canceled) {
		t.Errorf("error = %v, want context.Canceled", err)
	}
	if attempts != 0 {
		t.Errorf("attempts = %d, want 0 (context cancelled before first attempt)", attempts)
	}
}

func TestRetry_WithJitter(t *testing.T) {
	t.Parallel()
	t.Log("Testing Retry applies jitter to backoff delays")
	cfg := RetryConfig{
		InitialDelay: 10 * time.Millisecond,
		MaxDelay:     100 * time.Millisecond,
		Multiplier:   2.0,
		MaxAttempts:  3,
		Jitter:       0.5, // 50% jitter
	}

	start := time.Now()
	Retry(context.Background(), cfg, func() error {
		return ErrDOCANotConnected
	})
	elapsed := time.Since(start)

	// With jitter, delays should be: 10-15ms, 20-30ms
	// Total: at least 30ms (no jitter), at most 45ms (max jitter)
	if elapsed < 20*time.Millisecond {
		t.Errorf("elapsed %v too short, jitter may not be working", elapsed)
	}
}

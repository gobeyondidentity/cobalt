package transport

import (
	"context"
	"errors"
	"math/rand"
	"sync"
	"time"
)

// DOCA error sentinel values for retry classification.
// These map to DOCA SDK error codes for transport-level failures.
var (
	// Retryable errors - transient conditions that may resolve
	ErrDOCANotConnected    = errors.New("doca: not connected")
	ErrDOCAConnectionReset = errors.New("doca: connection reset")
	ErrDOCAAgain           = errors.New("doca: try again")
	ErrDOCAInProgress      = errors.New("doca: operation in progress")

	// Non-retryable errors - permanent failures
	ErrDOCAInvalidValue = errors.New("doca: invalid value")
	ErrDOCANotPermitted = errors.New("doca: not permitted")
	ErrDOCANotSupported = errors.New("doca: not supported")

	// Retry/circuit breaker errors
	ErrMaxRetriesExceeded = errors.New("retry: max attempts exceeded")
	ErrCircuitOpen        = errors.New("circuit breaker: circuit is open")
)

// retryableErrors contains all error types that should trigger a retry.
var retryableErrors = []error{
	ErrDOCANotConnected,
	ErrDOCAConnectionReset,
	ErrDOCAAgain,
	ErrDOCAInProgress,
}

// RetryConfig configures the retry behavior for DOCA operations.
type RetryConfig struct {
	// InitialDelay is the delay before the first retry. Default: 1s
	InitialDelay time.Duration

	// MaxDelay is the maximum delay between retries. Default: 30s
	MaxDelay time.Duration

	// Multiplier is the backoff multiplier applied after each retry. Default: 2.0
	Multiplier float64

	// MaxAttempts is the maximum number of attempts (including first try). Default: 10
	MaxAttempts int

	// Jitter is the random factor (0-1) added to delay to prevent thundering herd. Default: 0.1
	Jitter float64
}

// DefaultRetryConfig returns a RetryConfig with sensible defaults.
func DefaultRetryConfig() RetryConfig {
	return RetryConfig{
		InitialDelay: time.Second,
		MaxDelay:     30 * time.Second,
		Multiplier:   2.0,
		MaxAttempts:  10,
		Jitter:       0.1,
	}
}

// IsRetryable returns true if the error is a transient DOCA error that should be retried.
func IsRetryable(err error) bool {
	if err == nil {
		return false
	}

	for _, retryErr := range retryableErrors {
		if errors.Is(err, retryErr) {
			return true
		}
	}
	return false
}

// Retry executes fn with exponential backoff until it succeeds, returns a non-retryable error,
// or exhausts all attempts. Respects context cancellation.
func Retry(ctx context.Context, cfg RetryConfig, fn func() error) error {
	if cfg.MaxAttempts <= 0 {
		cfg.MaxAttempts = 1
	}

	delay := cfg.InitialDelay
	var lastErr error

	for attempt := 1; attempt <= cfg.MaxAttempts; attempt++ {
		// Check context before each attempt
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		lastErr = fn()
		if lastErr == nil {
			return nil
		}

		// Don't retry non-retryable errors
		if !IsRetryable(lastErr) {
			return lastErr
		}

		// Don't sleep after the last attempt
		if attempt == cfg.MaxAttempts {
			break
		}

		// Apply jitter
		actualDelay := delay
		if cfg.Jitter > 0 {
			jitterRange := float64(delay) * cfg.Jitter
			actualDelay = delay + time.Duration(rand.Float64()*jitterRange)
		}

		// Wait for delay or context cancellation
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(actualDelay):
		}

		// Increase delay for next iteration
		delay = time.Duration(float64(delay) * cfg.Multiplier)
		if delay > cfg.MaxDelay {
			delay = cfg.MaxDelay
		}
	}

	return errors.Join(ErrMaxRetriesExceeded, lastErr)
}

// CircuitState represents the state of a circuit breaker.
type CircuitState int

const (
	// CircuitClosed is the normal operating state where calls pass through.
	CircuitClosed CircuitState = iota

	// CircuitOpen is the tripped state where calls are rejected immediately.
	CircuitOpen

	// CircuitHalfOpen is the testing state after the reset timeout.
	// One call is allowed through to test if the system has recovered.
	CircuitHalfOpen
)

// String returns a human-readable circuit state name.
func (s CircuitState) String() string {
	switch s {
	case CircuitClosed:
		return "closed"
	case CircuitOpen:
		return "open"
	case CircuitHalfOpen:
		return "half-open"
	default:
		return "unknown"
	}
}

// CircuitBreakerConfig configures the circuit breaker behavior.
type CircuitBreakerConfig struct {
	// FailureThreshold is the number of consecutive failures before opening the circuit. Default: 5
	FailureThreshold int

	// ResetTimeout is how long to wait before attempting to reset from open state. Default: 60s
	ResetTimeout time.Duration
}

// DefaultCircuitBreakerConfig returns a CircuitBreakerConfig with sensible defaults.
func DefaultCircuitBreakerConfig() CircuitBreakerConfig {
	return CircuitBreakerConfig{
		FailureThreshold: 5,
		ResetTimeout:     60 * time.Second,
	}
}

// CircuitBreaker implements the circuit breaker pattern for DOCA operations.
// It prevents cascading failures by fast-failing when a service is unhealthy.
type CircuitBreaker struct {
	mu sync.Mutex

	cfg CircuitBreakerConfig

	state            CircuitState
	consecutiveFails int
	lastFailTime     time.Time
}

// NewCircuitBreaker creates a new circuit breaker with the given configuration.
func NewCircuitBreaker(cfg CircuitBreakerConfig) *CircuitBreaker {
	if cfg.FailureThreshold <= 0 {
		cfg.FailureThreshold = 5
	}
	if cfg.ResetTimeout <= 0 {
		cfg.ResetTimeout = 60 * time.Second
	}

	return &CircuitBreaker{
		cfg:   cfg,
		state: CircuitClosed,
	}
}

// State returns the current state of the circuit breaker.
// Note: this may transition from Open to HalfOpen if the reset timeout has elapsed.
func (cb *CircuitBreaker) State() CircuitState {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	return cb.stateLocked()
}

// stateLocked returns the current state, handling the Open->HalfOpen transition.
// Must be called with mu held.
func (cb *CircuitBreaker) stateLocked() CircuitState {
	if cb.state == CircuitOpen {
		if time.Since(cb.lastFailTime) >= cb.cfg.ResetTimeout {
			cb.state = CircuitHalfOpen
		}
	}
	return cb.state
}

// Execute runs the function through the circuit breaker.
// If the circuit is open, returns ErrCircuitOpen without calling fn.
// If the circuit is closed or half-open, calls fn and updates state based on result.
func (cb *CircuitBreaker) Execute(fn func() error) error {
	cb.mu.Lock()
	state := cb.stateLocked()

	if state == CircuitOpen {
		cb.mu.Unlock()
		return ErrCircuitOpen
	}

	cb.mu.Unlock()

	// Execute the function outside the lock
	err := fn()

	cb.mu.Lock()
	defer cb.mu.Unlock()

	if err != nil {
		cb.onFailure()
	} else {
		cb.onSuccess()
	}

	return err
}

// onFailure handles a failed call.
// Must be called with mu held.
func (cb *CircuitBreaker) onFailure() {
	cb.consecutiveFails++
	cb.lastFailTime = time.Now()

	// In half-open state, any failure reopens the circuit
	if cb.state == CircuitHalfOpen {
		cb.state = CircuitOpen
		return
	}

	// In closed state, trip after threshold
	if cb.consecutiveFails >= cb.cfg.FailureThreshold {
		cb.state = CircuitOpen
	}
}

// onSuccess handles a successful call.
// Must be called with mu held.
func (cb *CircuitBreaker) onSuccess() {
	cb.consecutiveFails = 0

	// Success in half-open state closes the circuit
	if cb.state == CircuitHalfOpen {
		cb.state = CircuitClosed
	}
}

// Reset manually resets the circuit breaker to closed state.
// Use this when you know the underlying issue has been resolved.
func (cb *CircuitBreaker) Reset() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.state = CircuitClosed
	cb.consecutiveFails = 0
}

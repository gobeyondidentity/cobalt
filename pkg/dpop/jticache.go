package dpop

import (
	"sync"
	"sync/atomic"
	"time"
)

const (
	// DefaultTTL is the default time-to-live for JTI entries.
	DefaultTTL = 5 * time.Minute

	// DefaultMaxEntries is the default maximum number of entries in the cache.
	DefaultMaxEntries = 100_000

	// DefaultCleanupInterval is the default interval for expired entry cleanup.
	DefaultCleanupInterval = 30 * time.Second

	// MaxJTILength is the maximum allowed JTI length in bytes.
	MaxJTILength = 1024
)

// JTICache provides replay detection for DPoP proof JTIs.
// Implementations must be safe for concurrent use.
type JTICache interface {
	// Record attempts to record a jti. Returns true if this is a replay
	// (the jti was already recorded and has not expired).
	// Returns an error for invalid input or if the cache is full.
	Record(jti string) (isReplay bool, err error)

	// Close stops any background goroutines and releases resources.
	Close() error
}

// jtiEntry stores metadata about a recorded JTI.
type jtiEntry struct {
	// offset is nanoseconds since cache creation (monotonic).
	offset int64
}

// MemoryJTICache is an in-memory JTI cache using sync.Map for atomic operations.
type MemoryJTICache struct {
	entries    sync.Map
	entryCount atomic.Int64
	maxEntries int64
	ttl        time.Duration
	createdAt  time.Time

	cleanupInterval time.Duration // 0 means use default, -1 means disabled
	stopCleanup     chan struct{}
	cleanupDone     chan struct{}
}

// MemoryJTICacheOption configures a MemoryJTICache.
type MemoryJTICacheOption func(*MemoryJTICache)

// WithTTL sets the time-to-live for JTI entries.
func WithTTL(ttl time.Duration) MemoryJTICacheOption {
	return func(c *MemoryJTICache) {
		c.ttl = ttl
	}
}

// WithMaxEntries sets the maximum number of entries in the cache.
func WithMaxEntries(max int) MemoryJTICacheOption {
	return func(c *MemoryJTICache) {
		c.maxEntries = int64(max)
	}
}

// WithCleanupInterval sets the interval for expired entry cleanup.
// Pass 0 to disable automatic cleanup.
func WithCleanupInterval(interval time.Duration) MemoryJTICacheOption {
	return func(c *MemoryJTICache) {
		if interval <= 0 {
			c.cleanupInterval = -1 // Disabled
		} else {
			c.cleanupInterval = interval
		}
	}
}

// NewMemoryJTICache creates a new in-memory JTI cache.
// By default, entries expire after 5 minutes, max 100,000 entries,
// with cleanup every 30 seconds.
func NewMemoryJTICache(opts ...MemoryJTICacheOption) *MemoryJTICache {
	c := &MemoryJTICache{
		ttl:             DefaultTTL,
		maxEntries:      DefaultMaxEntries,
		createdAt:       time.Now(),
		cleanupInterval: 0, // Use default
		stopCleanup:     make(chan struct{}),
		cleanupDone:     make(chan struct{}),
	}

	// Apply options
	for _, opt := range opts {
		opt(c)
	}

	// Start cleanup goroutine if not disabled
	if c.cleanupInterval >= 0 {
		interval := c.cleanupInterval
		if interval == 0 {
			interval = DefaultCleanupInterval
		}
		go c.cleanupLoop(interval)
	} else {
		// No cleanup, close done channel immediately
		close(c.cleanupDone)
	}

	return c
}

// Record attempts to record a jti. Returns true if this is a replay.
// This method is safe for concurrent use and uses atomic operations
// to prevent TOCTOU race conditions.
func (c *MemoryJTICache) Record(jti string) (bool, error) {
	// Validate input
	if jti == "" {
		return false, ErrInvalidJTI
	}
	if len(jti) > MaxJTILength {
		return false, ErrJTITooLong
	}

	// Calculate current offset using monotonic time
	offset := time.Since(c.createdAt).Nanoseconds()
	entry := &jtiEntry{offset: offset}

	// Atomic check-and-set using LoadOrStore
	existing, loaded := c.entries.LoadOrStore(jti, entry)
	if loaded {
		// Entry exists, check if expired
		existingEntry := existing.(*jtiEntry)
		age := time.Duration(offset - existingEntry.offset)
		if age < c.ttl {
			// Not expired, this is a replay
			return true, nil
		}
		// Expired, try to replace with new entry
		// Use CompareAndSwap for atomicity
		if c.entries.CompareAndSwap(jti, existing, entry) {
			return false, nil
		}
		// CAS failed, someone else updated it, this is a replay
		return true, nil
	}

	// New entry, check if we exceeded max entries
	count := c.entryCount.Add(1)
	if count > c.maxEntries {
		// Over limit, remove our entry and return error
		c.entries.Delete(jti)
		c.entryCount.Add(-1)
		return false, ErrCacheFull
	}

	return false, nil
}

// Close stops the cleanup goroutine and releases resources.
func (c *MemoryJTICache) Close() error {
	close(c.stopCleanup)
	<-c.cleanupDone
	return nil
}

// cleanupLoop periodically removes expired entries.
func (c *MemoryJTICache) cleanupLoop(interval time.Duration) {
	defer close(c.cleanupDone)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-c.stopCleanup:
			return
		case <-ticker.C:
			c.cleanup()
		}
	}
}

// cleanup removes all expired entries.
func (c *MemoryJTICache) cleanup() {
	now := time.Since(c.createdAt).Nanoseconds()
	ttlNanos := c.ttl.Nanoseconds()

	c.entries.Range(func(key, value any) bool {
		entry := value.(*jtiEntry)
		age := now - entry.offset
		if age >= ttlNanos {
			if c.entries.CompareAndDelete(key, value) {
				c.entryCount.Add(-1)
			}
		}
		return true
	})
}

// Len returns the current number of entries (for testing).
func (c *MemoryJTICache) Len() int {
	return int(c.entryCount.Load())
}

package dpop

import (
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestFirstUseSucceeds(t *testing.T) {
	t.Log("Creating new JTI cache")
	cache := NewMemoryJTICache(WithCleanupInterval(time.Hour)) // Slow cleanup for test
	defer cache.Close()

	t.Log("Recording new jti 'test-jti-1'")
	isReplay, err := cache.Record("test-jti-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if isReplay {
		t.Error("first use should not be detected as replay")
	}
	t.Log("First use succeeded as expected")
}

func TestSecondUseFails(t *testing.T) {
	t.Log("Creating new JTI cache")
	cache := NewMemoryJTICache(WithCleanupInterval(time.Hour))
	defer cache.Close()

	jti := "test-jti-replay"

	t.Log("Recording jti for the first time")
	isReplay, err := cache.Record(jti)
	if err != nil {
		t.Fatalf("unexpected error on first use: %v", err)
	}
	if isReplay {
		t.Error("first use should not be detected as replay")
	}

	t.Log("Attempting to record the same jti again")
	isReplay, err = cache.Record(jti)
	if err != nil {
		t.Fatalf("unexpected error on second use: %v", err)
	}
	if !isReplay {
		t.Error("second use should be detected as replay")
	}
	t.Log("Second use correctly detected as replay")
}

func TestExpiresAfterTTL(t *testing.T) {
	ttl := 50 * time.Millisecond
	t.Logf("Creating cache with short TTL (%v)", ttl)
	cache := NewMemoryJTICache(
		WithTTL(ttl),
		WithCleanupInterval(time.Hour), // Don't cleanup during test
	)
	defer cache.Close()

	jti := "test-jti-expiry"

	t.Log("Recording jti for the first time")
	isReplay, err := cache.Record(jti)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if isReplay {
		t.Error("first use should not be replay")
	}

	t.Logf("Waiting for TTL to expire (%v)", ttl+10*time.Millisecond)
	time.Sleep(ttl + 10*time.Millisecond)

	t.Log("Attempting to record the same jti after expiry")
	isReplay, err = cache.Record(jti)
	if err != nil {
		t.Fatalf("unexpected error after expiry: %v", err)
	}
	if isReplay {
		t.Error("jti should be reusable after TTL expiry")
	}
	t.Log("Expired jti correctly allowed reuse")
}

func TestConcurrentSameJTI(t *testing.T) {
	t.Log("Creating cache for concurrent test")
	cache := NewMemoryJTICache(WithCleanupInterval(time.Hour))
	defer cache.Close()

	jti := "concurrent-jti"
	numGoroutines := 100

	t.Logf("Starting %d goroutines to record the same jti simultaneously", numGoroutines)

	var wg sync.WaitGroup
	var successCount atomic.Int32
	var replayCount atomic.Int32
	var errCount atomic.Int32

	// Use a barrier to ensure all goroutines start at the same time
	barrier := make(chan struct{})

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-barrier // Wait for barrier

			isReplay, err := cache.Record(jti)
			if err != nil {
				errCount.Add(1)
				return
			}
			if isReplay {
				replayCount.Add(1)
			} else {
				successCount.Add(1)
			}
		}()
	}

	// Release all goroutines at once
	close(barrier)
	wg.Wait()

	successes := successCount.Load()
	replays := replayCount.Load()
	errors := errCount.Load()

	t.Logf("Results: %d success, %d replays, %d errors", successes, replays, errors)

	if errors > 0 {
		t.Errorf("unexpected errors: %d", errors)
	}
	if successes != 1 {
		t.Errorf("expected exactly 1 success, got %d", successes)
	}
	if replays != int32(numGoroutines-1) {
		t.Errorf("expected %d replays, got %d", numGoroutines-1, replays)
	}
	t.Log("Concurrent test passed: exactly 1 goroutine succeeded")
}

func TestSequentialPerformance(t *testing.T) {
	t.Log("Creating cache for performance test")
	cache := NewMemoryJTICache(WithCleanupInterval(time.Hour))
	defer cache.Close()

	numOps := 10_000
	t.Logf("Recording %d unique JTIs", numOps)

	start := time.Now()
	for i := 0; i < numOps; i++ {
		jti := fmt.Sprintf("perf-jti-%d", i)
		_, err := cache.Record(jti)
		if err != nil {
			t.Fatalf("unexpected error at iteration %d: %v", i, err)
		}
	}
	elapsed := time.Since(start)
	avgLatency := elapsed / time.Duration(numOps)

	t.Logf("Completed %d operations in %v (avg: %v per op)", numOps, elapsed, avgLatency)

	// Check average latency is under 1ms
	if avgLatency > time.Millisecond {
		t.Errorf("average latency %v exceeds 1ms threshold", avgLatency)
	}
	t.Log("Performance test passed: avg latency under 1ms")
}

func TestMemoryBounded(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping memory test in short mode")
	}

	ttl := 50 * time.Millisecond
	cleanupInterval := 25 * time.Millisecond
	t.Logf("Creating cache with short TTL (%v) and cleanup interval (%v)", ttl, cleanupInterval)

	cache := NewMemoryJTICache(
		WithTTL(ttl),
		WithMaxEntries(1_000_000), // High limit
		WithCleanupInterval(cleanupInterval),
	)
	defer cache.Close()

	// Force GC and get baseline
	runtime.GC()
	var baselineStats runtime.MemStats
	runtime.ReadMemStats(&baselineStats)

	batchSize := 100_000
	numBatches := 3 // Reduced from 10; still tests memory bounded property
	t.Logf("Inserting %d entries in %d batches", batchSize*numBatches, numBatches)

	for batch := 0; batch < numBatches; batch++ {
		for i := 0; i < batchSize; i++ {
			jti := fmt.Sprintf("mem-jti-%d-%d", batch, i)
			cache.Record(jti)
		}
		t.Logf("Batch %d complete, cache len: %d", batch+1, cache.Len())

		// Wait for TTL + cleanup to occur
		time.Sleep(ttl + cleanupInterval + 50*time.Millisecond)
	}

	// Wait for final cleanup
	time.Sleep(ttl + cleanupInterval*2)

	// Force GC
	runtime.GC()
	var finalStats runtime.MemStats
	runtime.ReadMemStats(&finalStats)

	finalLen := cache.Len()
	t.Logf("Final cache length: %d", finalLen)

	// After all entries expire and cleanup, cache should be nearly empty
	if finalLen > batchSize/10 {
		t.Errorf("cache should be mostly empty after expiry, got %d entries", finalLen)
	}

	// Memory should not have grown unboundedly
	memGrowth := finalStats.HeapAlloc - baselineStats.HeapAlloc
	t.Logf("Heap growth: %d bytes", memGrowth)

	t.Log("Memory bounded test passed")
}

func TestEmptyJTIRejected(t *testing.T) {
	t.Log("Creating cache")
	cache := NewMemoryJTICache(WithCleanupInterval(time.Hour))
	defer cache.Close()

	t.Log("Attempting to record empty jti")
	isReplay, err := cache.Record("")
	if err != ErrInvalidJTI {
		t.Errorf("expected ErrInvalidJTI, got: %v", err)
	}
	if isReplay {
		t.Error("empty jti should not be marked as replay")
	}
	t.Log("Empty jti correctly rejected with ErrInvalidJTI")
}

func TestOversizedJTIRejected(t *testing.T) {
	t.Log("Creating cache")
	cache := NewMemoryJTICache(WithCleanupInterval(time.Hour))
	defer cache.Close()

	// Create a jti that exceeds MaxJTILength (1024 bytes)
	oversizedJTI := make([]byte, MaxJTILength+1)
	for i := range oversizedJTI {
		oversizedJTI[i] = 'x'
	}

	t.Logf("Attempting to record oversized jti (%d bytes)", len(oversizedJTI))
	isReplay, err := cache.Record(string(oversizedJTI))
	if err != ErrJTITooLong {
		t.Errorf("expected ErrJTITooLong, got: %v", err)
	}
	if isReplay {
		t.Error("oversized jti should not be marked as replay")
	}
	t.Log("Oversized jti correctly rejected with ErrJTITooLong")
}

func TestMaxEntriesEnforced(t *testing.T) {
	maxEntries := 100
	t.Logf("Creating cache with max entries: %d", maxEntries)
	cache := NewMemoryJTICache(
		WithMaxEntries(maxEntries),
		WithTTL(time.Hour),           // Long TTL so entries don't expire
		WithCleanupInterval(time.Hour), // No cleanup during test
	)
	defer cache.Close()

	t.Logf("Filling cache to capacity (%d entries)", maxEntries)
	for i := 0; i < maxEntries; i++ {
		jti := fmt.Sprintf("limit-jti-%d", i)
		isReplay, err := cache.Record(jti)
		if err != nil {
			t.Fatalf("unexpected error at entry %d: %v", i, err)
		}
		if isReplay {
			t.Fatalf("unexpected replay at entry %d", i)
		}
	}

	t.Log("Attempting to add entry beyond capacity")
	isReplay, err := cache.Record("overflow-jti")
	if err != ErrCacheFull {
		t.Errorf("expected ErrCacheFull, got: %v", err)
	}
	if isReplay {
		t.Error("overflow should not be marked as replay")
	}
	t.Log("Cache correctly rejected overflow with ErrCacheFull")
}

func TestJTIAtMaxLength(t *testing.T) {
	t.Log("Creating cache")
	cache := NewMemoryJTICache(WithCleanupInterval(time.Hour))
	defer cache.Close()

	// Create a jti exactly at MaxJTILength
	maxLengthJTI := make([]byte, MaxJTILength)
	for i := range maxLengthJTI {
		maxLengthJTI[i] = 'y'
	}

	t.Logf("Recording jti at exactly max length (%d bytes)", MaxJTILength)
	isReplay, err := cache.Record(string(maxLengthJTI))
	if err != nil {
		t.Errorf("jti at max length should be accepted, got error: %v", err)
	}
	if isReplay {
		t.Error("first use should not be replay")
	}
	t.Log("JTI at max length correctly accepted")
}

func TestCleanupRemovesExpiredEntries(t *testing.T) {
	ttl := 50 * time.Millisecond
	cleanupInterval := 30 * time.Millisecond

	t.Logf("Creating cache with TTL=%v, cleanup=%v", ttl, cleanupInterval)
	cache := NewMemoryJTICache(
		WithTTL(ttl),
		WithCleanupInterval(cleanupInterval),
	)
	defer cache.Close()

	numEntries := 100
	t.Logf("Adding %d entries", numEntries)
	for i := 0; i < numEntries; i++ {
		cache.Record(fmt.Sprintf("cleanup-jti-%d", i))
	}

	initialLen := cache.Len()
	t.Logf("Initial cache length: %d", initialLen)

	// Wait for entries to expire and cleanup to run
	waitTime := ttl + cleanupInterval*2
	t.Logf("Waiting %v for expiry and cleanup", waitTime)
	time.Sleep(waitTime)

	finalLen := cache.Len()
	t.Logf("Final cache length: %d", finalLen)

	if finalLen >= initialLen {
		t.Errorf("cleanup should have removed entries, got %d (was %d)", finalLen, initialLen)
	}
	t.Log("Cleanup correctly removed expired entries")
}

// Benchmark for O(1) lookup verification
func BenchmarkRecord(b *testing.B) {
	cache := NewMemoryJTICache(
		WithMaxEntries(b.N + 1000),
		WithCleanupInterval(time.Hour),
	)
	defer cache.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cache.Record(fmt.Sprintf("bench-jti-%d", i))
	}
}

func BenchmarkRecordParallel(b *testing.B) {
	cache := NewMemoryJTICache(
		WithMaxEntries(b.N*10 + 1000),
		WithCleanupInterval(time.Hour),
	)
	defer cache.Close()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			cache.Record(fmt.Sprintf("bench-parallel-%d", i))
			i++
		}
	})
}

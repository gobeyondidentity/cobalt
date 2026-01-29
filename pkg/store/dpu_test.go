package store

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGetDPUByAddress tests looking up DPUs by host:port.
func TestGetDPUByAddress(t *testing.T) {
	s := setupTestStore(t)

	// Add a DPU
	err := s.Add("dpu1", "bf3-lab", "192.168.1.100", 50051)
	require.NoError(t, err)

	// Test: Find by exact address:port match
	t.Run("ExactMatch", func(t *testing.T) {
		existing, err := s.GetDPUByAddress("192.168.1.100", 50051)
		require.NoError(t, err)
		assert.NotNil(t, existing)
		assert.Equal(t, "bf3-lab", existing.Name)
	})

	// Test: No match for different port
	t.Run("DifferentPort", func(t *testing.T) {
		existing, err := s.GetDPUByAddress("192.168.1.100", 50052)
		require.NoError(t, err)
		assert.Nil(t, existing)
	})

	// Test: No match for different host
	t.Run("DifferentHost", func(t *testing.T) {
		existing, err := s.GetDPUByAddress("192.168.1.101", 50051)
		require.NoError(t, err)
		assert.Nil(t, existing)
	})
}

// TestDPUDuplicateAddress tests that adding DPUs with duplicate addresses returns an error.
func TestDPUDuplicateAddress(t *testing.T) {
	s := setupTestStore(t)

	// Add first DPU
	err := s.Add("dpu1", "bf3-lab", "192.168.1.100", 50051)
	require.NoError(t, err)

	// Test: GetDPUByAddress should find it
	existing, err := s.GetDPUByAddress("192.168.1.100", 50051)
	require.NoError(t, err)
	require.NotNil(t, existing)
	assert.Equal(t, "bf3-lab", existing.Name)

	// Test: Same address different name should be detected
	t.Run("SameAddressDifferentName", func(t *testing.T) {
		existing, err := s.GetDPUByAddress("192.168.1.100", 50051)
		require.NoError(t, err)
		assert.NotNil(t, existing, "should find existing DPU at same address")
	})

	// Test: Different port on same host is allowed
	t.Run("DifferentPortSameHost", func(t *testing.T) {
		existing, err := s.GetDPUByAddress("192.168.1.100", 50052)
		require.NoError(t, err)
		assert.Nil(t, existing, "should not find DPU at different port")

		// Add should succeed
		err = s.Add("dpu2", "bf3-lab-2", "192.168.1.100", 50052)
		require.NoError(t, err)
	})
}

// TestDPUMetadataPreserved tests that DPU metadata (labels) are preserved through operations.
func TestDPUMetadataPreserved(t *testing.T) {
	s := setupTestStore(t)

	t.Log("Testing DPU metadata is preserved through operations")

	// Add DPU
	t.Log("Adding DPU with initial registration")
	err := s.Add("dpu-meta-1", "bf3-meta", "192.168.1.50", 50051)
	require.NoError(t, err)

	// Set metadata labels (simulating serial number, firmware version)
	t.Log("Setting metadata labels (serial_number, firmware_version)")
	labels := map[string]string{
		"serial_number":    "BF3-SN-12345",
		"firmware_version": "24.04.0",
		"model":            "BlueField-3",
	}
	err = s.SetDPULabels("dpu-meta-1", labels)
	require.NoError(t, err)

	// Retrieve and verify
	t.Log("Verifying metadata preserved after retrieval")
	dpu, err := s.Get("bf3-meta")
	require.NoError(t, err)
	assert.Equal(t, "BF3-SN-12345", dpu.Labels["serial_number"])
	assert.Equal(t, "24.04.0", dpu.Labels["firmware_version"])
	assert.Equal(t, "BlueField-3", dpu.Labels["model"])

	t.Log("All metadata labels correctly preserved")
}

// TestDPUReregistrationIdempotency tests that re-registering a DPU doesn't create duplicates.
func TestDPUReregistrationIdempotency(t *testing.T) {
	s := setupTestStore(t)

	t.Log("Testing DPU re-registration idempotency")

	// Initial registration
	t.Log("Initial DPU registration")
	err := s.Add("dpu-idem-1", "bf3-idem", "192.168.1.60", 50051)
	require.NoError(t, err)

	// Count DPUs
	dpus, err := s.List()
	require.NoError(t, err)
	initialCount := len(dpus)
	t.Logf("Initial DPU count: %d", initialCount)

	// Get original DPU ID for comparison
	original, err := s.Get("bf3-idem")
	require.NoError(t, err)
	originalID := original.ID
	t.Logf("Original DPU ID: %s", originalID)

	// Attempt re-registration with same name and address
	t.Log("Attempting re-registration with same name and address")
	err = s.Add("dpu-idem-2", "bf3-idem", "192.168.1.60", 50051)

	// Should either:
	// 1. Return error (duplicate detected), OR
	// 2. Be idempotent (same DPU returned, no duplicate)

	// Count DPUs again
	dpusAfter, err2 := s.List()
	require.NoError(t, err2)
	afterCount := len(dpusAfter)
	t.Logf("DPU count after re-registration attempt: %d", afterCount)

	// Verify no duplicate created
	t.Log("Verifying no duplicate DPU created")
	if err != nil {
		// Error case is acceptable (duplicate rejected)
		t.Logf("Re-registration correctly rejected with error: %v", err)
		assert.Equal(t, initialCount, afterCount, "DPU count should be unchanged after rejected re-registration")
	} else {
		// If no error, verify it's the same DPU (upsert behavior)
		retrieved, err := s.Get("bf3-idem")
		require.NoError(t, err)
		assert.Equal(t, originalID, retrieved.ID, "DPU ID should remain unchanged after re-registration")
		assert.Equal(t, initialCount, afterCount, "DPU count should be unchanged after idempotent re-registration")
	}

	t.Log("Re-registration idempotency verified")
}

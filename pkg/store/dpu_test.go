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

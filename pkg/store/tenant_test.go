package store

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGetTenantDependencies tests the comprehensive dependency checking for tenants.
func TestGetTenantDependencies(t *testing.T) {
	// Enable insecure mode for test (no encryption key set)
	SetInsecureMode(true)
	defer SetInsecureMode(false)

	s := setupTestStore(t)

	// Create a tenant
	tenantID := "tnt_test"
	err := s.AddTenant(tenantID, "Test Tenant", "", "", nil)
	require.NoError(t, err)

	t.Run("NoDependencies", func(t *testing.T) {
		deps, err := s.GetTenantDependencies(tenantID)
		require.NoError(t, err)
		assert.Empty(t, deps.DPUs)
		assert.Empty(t, deps.Operators)
		assert.Empty(t, deps.CAs)
		assert.Equal(t, 0, deps.TrustRelationships)
		assert.False(t, deps.HasAny())
	})

	t.Run("WithDPUs", func(t *testing.T) {
		// Add DPUs and assign to tenant
		err := s.Add("dpu1", "bf3-test-1", "192.168.1.1", 50051)
		require.NoError(t, err)
		err = s.Add("dpu2", "bf3-test-2", "192.168.1.2", 50051)
		require.NoError(t, err)

		err = s.AssignDPUToTenant("dpu1", tenantID)
		require.NoError(t, err)
		err = s.AssignDPUToTenant("dpu2", tenantID)
		require.NoError(t, err)

		deps, err := s.GetTenantDependencies(tenantID)
		require.NoError(t, err)
		assert.Len(t, deps.DPUs, 2)
		assert.Contains(t, deps.DPUs, "bf3-test-1")
		assert.Contains(t, deps.DPUs, "bf3-test-2")
		assert.True(t, deps.HasAny())
	})

	t.Run("WithOperators", func(t *testing.T) {
		// Create operators and add to tenant
		err := s.CreateOperator("op1", "alice@example.com", "Alice")
		require.NoError(t, err)
		err = s.CreateOperator("op2", "bob@example.com", "Bob")
		require.NoError(t, err)

		err = s.AddOperatorToTenant("op1", tenantID, "admin")
		require.NoError(t, err)
		err = s.AddOperatorToTenant("op2", tenantID, "operator")
		require.NoError(t, err)

		deps, err := s.GetTenantDependencies(tenantID)
		require.NoError(t, err)
		assert.Len(t, deps.Operators, 2)
		assert.Contains(t, deps.Operators, "alice@example.com")
		assert.Contains(t, deps.Operators, "bob@example.com")
		assert.True(t, deps.HasAny())
	})

	t.Run("WithCAs", func(t *testing.T) {
		// Create an SSH CA for the tenant
		err := s.CreateSSHCA("ca1", "test-ca", []byte("pubkey"), []byte("privkey"), "ed25519", &tenantID)
		require.NoError(t, err)

		deps, err := s.GetTenantDependencies(tenantID)
		require.NoError(t, err)
		assert.Len(t, deps.CAs, 1)
		assert.Contains(t, deps.CAs, "test-ca")
		assert.True(t, deps.HasAny())
	})

	t.Run("WithTrustRelationships", func(t *testing.T) {
		// Create a trust relationship for the tenant
		tr := &TrustRelationship{
			ID:            "tr_test1",
			SourceHost:    "host1.example.com",
			TargetHost:    "host2.example.com",
			SourceDPUID:   "dpu1",
			SourceDPUName: "bf3-test-1",
			TargetDPUID:   "dpu2",
			TargetDPUName: "bf3-test-2",
			TenantID:      tenantID,
			TrustType:     TrustTypeSSHHost,
		}
		err := s.CreateTrustRelationship(tr)
		require.NoError(t, err)

		deps, err := s.GetTenantDependencies(tenantID)
		require.NoError(t, err)
		assert.Equal(t, 1, deps.TrustRelationships)
		assert.True(t, deps.HasAny())
	})

	t.Run("WithPendingInvites", func(t *testing.T) {
		// Create a pending invite code for the tenant
		invite := &InviteCode{
			ID:            "inv_test1",
			CodeHash:      "abc123hash",
			OperatorEmail: "newuser@example.com",
			TenantID:      tenantID,
			Role:          "operator",
			CreatedBy:     "admin@example.com",
			ExpiresAt:     time.Now().Add(24 * time.Hour),
			Status:        "pending",
		}
		err := s.CreateInviteCode(invite)
		require.NoError(t, err)

		deps, err := s.GetTenantDependencies(tenantID)
		require.NoError(t, err)
		assert.Equal(t, 1, deps.Invites)
		assert.True(t, deps.HasAny())
	})

	t.Run("UsedInvitesNotCounted", func(t *testing.T) {
		// Create a used invite code (should not be counted)
		usedInvite := &InviteCode{
			ID:            "inv_used",
			CodeHash:      "usedhash123",
			OperatorEmail: "useduser@example.com",
			TenantID:      tenantID,
			Role:          "operator",
			CreatedBy:     "admin@example.com",
			ExpiresAt:     time.Now().Add(24 * time.Hour),
			Status:        "used",
		}
		err := s.CreateInviteCode(usedInvite)
		require.NoError(t, err)

		deps, err := s.GetTenantDependencies(tenantID)
		require.NoError(t, err)
		// Should still be 1 from previous test, not 2
		assert.Equal(t, 1, deps.Invites)
	})

	t.Run("AllDependencies", func(t *testing.T) {
		// Verify all dependencies are collected
		deps, err := s.GetTenantDependencies(tenantID)
		require.NoError(t, err)

		assert.Len(t, deps.DPUs, 2)
		assert.Len(t, deps.Operators, 2)
		assert.Len(t, deps.CAs, 1)
		assert.Equal(t, 1, deps.TrustRelationships)
		assert.Equal(t, 1, deps.Invites) // Only pending invites
		assert.True(t, deps.HasAny())
	})

	t.Run("NonExistentTenant", func(t *testing.T) {
		deps, err := s.GetTenantDependencies("nonexistent")
		require.NoError(t, err)
		assert.Empty(t, deps.DPUs)
		assert.Empty(t, deps.Operators)
		assert.Empty(t, deps.CAs)
		assert.Equal(t, 0, deps.TrustRelationships)
		assert.Equal(t, 0, deps.Invites)
		assert.False(t, deps.HasAny())
	})
}

// TestTenantDependenciesHasAny tests the HasAny method on TenantDependencies.
func TestTenantDependenciesHasAny(t *testing.T) {
	tests := []struct {
		name     string
		deps     TenantDependencies
		expected bool
	}{
		{
			name:     "Empty",
			deps:     TenantDependencies{},
			expected: false,
		},
		{
			name: "OnlyDPUs",
			deps: TenantDependencies{
				DPUs: []string{"dpu1"},
			},
			expected: true,
		},
		{
			name: "OnlyOperators",
			deps: TenantDependencies{
				Operators: []string{"alice@example.com"},
			},
			expected: true,
		},
		{
			name: "OnlyCAs",
			deps: TenantDependencies{
				CAs: []string{"my-ca"},
			},
			expected: true,
		},
		{
			name: "OnlyTrustRelationships",
			deps: TenantDependencies{
				TrustRelationships: 1,
			},
			expected: true,
		},
		{
			name: "OnlyInvites",
			deps: TenantDependencies{
				Invites: 1,
			},
			expected: true,
		},
		{
			name: "AllEmpty",
			deps: TenantDependencies{
				DPUs:               []string{},
				Operators:          []string{},
				CAs:                []string{},
				TrustRelationships: 0,
				Invites:            0,
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.deps.HasAny())
		})
	}
}

// TestAddTenantDuplicateName verifies that creating a tenant with a duplicate
// name returns a user-friendly error message, not raw SQL errors.
func TestAddTenantDuplicateName(t *testing.T) {
	s := setupTestStore(t)

	// Create initial tenant
	err := s.AddTenant("tnt_first", "Production", "", "", nil)
	require.NoError(t, err)

	// Attempt to create another tenant with the same name
	err = s.AddTenant("tnt_second", "Production", "", "", nil)
	require.Error(t, err)

	// Verify error message is user-friendly
	errMsg := err.Error()

	// Should NOT contain raw SQL error
	assert.False(t, strings.Contains(errMsg, "UNIQUE constraint failed"),
		"error should not expose raw SQL: %s", errMsg)

	// Should contain the tenant name for context
	assert.True(t, strings.Contains(errMsg, "Production"),
		"error should mention the tenant name: %s", errMsg)

	// Should indicate it already exists
	assert.True(t, strings.Contains(errMsg, "already exists"),
		"error should say 'already exists': %s", errMsg)
}

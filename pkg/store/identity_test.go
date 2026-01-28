package store

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestGenerateInviteCode(t *testing.T) {
	tests := []struct {
		name           string
		prefix         string
		wantSingleDash bool // first separator should be single dash, not double
	}{
		{
			name:           "clean prefix without dash",
			prefix:         "GPU",
			wantSingleDash: true,
		},
		{
			name:           "prefix with trailing dash",
			prefix:         "GPU-",
			wantSingleDash: true,
		},
		{
			name:           "four char prefix without dash",
			prefix:         "ACME",
			wantSingleDash: true,
		},
		{
			name:           "prefix with multiple trailing dashes",
			prefix:         "AB--",
			wantSingleDash: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code := GenerateInviteCode(tt.prefix)

			// Should have format PREFIX-XXXX-XXXX
			parts := strings.Split(code, "-")
			assert.Len(t, parts, 3, "invite code should have 3 parts separated by dashes")

			// First part should be prefix without trailing dashes
			expectedPrefix := strings.TrimRight(strings.ToUpper(tt.prefix), "-")
			assert.Equal(t, expectedPrefix, parts[0], "prefix should not have trailing dashes")

			// Second and third parts should be 4 chars each
			assert.Len(t, parts[1], 4, "second part should be 4 characters")
			assert.Len(t, parts[2], 4, "third part should be 4 characters")

			// Should not contain double dashes
			assert.NotContains(t, code, "--", "invite code should not contain double dashes")
		})
	}
}

func TestGenerateInviteCodeFormat(t *testing.T) {
	// Generate multiple codes to verify randomness and format
	codes := make(map[string]bool)
	for i := 0; i < 100; i++ {
		code := GenerateInviteCode("TEST")
		codes[code] = true

		// Verify format
		assert.True(t, strings.HasPrefix(code, "TEST-"), "code should start with TEST-")
		assert.Len(t, code, 14, "code should be 14 chars: TEST-XXXX-XXXX")
	}

	// Should generate unique codes (collision extremely unlikely)
	assert.Greater(t, len(codes), 90, "should generate mostly unique codes")
}

func TestHashInviteCode(t *testing.T) {
	code := "TEST-ABCD-1234"
	hash := HashInviteCode(code)

	// SHA-256 produces 64 hex characters
	assert.Len(t, hash, 64)

	// Same input produces same hash
	assert.Equal(t, hash, HashInviteCode(code))

	// Different input produces different hash
	assert.NotEqual(t, hash, HashInviteCode("TEST-ABCD-5678"))
}

// TestCrossConnectionInviteCodeVisibility tests that invite codes created
// by one database connection are immediately visible to another connection.
// This simulates the scenario where the CLI creates an invite code and
// the Nexus server needs to validate it without a restart.
func TestCrossConnectionInviteCodeVisibility(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := tmpDir + "/test.db"

	// Open first connection (simulates Nexus server)
	SetInsecureMode(true)
	serverConn, err := Open(dbPath)
	if err != nil {
		t.Fatalf("failed to open server connection: %v", err)
	}
	defer serverConn.Close()

	// Create a tenant via server connection
	err = serverConn.AddTenant("tenant1", "Test Tenant", "desc", "contact", []string{})
	if err != nil {
		t.Fatalf("failed to create tenant: %v", err)
	}

	// Create an operator via server connection
	err = serverConn.CreateOperator("op1", "test@example.com", "Test")
	if err != nil {
		t.Fatalf("failed to create operator: %v", err)
	}

	// Open second connection (simulates CLI)
	cliConn, err := Open(dbPath)
	if err != nil {
		t.Fatalf("failed to open CLI connection: %v", err)
	}
	defer cliConn.Close()

	// Create invite code via CLI connection
	inviteCode := GenerateInviteCode("TEST")
	codeHash := HashInviteCode(inviteCode)
	invite := &InviteCode{
		ID:            "inv1",
		CodeHash:      codeHash,
		OperatorEmail: "test@example.com",
		TenantID:      "tenant1",
		Role:          "operator",
		CreatedBy:     "cli",
		ExpiresAt:     DefaultExpirationTime(),
		Status:        "pending",
	}
	err = cliConn.CreateInviteCode(invite)
	if err != nil {
		t.Fatalf("failed to create invite code via CLI: %v", err)
	}

	// CRITICAL: Without WAL mode, this lookup would fail because the server
	// connection wouldn't see the invite code created by the CLI connection.
	// With WAL mode enabled, the server connection should immediately see the new invite.
	foundInvite, err := serverConn.GetInviteCodeByHash(codeHash)
	if err != nil {
		t.Fatalf("server connection failed to find invite code created by CLI: %v", err)
	}

	assert.Equal(t, "inv1", foundInvite.ID)
	assert.Equal(t, "test@example.com", foundInvite.OperatorEmail)
	assert.Equal(t, "pending", foundInvite.Status)
}

// DefaultExpirationTime returns a time 24 hours from now for testing.
func DefaultExpirationTime() time.Time {
	return time.Now().Add(24 * time.Hour)
}

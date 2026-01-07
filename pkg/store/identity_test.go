package store

import (
	"strings"
	"testing"

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

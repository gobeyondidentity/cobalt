package api

import (
	"testing"

	"github.com/gobeyondidentity/secure-infra/pkg/dpop"
)

func TestMapDPUStatus(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected dpop.IdentityStatus
	}{
		// Valid statuses that map to Active
		{
			name:     "healthy status maps to Active",
			input:    "healthy",
			expected: dpop.IdentityStatusActive,
		},
		{
			name:     "enrolled status maps to Active",
			input:    "enrolled",
			expected: dpop.IdentityStatusActive,
		},
		{
			name:     "active status maps to Active",
			input:    "active",
			expected: dpop.IdentityStatusActive,
		},

		// Valid statuses that map to their respective states
		{
			name:     "suspended status maps to Suspended",
			input:    "suspended",
			expected: dpop.IdentityStatusSuspended,
		},
		{
			name:     "revoked status maps to Revoked",
			input:    "revoked",
			expected: dpop.IdentityStatusRevoked,
		},
		{
			name:     "decommissioned status maps to Decommissioned",
			input:    "decommissioned",
			expected: dpop.IdentityStatusDecommissioned,
		},

		// Unknown statuses should default to Revoked (deny by default)
		{
			name:     "pending status defaults to Revoked",
			input:    "pending",
			expected: dpop.IdentityStatusRevoked,
		},
		{
			name:     "unhealthy status defaults to Revoked",
			input:    "unhealthy",
			expected: dpop.IdentityStatusRevoked,
		},
		{
			name:     "unknown status defaults to Revoked",
			input:    "unknown",
			expected: dpop.IdentityStatusRevoked,
		},
		{
			name:     "empty string defaults to Revoked",
			input:    "",
			expected: dpop.IdentityStatusRevoked,
		},
		{
			name:     "garbage input defaults to Revoked",
			input:    "foobar123",
			expected: dpop.IdentityStatusRevoked,
		},
		{
			name:     "ACTIVE uppercase defaults to Revoked (case sensitive)",
			input:    "ACTIVE",
			expected: dpop.IdentityStatusRevoked,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Logf("Testing mapDPUStatus with input %q", tc.input)

			result := mapDPUStatus(tc.input)

			t.Logf("Expected: %q, Got: %q", tc.expected, result)

			if result != tc.expected {
				t.Errorf("mapDPUStatus(%q) = %q, want %q", tc.input, result, tc.expected)
			}
		})
	}
}

func TestMapDPUStatus_SecurityProperty(t *testing.T) {
	t.Log("Verifying security property: unknown statuses must deny by default")

	unknownStatuses := []string{
		"pending",
		"unhealthy",
		"initializing",
		"error",
		"offline",
		"maintenance",
		"",
		"  ",
		"Active", // wrong case
		"HEALTHY",
	}

	for _, status := range unknownStatuses {
		t.Run("unknown_"+status, func(t *testing.T) {
			t.Logf("Checking that unknown status %q maps to Revoked", status)

			result := mapDPUStatus(status)

			if result != dpop.IdentityStatusRevoked {
				t.Errorf("SECURITY VIOLATION: mapDPUStatus(%q) = %q, but unknown statuses must return Revoked", status, result)
			}
		})
	}
}

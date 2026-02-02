package enrollment

import (
	"encoding/base64"
	"testing"
)

func TestGenerateInviteCode(t *testing.T) {
	t.Parallel()
	t.Log("Generating single invite code")
	code, err := GenerateInviteCode()
	if err != nil {
		t.Fatalf("GenerateInviteCode() error = %v", err)
	}

	t.Log("Verifying code is valid base64url")
	decoded, err := base64.RawURLEncoding.DecodeString(code)
	if err != nil {
		t.Errorf("GenerateInviteCode() produced invalid base64url: %v", err)
	}

	t.Log("Verifying decoded length is 16 bytes (128 bits)")
	if len(decoded) != 16 {
		t.Errorf("GenerateInviteCode() decoded length = %d, want 16", len(decoded))
	}
}

func TestGenerateInviteCodeUniqueness(t *testing.T) {
	t.Parallel()
	const iterations = 10000
	t.Logf("Generating %d invite codes to verify uniqueness", iterations)

	seen := make(map[string]bool, iterations)

	for i := 0; i < iterations; i++ {
		code, err := GenerateInviteCode()
		if err != nil {
			t.Fatalf("GenerateInviteCode() iteration %d error = %v", i, err)
		}

		if seen[code] {
			t.Errorf("GenerateInviteCode() produced duplicate at iteration %d", i)
		}
		seen[code] = true
	}

	t.Logf("All %d codes were unique", iterations)
}

func TestHashCode(t *testing.T) {
	t.Parallel()
	t.Log("Testing HashCode produces consistent results")
	code := "test-invite-code-123"

	hash1 := HashCode(code)
	hash2 := HashCode(code)

	if hash1 != hash2 {
		t.Errorf("HashCode() not deterministic: %q != %q", hash1, hash2)
	}

	t.Log("Verifying hash is 64 characters (SHA256 hex)")
	if len(hash1) != 64 {
		t.Errorf("HashCode() length = %d, want 64", len(hash1))
	}
}

func TestHashCodeDifferentInputs(t *testing.T) {
	t.Parallel()
	t.Log("Testing HashCode produces different results for different inputs")
	code1 := "invite-code-1"
	code2 := "invite-code-2"

	hash1 := HashCode(code1)
	hash2 := HashCode(code2)

	if hash1 == hash2 {
		t.Error("HashCode() produced same hash for different codes")
	}
}

func TestValidateCodeHash(t *testing.T) {
	t.Parallel()
	t.Log("Testing ValidateCodeHash with valid code/hash pair")
	code := "test-validation-code"
	hash := HashCode(code)

	if !ValidateCodeHash(code, hash) {
		t.Error("ValidateCodeHash() returned false for valid pair")
	}
}

func TestValidateCodeHashInvalid(t *testing.T) {
	t.Parallel()
	t.Log("Testing ValidateCodeHash with mismatched code/hash")
	code := "original-code"
	wrongHash := HashCode("different-code")

	if ValidateCodeHash(code, wrongHash) {
		t.Error("ValidateCodeHash() returned true for invalid pair")
	}
}

func TestValidateCodeHashConstantTime(t *testing.T) {
	t.Parallel()
	// This test verifies the function works correctly with various inputs.
	// Actual timing analysis would require statistical measurements.
	t.Log("Testing ValidateCodeHash with edge cases")

	tests := []struct {
		name  string
		code  string
		hash  string
		valid bool
	}{
		{"EmptyCode", "", HashCode(""), true},
		{"EmptyHash", "code", "", false},
		{"PartialMatch", "code", HashCode("code")[:32] + "0000000000000000000000000000000000000000000000000000000000000000"[:32], false},
		{"ValidPair", "my-code", HashCode("my-code"), true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Logf("Validating code=%q against hash=%q", tc.code, tc.hash)
			got := ValidateCodeHash(tc.code, tc.hash)
			if got != tc.valid {
				t.Errorf("ValidateCodeHash(%q, %q) = %v, want %v", tc.code, tc.hash, got, tc.valid)
			}
		})
	}
}

func TestInviteCodeNoStandardPadding(t *testing.T) {
	t.Parallel()
	t.Log("Verifying invite codes use base64url without padding")
	for i := 0; i < 100; i++ {
		code, err := GenerateInviteCode()
		if err != nil {
			t.Fatalf("GenerateInviteCode() error = %v", err)
		}

		// Check no padding characters
		for _, c := range code {
			if c == '=' {
				t.Errorf("GenerateInviteCode() contains padding character at iteration %d", i)
			}
			// Also verify URL-safe characters only
			if c == '+' || c == '/' {
				t.Errorf("GenerateInviteCode() contains non-URL-safe character at iteration %d", i)
			}
		}
	}
}

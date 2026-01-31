package enrollment

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

// InviteCodeSize is the number of bytes in a generated invite code (128 bits).
const InviteCodeSize = 16

// GenerateInviteCode generates a 16-byte (128-bit) cryptographically random
// invite code and returns it as a base64url-encoded string without padding.
//
// Uses crypto/rand for secure entropy; never uses math/rand.
//
// SECURITY: The plaintext code should be zero-cleared after hashing
// in caller code to minimize exposure window. The returned string
// should be transmitted to the user and then discarded; only store
// the hash from HashCode().
func GenerateInviteCode() (string, error) {
	codeBytes := make([]byte, InviteCodeSize)
	_, err := rand.Read(codeBytes)
	if err != nil {
		return "", fmt.Errorf("failed to generate invite code: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(codeBytes), nil
}

// HashCode computes the SHA256 hash of an invite code.
// Returns a lowercase hex string (64 characters).
//
// Use this to store invite codes; never store the plaintext code.
func HashCode(code string) string {
	hash := sha256.Sum256([]byte(code))
	return hex.EncodeToString(hash[:])
}

// ValidateCodeHash validates an invite code against its stored hash
// using constant-time comparison to prevent timing attacks.
//
// Returns true if the code matches the hash, false otherwise.
func ValidateCodeHash(code, hash string) bool {
	computedHash := HashCode(code)
	// Convert to bytes for constant-time comparison
	computedBytes := []byte(computedHash)
	hashBytes := []byte(hash)

	// Use constant-time comparison to prevent timing attacks
	return subtle.ConstantTimeCompare(computedBytes, hashBytes) == 1
}

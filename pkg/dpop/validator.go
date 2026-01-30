package dpop

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"
)

const (
	// maxProofSize is the maximum allowed size of a DPoP proof in bytes.
	// This prevents DoS attacks via oversized proofs.
	maxProofSize = 8 * 1024 // 8KB
)

// KeyLookup is a function that retrieves the public key for a given kid.
// Returns nil if the key is not found.
type KeyLookup func(kid string) ed25519.PublicKey

// ValidatorConfig contains configuration for DPoP proof validation.
type ValidatorConfig struct {
	// ClockSkew is the maximum allowed difference between proof iat and server time.
	// Default: 60 seconds per RFC 9449
	ClockSkew time.Duration

	// MaxProofAge is the maximum age of a proof (iat in the past).
	// Default: 60 seconds
	MaxProofAge time.Duration
}

// DefaultValidatorConfig returns the default validator configuration.
func DefaultValidatorConfig() ValidatorConfig {
	return ValidatorConfig{
		ClockSkew:   60 * time.Second,
		MaxProofAge: 60 * time.Second,
	}
}

// Validator validates DPoP proofs.
type Validator struct {
	config ValidatorConfig
}

// NewValidator creates a new DPoP proof validator.
func NewValidator(config ValidatorConfig) *Validator {
	return &Validator{config: config}
}

// ValidateProof validates a DPoP proof and returns the kid if valid.
// The keyLookup function is called to retrieve the public key for the kid.
// Returns (kid, nil) on success, or ("", error) on failure.
//
// Validation order (per security requirements):
// 1. Empty check: proof cannot be empty string (returns dpop.missing_proof)
// 2. Format check: exactly 3 base64url parts separated by dots
// 3. Size limit: reject proofs > 8KB total
// 4. Parse header: base64url decode, JSON unmarshal
// 5. typ check: must equal "dpop+jwt" exactly
// 6. alg check: must equal "EdDSA" exactly (algorithm confusion prevention)
// 7. Parse payload: base64url decode, JSON unmarshal
// 8. kid presence: kid must be non-empty in header
// 9. Key lookup: call keyLookup(kid); if nil, return ErrUnknownKey
// 10. Signature verify: ed25519.Verify(publicKey, signingInput, signature)
// 11. htm check: must match method parameter (case-sensitive)
// 12. htu check: must match normalized uri parameter
// 13. iat check: must be within ClockSkew of current time
func (v *Validator) ValidateProof(proof, method, uri string, keyLookup KeyLookup) (string, error) {
	// Step 1: Check proof is not empty
	if proof == "" {
		return "", ErrMissingProof()
	}

	// Step 2: Format check - exactly 3 parts
	parts := strings.Split(proof, ".")
	if len(parts) != 3 {
		return "", ErrInvalidProof("JWT must have exactly 3 parts")
	}

	// Check for empty parts
	if parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return "", ErrInvalidProof("JWT parts cannot be empty")
	}

	// Step 2: Size limit
	if len(proof) > maxProofSize {
		return "", ErrInvalidProof("proof exceeds maximum size of 8KB")
	}

	// Step 3: Parse header
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", ErrInvalidProof("invalid base64url encoding in header")
	}

	var header Header
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return "", ErrInvalidProof("invalid JSON in header")
	}

	// Step 4: typ check - must equal "dpop+jwt" exactly
	if header.Typ != TypeDPoP {
		return "", ErrInvalidProof("typ must be \"dpop+jwt\"")
	}

	// Step 5: alg check - must equal "EdDSA" exactly
	// CRITICAL: This is hardcoded to prevent algorithm confusion attacks.
	// We NEVER use the alg from the header to select the verification algorithm.
	if header.Alg != AlgEdDSA {
		return "", ErrInvalidProof("alg must be \"EdDSA\"")
	}

	// Step 6: Parse payload
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", ErrInvalidProof("invalid base64url encoding in payload")
	}

	var claims Claims
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return "", ErrInvalidProof("invalid JSON in payload")
	}

	// Check required claims presence
	if claims.HTM == "" {
		return "", ErrInvalidProof("htm claim is required")
	}
	if claims.HTU == "" {
		return "", ErrInvalidProof("htu claim is required")
	}

	// Step 7: kid presence check
	if header.Kid == "" {
		return "", ErrInvalidProof("kid is required in header")
	}

	// Step 8: Key lookup
	publicKey := keyLookup(header.Kid)
	if publicKey == nil {
		return "", ErrUnknownKey(header.Kid)
	}

	// Validate public key length
	if len(publicKey) != ed25519.PublicKeySize {
		return "", ErrInvalidProof("invalid public key size")
	}

	// Step 9: Signature verification
	signatureBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return "", ErrInvalidProof("invalid base64url encoding in signature")
	}

	// Ed25519 signature must be exactly 64 bytes
	if len(signatureBytes) != ed25519.SignatureSize {
		return "", ErrInvalidSignature()
	}

	// The signing input is "header.payload" (the first two parts)
	signingInput := parts[0] + "." + parts[1]

	// Use ed25519.Verify which is inherently constant-time
	if !ed25519.Verify(publicKey, []byte(signingInput), signatureBytes) {
		return "", ErrInvalidSignature()
	}

	// Step 10: htm check - must match method parameter (case-sensitive)
	if claims.HTM != method {
		return "", ErrMethodMismatch(claims.HTM, method)
	}

	// Step 11: htu check - must match normalized uri parameter
	normalizedProofURI, err := NormalizeURI(claims.HTU)
	if err != nil {
		return "", ErrInvalidProof("invalid htu URL")
	}
	normalizedRequestURI, err := NormalizeURI(uri)
	if err != nil {
		return "", ErrInvalidProof("invalid request URI")
	}
	if normalizedProofURI != normalizedRequestURI {
		return "", ErrURIMismatch(normalizedProofURI, normalizedRequestURI)
	}

	// Step 12: iat check - must be within acceptable window
	now := time.Now().Unix()
	iat := claims.IAT

	// iat must be positive (0 is invalid, as is negative)
	if iat <= 0 {
		return "", ErrIATNonPositive()
	}

	// Check if iat is too far in the past
	age := now - iat
	maxAge := int64(v.config.MaxProofAge.Seconds())
	if age > maxAge {
		return "", ErrInvalidIAT(age, maxAge)
	}

	// Check if iat is too far in the future (clock skew)
	if iat > now+int64(v.config.ClockSkew.Seconds()) {
		futureOffset := iat - now
		return "", ErrInvalidIAT(-futureOffset, maxAge)
	}

	return header.Kid, nil
}

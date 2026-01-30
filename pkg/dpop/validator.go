package dpop

import (
	"crypto/ed25519"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
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

// validatorClaims represents the claims we extract from DPoP proofs.
type validatorClaims struct {
	JTI string `json:"jti"`
	HTM string `json:"htm"`
	HTU string `json:"htu"`
	IAT int64  `json:"iat"`
}

// ValidateProof validates a DPoP proof and returns the kid if valid.
// The keyLookup function is called to retrieve the public key for the kid.
// Returns (kid, nil) on success, or ("", error) on failure.
//
// Validation order (per security requirements):
// 1. Empty check: proof cannot be empty string (returns dpop.missing_proof)
// 2. Size limit: reject proofs > 8KB BEFORE any parsing (DoS prevention)
// 3. Parse with go-jose: ONLY accept EdDSA algorithm (algorithm confusion prevention)
// 4. typ check: must equal "dpop+jwt" exactly
// 5. kid presence: kid must be non-empty in header
// 6. Key lookup: call keyLookup(kid); if nil, return ErrUnknownKey
// 7. Signature verify: via go-jose Claims extraction with public key
// 8. htm check: must match method parameter (case-sensitive)
// 9. htu check: must match normalized uri parameter
// 10. iat check: must be within ClockSkew of current time
func (v *Validator) ValidateProof(proof, method, uri string, keyLookup KeyLookup) (string, error) {
	// Step 1: Check proof is not empty
	if proof == "" {
		return "", ErrMissingProof()
	}

	// Step 2: Size limit BEFORE any parsing (DoS prevention)
	// CRITICAL: This must happen before go-jose parsing to prevent memory exhaustion
	if len(proof) > maxProofSize {
		return "", ErrInvalidProof("proof exceeds maximum size of 8KB")
	}

	// Step 3: Parse with go-jose, using ONLY EdDSA algorithm
	// CRITICAL: The algorithm allowlist prevents algorithm confusion attacks (CVE-2015-2951)
	// We ONLY accept EdDSA - any other algorithm in the header will be rejected
	parsedJWT, err := jwt.ParseSigned(proof, []jose.SignatureAlgorithm{jose.EdDSA})
	if err != nil {
		return "", ErrInvalidProof("failed to parse JWT: " + err.Error())
	}

	// Verify we have at least one signature
	if len(parsedJWT.Headers) == 0 {
		return "", ErrInvalidProof("JWT has no headers")
	}

	// Get the first (and should be only) header
	header := parsedJWT.Headers[0]

	// Step 4: typ check - must equal "dpop+jwt" exactly
	// CRITICAL: go-jose doesn't enforce typ, so we must check explicitly
	typ, ok := header.ExtraHeaders["typ"]
	if !ok {
		return "", ErrInvalidProof("typ must be \"dpop+jwt\"")
	}
	typStr, ok := typ.(string)
	if !ok || typStr != TypeDPoP {
		return "", ErrInvalidProof("typ must be \"dpop+jwt\"")
	}

	// Step 5: kid presence check
	if header.KeyID == "" {
		return "", ErrInvalidProof("kid is required in header")
	}

	// Step 6: Key lookup
	publicKey := keyLookup(header.KeyID)
	if publicKey == nil {
		return "", ErrUnknownKey(header.KeyID)
	}

	// Validate public key length
	if len(publicKey) != ed25519.PublicKeySize {
		return "", ErrInvalidProof("invalid public key size")
	}

	// Step 7: Signature verification and claims extraction
	// go-jose verifies the signature when extracting claims
	var claims validatorClaims
	if err := parsedJWT.Claims(publicKey, &claims); err != nil {
		return "", ErrInvalidSignature()
	}

	// Check required claims presence
	if claims.HTM == "" {
		return "", ErrInvalidProof("htm claim is required")
	}
	if claims.HTU == "" {
		return "", ErrInvalidProof("htu claim is required")
	}

	// Step 8: htm check - must match method parameter (case-sensitive)
	if claims.HTM != method {
		return "", ErrMethodMismatch(claims.HTM, method)
	}

	// Step 9: htu check - must match normalized uri parameter
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

	// Step 10: iat check - must be within acceptable window
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

	return header.KeyID, nil
}

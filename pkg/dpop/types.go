// Package dpop provides DPoP proof types and utilities for RFC 9449 authentication.
//
// DPoP (Demonstrating Proof of Possession) binds requests to the caller's key,
// preventing token theft and replay attacks. This package provides the core types
// for constructing and validating DPoP proofs.
//
// Reference: RFC 9449 (OAuth 2.0 Demonstrating Proof of Possession)
package dpop

// Type and algorithm constants. These are compile-time constants per security requirements.
// The algorithm MUST be EdDSA; other algorithms are not permitted.
const (
	// TypeDPoP is the required typ header value for DPoP proofs.
	TypeDPoP = "dpop+jwt"

	// AlgEdDSA is the only permitted algorithm for DPoP proofs.
	// This is a security requirement, not a configuration option.
	AlgEdDSA = "EdDSA"
)

// Header contains the JOSE header claims for a DPoP proof JWT.
// Per RFC 9449, the header must contain typ, alg, and either kid or jwk.
type Header struct {
	// Typ must be "dpop+jwt" (required)
	Typ string `json:"typ"`

	// Alg must be "EdDSA" for Ed25519 signatures (required)
	Alg string `json:"alg"`

	// Kid is the server-assigned key identifier, used after enrollment.
	// Mutually exclusive with JWK (use one or the other).
	Kid string `json:"kid,omitempty"`

	// JWK contains the public key for initial enrollment requests.
	// Mutually exclusive with Kid (use one or the other).
	JWK *JWK `json:"jwk,omitempty"`
}

// Claims contains the payload claims for a DPoP proof JWT.
// These claims bind the proof to a specific HTTP request.
type Claims struct {
	// JTI is a unique token identifier (UUID) for replay prevention (required)
	JTI string `json:"jti"`

	// HTM is the HTTP method of the request (e.g., "POST", "GET") (required)
	HTM string `json:"htm"`

	// HTU is the HTTP URI of the request, normalized (scheme + host + path) (required)
	HTU string `json:"htu"`

	// IAT is the issued-at timestamp in Unix seconds (required)
	IAT int64 `json:"iat"`
}

// JWK represents a JSON Web Key containing an Ed25519 public key.
// This is embedded in the DPoP header during enrollment to convey the public key.
type JWK struct {
	// Kty must be "OKP" (Octet Key Pair) for Ed25519 keys
	Kty string `json:"kty"`

	// Crv must be "Ed25519" for Ed25519 keys
	Crv string `json:"crv"`

	// X is the base64url-encoded public key bytes (32 bytes for Ed25519)
	X string `json:"x"`
}

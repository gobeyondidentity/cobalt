package dpop

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"
)

// Ed25519Generator generates DPoP proofs using Ed25519 keys.
// It implements the ProofGenerator interface.
type Ed25519Generator struct {
	privateKey ed25519.PrivateKey
}

// NewEd25519Generator creates a new proof generator with the given private key.
func NewEd25519Generator(privateKey ed25519.PrivateKey) *Ed25519Generator {
	return &Ed25519Generator{privateKey: privateKey}
}

// Generate creates a DPoP proof JWT for the given HTTP method and URI.
// The kid parameter is the server-assigned key identifier (empty during enrollment).
// Returns a signed JWT string.
func (g *Ed25519Generator) Generate(method, uri, kid string) (string, error) {
	return GenerateProof(g.privateKey, method, uri, kid)
}

// SignRequest adds a DPoP header to an HTTP request.
// The kid parameter is the server-assigned key identifier (empty during enrollment).
func (g *Ed25519Generator) SignRequest(req *http.Request, kid string) error {
	// Build URI from request URL, not from Host header (prevents injection)
	uri := buildRequestURI(req)

	proof, err := g.Generate(req.Method, uri, kid)
	if err != nil {
		return err
	}

	req.Header.Set("DPoP", proof)
	return nil
}

// dpopClaims represents the DPoP-specific JWT claims.
// This type is used with go-jose's jwt package for proper serialization.
type dpopClaims struct {
	JTI string `json:"jti"`
	HTM string `json:"htm"`
	HTU string `json:"htu"`
	IAT int64  `json:"iat"`
}

// GenerateProof creates a DPoP proof JWT for an HTTP request.
//
// The proof binds the request to the caller's private key, preventing token theft
// and replay attacks. Per RFC 9449, the proof contains:
//   - Header: typ="dpop+jwt", alg="EdDSA", and either kid (post-enrollment) or jwk (enrollment)
//   - Payload: jti (unique ID), htm (HTTP method), htu (normalized URI), iat (timestamp)
//
// Parameters:
//   - privateKey: Ed25519 private key for signing (64 bytes)
//   - method: HTTP method (e.g., "POST", "GET") used exactly as provided
//   - uri: Full URL of the request (will be normalized per RFC 9449)
//   - kid: Server-assigned key identifier; if empty, public key is embedded as jwk
//
// Returns the signed JWT string in format: base64url(header).base64url(payload).base64url(signature)
func GenerateProof(privateKey ed25519.PrivateKey, method, uri string, kid string) (string, error) {
	// Normalize URI per RFC 9449
	normalizedURI, err := NormalizeURI(uri)
	if err != nil {
		return "", fmt.Errorf("failed to normalize URI: %w", err)
	}

	// Build signer options
	signerOpts := (&jose.SignerOptions{}).WithType("dpop+jwt")

	// If kid is provided, use it; otherwise embed JWK
	if kid != "" {
		signerOpts = signerOpts.WithHeader("kid", kid)
	} else {
		// Derive public key from private key for JWK embedding
		publicKey := privateKey.Public().(ed25519.PublicKey)
		jwk := jose.JSONWebKey{
			Key:       publicKey,
			Algorithm: string(jose.EdDSA),
		}
		signerOpts = signerOpts.WithHeader("jwk", jwk)
	}

	// Create signer
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: privateKey}, signerOpts)
	if err != nil {
		return "", fmt.Errorf("failed to create signer: %w", err)
	}

	// Build claims
	claims := dpopClaims{
		JTI: uuid.New().String(),
		HTM: method, // Preserve exact case
		HTU: normalizedURI,
		IAT: time.Now().Unix(),
	}

	// Create signed JWT
	builder := jwt.Signed(signer).Claims(claims)
	proof, err := builder.Serialize()
	if err != nil {
		return "", fmt.Errorf("failed to serialize proof: %w", err)
	}

	return proof, nil
}

// SignRequest adds a DPoP header to an http.Request.
//
// This is a convenience function that generates a proof and attaches it to the request.
// The htu is derived from the request's URL, not the Host header, to prevent
// Host header injection attacks.
//
// Parameters:
//   - req: HTTP request to sign (URL and Method are used)
//   - privateKey: Ed25519 private key for signing
//   - kid: Server-assigned key identifier; if empty, public key is embedded
func SignRequest(req *http.Request, privateKey ed25519.PrivateKey, kid string) error {
	// Use the request URL directly, not the Host header
	uri := req.URL.String()

	proof, err := GenerateProof(privateKey, req.Method, uri, kid)
	if err != nil {
		return fmt.Errorf("failed to generate DPoP proof: %w", err)
	}

	req.Header.Set("DPoP", proof)
	return nil
}

// NormalizeURI normalizes a URI per RFC 9449 Section 4.2:
//   - Lowercase scheme and host
//   - Keep path exactly as-is
//   - Remove query string and fragment
//   - Remove default port (443 for https, 80 for http)
//
// Returns an error if the URI is empty or missing scheme/host.
func NormalizeURI(rawURI string) (string, error) {
	if rawURI == "" {
		return "", ErrInvalidProof("URL cannot be empty")
	}

	parsed, err := url.Parse(rawURI)
	if err != nil {
		return "", err
	}

	if parsed.Scheme == "" || parsed.Host == "" {
		return "", ErrInvalidProof("URL must have scheme and host")
	}

	// Lowercase scheme and host
	scheme := strings.ToLower(parsed.Scheme)
	host := strings.ToLower(parsed.Hostname())

	// Handle port: remove default ports
	port := parsed.Port()
	if port != "" {
		isDefaultPort := (scheme == "https" && port == "443") || (scheme == "http" && port == "80")
		if !isDefaultPort {
			host = host + ":" + port
		}
	}

	// Path only (no query or fragment)
	path := parsed.Path
	if path == "" {
		path = "/"
	}

	return scheme + "://" + host + path, nil
}

// buildRequestURI constructs the URI from an http.Request.
// Uses the request URL, not the Host header, to prevent injection attacks.
func buildRequestURI(req *http.Request) string {
	scheme := "https"
	if req.TLS == nil {
		scheme = "http"
	}

	// Use URL.Host if available (for client requests), otherwise use Host header
	host := req.URL.Host
	if host == "" {
		host = req.Host
	}

	return scheme + "://" + host + req.URL.Path
}

// base64URLEncode encodes data using base64url encoding without padding.
func base64URLEncode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

// base64URLDecode decodes base64url encoded data.
func base64URLDecode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

// ParseProof parses a DPoP proof JWT and returns its components.
// This is useful for testing and debugging.
func ParseProof(proof string) (header, payload map[string]any, signature []byte, err error) {
	parts := strings.Split(proof, ".")
	if len(parts) != 3 {
		return nil, nil, nil, fmt.Errorf("invalid JWT: expected 3 parts, got %d", len(parts))
	}

	// Decode header
	headerBytes, err := base64URLDecode(parts[0])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("decode header: %w", err)
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, nil, nil, fmt.Errorf("unmarshal header: %w", err)
	}

	// Decode payload
	payloadBytes, err := base64URLDecode(parts[1])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("decode payload: %w", err)
	}
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, nil, nil, fmt.Errorf("unmarshal payload: %w", err)
	}

	// Decode signature
	signature, err = base64URLDecode(parts[2])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("decode signature: %w", err)
	}

	return header, payload, signature, nil
}

// VerifyProof verifies a DPoP proof signature using the provided public key.
func VerifyProof(proof string, publicKey ed25519.PublicKey) bool {
	parts := strings.Split(proof, ".")
	if len(parts) != 3 {
		return false
	}

	signingInput := parts[0] + "." + parts[1]
	signature, err := base64URLDecode(parts[2])
	if err != nil {
		return false
	}

	return ed25519.Verify(publicKey, []byte(signingInput), signature)
}

// Ensure Ed25519Generator implements ProofGenerator
var _ ProofGenerator = (*Ed25519Generator)(nil)

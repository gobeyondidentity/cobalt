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
	// Normalize the URI per RFC 9449
	normalizedURI, err := normalizeURI(uri)
	if err != nil {
		return "", fmt.Errorf("normalize uri: %w", err)
	}

	// Build header
	header := map[string]any{
		"typ": "dpop+jwt",
		"alg": "EdDSA",
	}

	if kid != "" {
		// Post-enrollment: use kid
		header["kid"] = kid
	} else {
		// Enrollment: include jwk (public key)
		header["jwk"] = publicKeyToJWK(g.privateKey.Public().(ed25519.PublicKey))
	}

	// Build payload
	payload := map[string]any{
		"jti": uuid.New().String(), // UUIDv4 - random, not sequential
		"htm": method,              // HTTP method exactly as provided
		"htu": normalizedURI,       // Normalized URI
		"iat": time.Now().Unix(),   // Current Unix timestamp
	}

	// Encode header and payload
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("marshal header: %w", err)
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshal payload: %w", err)
	}

	headerB64 := base64URLEncode(headerJSON)
	payloadB64 := base64URLEncode(payloadJSON)

	// Create signing input (header.payload)
	signingInput := headerB64 + "." + payloadB64

	// Sign with Ed25519
	signature := ed25519.Sign(g.privateKey, []byte(signingInput))
	signatureB64 := base64URLEncode(signature)

	// Return complete JWT
	return signingInput + "." + signatureB64, nil
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

// normalizeURI normalizes a URI per RFC 9449 Section 4.1:
// - Lowercase scheme and host
// - Include port only if non-default
// - Path only (no query string or fragment)
func normalizeURI(rawURI string) (string, error) {
	u, err := url.Parse(rawURI)
	if err != nil {
		return "", err
	}

	// Lowercase scheme
	scheme := strings.ToLower(u.Scheme)

	// Lowercase host
	host := strings.ToLower(u.Hostname())

	// Handle port
	port := u.Port()
	if port != "" {
		// Include port only if non-default
		if (scheme == "https" && port != "443") || (scheme == "http" && port != "80") {
			host = host + ":" + port
		}
	}

	// Path only (no query or fragment)
	path := u.Path
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

// publicKeyToJWK converts an Ed25519 public key to a JWK map.
func publicKeyToJWK(pub ed25519.PublicKey) map[string]string {
	return map[string]string{
		"kty": "OKP",
		"crv": "Ed25519",
		"x":   base64URLEncode(pub),
	}
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

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
	// Derive public key from private key for JWK embedding
	publicKey := privateKey.Public().(ed25519.PublicKey)

	// Build header with either kid or jwk
	header := Header{
		Typ: TypeDPoP,
		Alg: AlgEdDSA,
	}
	if kid != "" {
		header.Kid = kid
	} else {
		header.JWK = PublicKeyToJWK(publicKey)
	}

	// Normalize URI per RFC 9449
	normalizedURI, err := normalizeURI(uri)
	if err != nil {
		return "", fmt.Errorf("failed to normalize URI: %w", err)
	}

	// Build claims with unique jti
	claims := Claims{
		JTI: uuid.New().String(),
		HTM: method, // Preserve exact case
		HTU: normalizedURI,
		IAT: time.Now().Unix(),
	}

	// Encode header and payload
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("failed to marshal header: %w", err)
	}
	payloadJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("failed to marshal claims: %w", err)
	}

	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)

	// Create signing input and sign
	signingInput := headerB64 + "." + payloadB64
	signature := ed25519.Sign(privateKey, []byte(signingInput))
	signatureB64 := base64.RawURLEncoding.EncodeToString(signature)

	return signingInput + "." + signatureB64, nil
}

// SignRequest adds a DPoP header to an http.Request.
//
// This is a convenience method that generates a proof and attaches it to the request.
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

// normalizeURI normalizes a URI per RFC 9449 Section 4.2:
//   - Lowercase scheme and host
//   - Keep path exactly as-is
//   - Remove query string and fragment
//   - Remove default port (443 for https, 80 for http)
func normalizeURI(rawURI string) (string, error) {
	parsed, err := url.Parse(rawURI)
	if err != nil {
		return "", err
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

	// Reconstruct URI without query or fragment
	// Path is preserved exactly as-is (case-sensitive)
	result := scheme + "://" + host + parsed.Path

	return result, nil
}

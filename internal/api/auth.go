// Package api implements the HTTP API server for the dashboard.
package api

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// Context keys for authenticated operator info
type contextKey string

const (
	contextKeyOperatorID    contextKey = "operator_id"
	contextKeyOperatorEmail contextKey = "operator_email"
	contextKeyKeyMakerID    contextKey = "keymaker_id"
)

// KMClaims represents the JWT claims for km authentication.
// See system-design.md:1424-1430
type KMClaims struct {
	KeyMakerID string `json:"kid"`
	IssuedAt   int64  `json:"iat"`
	ExpiresAt  int64  `json:"exp"`
	Nonce      string `json:"nonce"`
}

// jwtHeader is the standard JWT header for Ed25519 signing.
type jwtHeader struct {
	Algorithm string `json:"alg"`
	Type      string `json:"typ"`
}

const (
	// jwtValidityWindow is the maximum age of a valid JWT (5 minutes).
	jwtValidityWindow = 5 * time.Minute
	// jwtClockSkew allows for clock drift between client and server.
	jwtClockSkew = 30 * time.Second
)

// AuthMiddleware validates requests using signed JWTs.
// Required header: Authorization: Bearer <jwt>
//
// JWT format: header.claims.signature (base64url encoded)
// Claims must include: kid (keymaker_id), iat, exp, nonce
// Signature: Ed25519 signature of "header.claims" using KeyMaker private key
func (s *Server) AuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Extract Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			log.Printf("AUTH DENIED: %s %s - missing Authorization header from %s",
				r.Method, r.URL.Path, r.RemoteAddr)
			writeError(w, r, http.StatusUnauthorized, "missing Authorization header")
			return
		}

		// Parse Bearer token
		if !strings.HasPrefix(authHeader, "Bearer ") {
			log.Printf("AUTH DENIED: %s %s - invalid Authorization format from %s",
				r.Method, r.URL.Path, r.RemoteAddr)
			writeError(w, r, http.StatusUnauthorized, "invalid Authorization format")
			return
		}
		token := strings.TrimPrefix(authHeader, "Bearer ")

		// Parse and validate JWT
		claims, err := s.validateJWT(token)
		if err != nil {
			log.Printf("AUTH DENIED: %s %s - %v from %s",
				r.Method, r.URL.Path, err, r.RemoteAddr)
			writeError(w, r, http.StatusUnauthorized, err.Error())
			return
		}

		// Look up KeyMaker
		km, err := s.store.GetKeyMaker(claims.KeyMakerID)
		if err != nil {
			log.Printf("AUTH DENIED: %s %s - unknown keymaker %s from %s",
				r.Method, r.URL.Path, claims.KeyMakerID, r.RemoteAddr)
			writeError(w, r, http.StatusUnauthorized, "invalid credentials")
			return
		}

		// Check KeyMaker status
		if km.Status != "active" {
			log.Printf("AUTH DENIED: %s %s - keymaker %s status is %s (operator=%s) from %s",
				r.Method, r.URL.Path, claims.KeyMakerID, km.Status, km.OperatorID, r.RemoteAddr)
			writeError(w, r, http.StatusUnauthorized, "keymaker is not active")
			return
		}

		// Look up operator and check status
		operator, err := s.store.GetOperator(km.OperatorID)
		if err != nil {
			log.Printf("AUTH DENIED: %s %s - operator %s not found for keymaker %s from %s",
				r.Method, r.URL.Path, km.OperatorID, claims.KeyMakerID, r.RemoteAddr)
			writeError(w, r, http.StatusUnauthorized, "invalid credentials")
			return
		}

		if operator.Status == "suspended" {
			log.Printf("AUTH DENIED: %s %s - operator %s is suspended (keymaker=%s) from %s",
				r.Method, r.URL.Path, operator.Email, claims.KeyMakerID, r.RemoteAddr)
			writeError(w, r, http.StatusForbidden, "account suspended")
			return
		}

		if operator.Status != "active" {
			log.Printf("AUTH DENIED: %s %s - operator %s status is %s (keymaker=%s) from %s",
				r.Method, r.URL.Path, operator.Email, operator.Status, claims.KeyMakerID, r.RemoteAddr)
			writeError(w, r, http.StatusForbidden, "account not active")
			return
		}

		// Restore request body for handler (was consumed during JWT validation if needed)
		// JWT is self-contained so body wasn't needed, but ensure it's still available
		if r.Body != nil {
			body, _ := io.ReadAll(r.Body)
			r.Body = io.NopCloser(bytes.NewReader(body))
		}

		// Add authenticated context
		ctx := r.Context()
		ctx = context.WithValue(ctx, contextKeyOperatorID, operator.ID)
		ctx = context.WithValue(ctx, contextKeyOperatorEmail, operator.Email)
		ctx = context.WithValue(ctx, contextKeyKeyMakerID, claims.KeyMakerID)

		log.Printf("AUTH OK: %s %s - operator=%s keymaker=%s from %s",
			r.Method, r.URL.Path, operator.Email, claims.KeyMakerID, r.RemoteAddr)

		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

// validateJWT parses and validates a JWT token.
// Returns the claims if valid, or an error describing the failure.
func (s *Server) validateJWT(token string) (*KMClaims, error) {
	// Split into parts: header.claims.signature
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid token format")
	}

	headerB64, claimsB64, signatureB64 := parts[0], parts[1], parts[2]

	// Decode header
	headerJSON, err := base64.RawURLEncoding.DecodeString(headerB64)
	if err != nil {
		return nil, fmt.Errorf("invalid token header encoding")
	}

	var header jwtHeader
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, fmt.Errorf("invalid token header")
	}

	// Verify algorithm is EdDSA (Ed25519)
	if header.Algorithm != "EdDSA" {
		return nil, fmt.Errorf("unsupported algorithm: %s", header.Algorithm)
	}

	// Decode claims
	claimsJSON, err := base64.RawURLEncoding.DecodeString(claimsB64)
	if err != nil {
		return nil, fmt.Errorf("invalid token claims encoding")
	}

	var claims KMClaims
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		return nil, fmt.Errorf("invalid token claims")
	}

	// Validate required claims
	if claims.KeyMakerID == "" {
		return nil, fmt.Errorf("missing keymaker_id in token")
	}
	if claims.IssuedAt == 0 {
		return nil, fmt.Errorf("missing iat in token")
	}
	if claims.Nonce == "" {
		return nil, fmt.Errorf("missing nonce in token")
	}

	// Validate timestamps
	now := time.Now()
	issuedAt := time.Unix(claims.IssuedAt, 0)

	// Check if token is from the future (with clock skew allowance)
	if issuedAt.After(now.Add(jwtClockSkew)) {
		return nil, fmt.Errorf("token issued in the future")
	}

	// Check expiry if provided
	if claims.ExpiresAt > 0 {
		expiresAt := time.Unix(claims.ExpiresAt, 0)
		if now.After(expiresAt.Add(jwtClockSkew)) {
			return nil, fmt.Errorf("token expired")
		}
	} else {
		// No explicit expiry, use validity window from iat
		if now.After(issuedAt.Add(jwtValidityWindow)) {
			return nil, fmt.Errorf("token expired")
		}
	}

	// Look up KeyMaker to get public key for signature verification
	km, err := s.store.GetKeyMaker(claims.KeyMakerID)
	if err != nil {
		return nil, fmt.Errorf("unknown keymaker")
	}

	// Parse public key
	pubKey, err := parseSSHPublicKey(km.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("invalid keymaker public key")
	}

	// Decode signature
	signature, err := base64.RawURLEncoding.DecodeString(signatureB64)
	if err != nil {
		return nil, fmt.Errorf("invalid signature encoding")
	}

	// Verify signature over header.claims
	signedData := []byte(headerB64 + "." + claimsB64)
	if !ed25519.Verify(pubKey, signedData, signature) {
		return nil, fmt.Errorf("invalid signature")
	}

	return &claims, nil
}

// parseSSHPublicKey extracts an Ed25519 public key from SSH authorized_keys format.
func parseSSHPublicKey(sshPubKey string) (ed25519.PublicKey, error) {
	// Parse SSH public key
	pubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(sshPubKey))
	if err != nil {
		return nil, err
	}

	// Extract the crypto public key
	cryptoPubKey, ok := pubKey.(ssh.CryptoPublicKey)
	if !ok {
		return nil, fmt.Errorf("not a crypto public key")
	}

	// Get the underlying ed25519 key
	ed25519Key, ok := cryptoPubKey.CryptoPublicKey().(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an ed25519 key")
	}

	return ed25519Key, nil
}

// GetAuthOperatorID returns the authenticated operator ID from context.
func GetAuthOperatorID(ctx context.Context) string {
	if v := ctx.Value(contextKeyOperatorID); v != nil {
		return v.(string)
	}
	return ""
}

// GetAuthOperatorEmail returns the authenticated operator email from context.
func GetAuthOperatorEmail(ctx context.Context) string {
	if v := ctx.Value(contextKeyOperatorEmail); v != nil {
		return v.(string)
	}
	return ""
}

// GetAuthKeyMakerID returns the authenticated KeyMaker ID from context.
func GetAuthKeyMakerID(ctx context.Context) string {
	if v := ctx.Value(contextKeyKeyMakerID); v != nil {
		return v.(string)
	}
	return ""
}

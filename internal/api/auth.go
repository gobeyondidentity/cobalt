// Package api implements the HTTP API server for the dashboard.
package api

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"io"
	"log"
	"net/http"
	"strings"

	"golang.org/x/crypto/ssh"
)

// Context keys for authenticated operator info
type contextKey string

const (
	contextKeyOperatorID    contextKey = "operator_id"
	contextKeyOperatorEmail contextKey = "operator_email"
	contextKeyKeyMakerID    contextKey = "keymaker_id"
)

// AuthMiddleware validates requests using Ed25519 signatures.
// Required headers:
//   - X-KM-ID: KeyMaker ID (e.g., "km_abc123")
//   - X-KM-Signature: Base64-encoded Ed25519 signature of request body
func (s *Server) AuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Extract headers
		kmID := r.Header.Get("X-KM-ID")
		signature := r.Header.Get("X-KM-Signature")

		if kmID == "" {
			log.Printf("AUTH DENIED: %s %s - missing X-KM-ID header from %s", r.Method, r.URL.Path, r.RemoteAddr)
			writeError(w, r, http.StatusUnauthorized, "missing X-KM-ID header")
			return
		}

		if signature == "" {
			log.Printf("AUTH DENIED: %s %s - missing X-KM-Signature header from %s (km_id=%s)", r.Method, r.URL.Path, r.RemoteAddr, kmID)
			writeError(w, r, http.StatusUnauthorized, "missing X-KM-Signature header")
			return
		}

		// Look up KeyMaker
		km, err := s.store.GetKeyMaker(kmID)
		if err != nil {
			log.Printf("AUTH DENIED: %s %s - unknown keymaker %s from %s", r.Method, r.URL.Path, kmID, r.RemoteAddr)
			writeError(w, r, http.StatusUnauthorized, "invalid credentials")
			return
		}

		// Check KeyMaker status
		if km.Status != "active" {
			log.Printf("AUTH DENIED: %s %s - keymaker %s status is %s (operator=%s) from %s",
				r.Method, r.URL.Path, kmID, km.Status, km.OperatorID, r.RemoteAddr)
			writeError(w, r, http.StatusUnauthorized, "keymaker is not active")
			return
		}

		// Look up operator and check status
		operator, err := s.store.GetOperator(km.OperatorID)
		if err != nil {
			log.Printf("AUTH DENIED: %s %s - operator %s not found for keymaker %s from %s",
				r.Method, r.URL.Path, km.OperatorID, kmID, r.RemoteAddr)
			writeError(w, r, http.StatusUnauthorized, "invalid credentials")
			return
		}

		if operator.Status == "suspended" {
			log.Printf("AUTH DENIED: %s %s - operator %s is suspended (keymaker=%s) from %s",
				r.Method, r.URL.Path, operator.Email, kmID, r.RemoteAddr)
			writeError(w, r, http.StatusForbidden, "account suspended")
			return
		}

		if operator.Status != "active" {
			log.Printf("AUTH DENIED: %s %s - operator %s status is %s (keymaker=%s) from %s",
				r.Method, r.URL.Path, operator.Email, operator.Status, kmID, r.RemoteAddr)
			writeError(w, r, http.StatusForbidden, "account not active")
			return
		}

		// Read request body for signature verification
		body, err := io.ReadAll(r.Body)
		if err != nil {
			log.Printf("AUTH ERROR: %s %s - failed to read body: %v", r.Method, r.URL.Path, err)
			writeError(w, r, http.StatusBadRequest, "failed to read request body")
			return
		}
		// Restore body for handler
		r.Body = io.NopCloser(bytes.NewReader(body))

		// Decode signature
		sigBytes, err := base64.StdEncoding.DecodeString(signature)
		if err != nil {
			log.Printf("AUTH DENIED: %s %s - invalid signature encoding from %s (km_id=%s)",
				r.Method, r.URL.Path, r.RemoteAddr, kmID)
			writeError(w, r, http.StatusUnauthorized, "invalid signature encoding")
			return
		}

		// Parse public key from stored SSH format
		pubKey, err := parseSSHPublicKey(km.PublicKey)
		if err != nil {
			log.Printf("AUTH ERROR: %s %s - failed to parse public key for km %s: %v",
				r.Method, r.URL.Path, kmID, err)
			writeError(w, r, http.StatusInternalServerError, "invalid keymaker public key")
			return
		}

		// Verify signature
		if !ed25519.Verify(pubKey, body, sigBytes) {
			log.Printf("AUTH DENIED: %s %s - signature verification failed from %s (km_id=%s, operator=%s)",
				r.Method, r.URL.Path, r.RemoteAddr, kmID, operator.Email)
			writeError(w, r, http.StatusUnauthorized, "invalid signature")
			return
		}

		// Add authenticated context
		ctx := r.Context()
		ctx = context.WithValue(ctx, contextKeyOperatorID, operator.ID)
		ctx = context.WithValue(ctx, contextKeyOperatorEmail, operator.Email)
		ctx = context.WithValue(ctx, contextKeyKeyMakerID, kmID)

		log.Printf("AUTH OK: %s %s - operator=%s keymaker=%s from %s",
			r.Method, r.URL.Path, operator.Email, kmID, r.RemoteAddr)

		next.ServeHTTP(w, r.WithContext(ctx))
	}
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
		return nil, err
	}

	// Get the underlying ed25519 key
	ed25519Key, ok := cryptoPubKey.CryptoPublicKey().(ed25519.PublicKey)
	if !ok {
		return nil, err
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

// isSSHED25519Key checks if the SSH public key is an Ed25519 key.
func isSSHED25519Key(sshPubKey string) bool {
	return strings.HasPrefix(sshPubKey, "ssh-ed25519 ")
}

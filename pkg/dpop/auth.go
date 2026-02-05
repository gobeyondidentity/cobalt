package dpop

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"
	"path"
	"runtime/debug"
	"strings"
	"time"
)

// CallerType identifies the type of authenticated caller.
type CallerType string

const (
	CallerTypeKeyMaker CallerType = "keymaker"
	CallerTypeAdmin    CallerType = "admin"
	CallerTypeDPU      CallerType = "dpu"
)

// IdentityStatus represents the status of an identity.
type IdentityStatus string

const (
	IdentityStatusActive         IdentityStatus = "active"
	IdentityStatusSuspended      IdentityStatus = "suspended"
	IdentityStatusRevoked        IdentityStatus = "revoked"
	IdentityStatusDecommissioned IdentityStatus = "decommissioned"
)

// Identity represents an authenticated caller's identity.
type Identity struct {
	KID        string
	CallerType CallerType
	Status     IdentityStatus
	OperatorID string // For keymakers/admins, the parent operator ID
	TenantID   string // For DPUs, the tenant assignment
}

// ProofValidationResult contains the result of DPoP proof validation.
type ProofValidationResult struct {
	Valid bool
	KID   string
	JTI   string // The jti claim from the proof, used for replay detection
	Error string
	Code  string // Error code for response (e.g., "dpop.invalid_proof")
}

// ProofValidator validates DPoP proofs.
// This interface is implemented by the proof validator (si-d2y.1.7).
type ProofValidator interface {
	// Validate validates a DPoP proof against the request.
	// Returns the kid on success, or an error code on failure.
	Validate(proof string, method string, uri string) ProofValidationResult
}

// IdentityLookup looks up identity information by kid.
// This interface is implemented by the database layer (si-d2y.1.4).
type IdentityLookup interface {
	// LookupByKID looks up an identity by its kid.
	// Returns nil if the kid is not found.
	LookupByKID(ctx context.Context, kid string) (*Identity, error)
}

// AuditEmitter emits structured audit events for authentication outcomes.
// Implementations live in pkg/audit; defined here to avoid import cycles
// (pkg/audit -> pkg/authz -> pkg/dpop).
type AuditEmitter interface {
	// EmitAuthSuccess records a successful DPoP authentication.
	EmitAuthSuccess(kid, ip, method, path string, latencyMS int64)
	// EmitAuthFailure records a failed DPoP authentication.
	EmitAuthFailure(kid, ip, reason, method, path string)
}

// nopAuditEmitter discards all events. Used when no emitter is configured.
type nopAuditEmitter struct{}

func (nopAuditEmitter) EmitAuthSuccess(string, string, string, string, int64) {}
func (nopAuditEmitter) EmitAuthFailure(string, string, string, string, string) {}

// contextKey is an unexported type for context keys to prevent collisions.
type contextKey int

const (
	// identityKey is the context key for the authenticated identity.
	identityKey contextKey = iota
)

// IdentityFromContext extracts the authenticated identity from the context.
// Returns nil if no identity is present (e.g., bypassed endpoint).
func IdentityFromContext(ctx context.Context) *Identity {
	id, _ := ctx.Value(identityKey).(*Identity)
	return id
}

// ContextWithIdentity returns a new context with the given identity.
// This is primarily used for testing handlers that expect an authenticated identity.
func ContextWithIdentity(ctx context.Context, identity *Identity) context.Context {
	return context.WithValue(ctx, identityKey, identity)
}

// AuthMiddleware provides DPoP authentication middleware for HTTP handlers.
type AuthMiddleware struct {
	validator      ProofValidator
	identityLookup IdentityLookup
	jtiCache       JTICache
	logger         *slog.Logger
	auditEmitter   AuditEmitter

	// bypassPaths contains paths that don't require DPoP authentication.
	// Paths are normalized (lowercase, no trailing slash).
	bypassPaths map[string]bool

	// bypassPrefixes contains path prefixes that don't require DPoP.
	bypassPrefixes []string

	// debugMode enables detailed error codes in responses.
	// Per security-architecture.md §5: In production mode (default), lifecycle errors
	// return generic "auth.failed" to prevent identity enumeration.
	// In debug mode, returns detailed codes (auth.revoked, auth.suspended, etc.)
	// Detailed codes are ALWAYS logged server-side regardless of this setting.
	debugMode bool
}

// AuthMiddlewareOption configures an AuthMiddleware.
type AuthMiddlewareOption func(*AuthMiddleware)

// WithLogger sets the logger for the middleware.
func WithLogger(logger *slog.Logger) AuthMiddlewareOption {
	return func(m *AuthMiddleware) {
		m.logger = logger
	}
}

// WithDebugMode enables detailed error codes in responses.
// Per security-architecture.md §5: Production mode (default) masks lifecycle
// errors as "auth.failed" to prevent identity enumeration attacks.
// Debug mode returns specific codes like auth.revoked, auth.suspended.
// Detailed codes are ALWAYS logged server-side regardless of this setting.
func WithDebugMode(enabled bool) AuthMiddlewareOption {
	return func(m *AuthMiddleware) {
		m.debugMode = enabled
	}
}

// WithAuditEmitter sets the audit event emitter for recording authentication outcomes.
// When set, the middleware emits auth.success and auth.failure events through the emitter
// in addition to the existing slog output.
func WithAuditEmitter(emitter AuditEmitter) AuthMiddlewareOption {
	return func(m *AuthMiddleware) {
		if emitter != nil {
			m.auditEmitter = emitter
		}
	}
}

// NewAuthMiddleware creates a new DPoP authentication middleware.
func NewAuthMiddleware(
	validator ProofValidator,
	identityLookup IdentityLookup,
	jtiCache JTICache,
	opts ...AuthMiddlewareOption,
) *AuthMiddleware {
	m := &AuthMiddleware{
		validator:      validator,
		identityLookup: identityLookup,
		jtiCache:       jtiCache,
		logger:         slog.Default(),
		auditEmitter:   nopAuditEmitter{},
		bypassPaths: map[string]bool{
			"/health": true,
			"/ready":  true,
		},
		bypassPrefixes: []string{
			"/api/v1/enroll/",
			"/api/v1/admin/bootstrap",
		},
	}

	for _, opt := range opts {
		opt(m)
	}

	return m
}

// Wrap wraps an HTTP handler with DPoP authentication.
// The handler will only be called if authentication succeeds or the path is bypassed.
func (m *AuthMiddleware) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Recover from panics to prevent unauthenticated access
		defer func() {
			if err := recover(); err != nil {
				m.logger.Error("panic in auth middleware",
					"error", err,
					"method", r.Method,
					"path", r.URL.Path,
					"stack", string(debug.Stack()),
				)
				m.writeError(w, http.StatusInternalServerError, "internal_error", "internal server error")
				// Do NOT call next - request must not proceed
			}
		}()

		// Normalize path for bypass check
		normalizedPath := m.normalizePath(r.URL.Path)

		// Check if path is bypassed
		if m.shouldBypass(normalizedPath) {
			m.logger.Debug("bypassing authentication",
				"method", r.Method,
				"path", r.URL.Path,
			)
			next.ServeHTTP(w, r)
			return
		}

		// Extract DPoP header
		proof := r.Header.Get("DPoP")
		if proof == "" {
			m.logAuthFailure(r, "", "dpop.missing_proof", "")
			m.writeError(w, http.StatusUnauthorized, "dpop.missing_proof", "DPoP proof required")
			return
		}

		// Build request URI for validation (scheme + host + path)
		requestURI := m.buildRequestURI(r)

		// Validate proof
		result := m.validator.Validate(proof, r.Method, requestURI)
		if !result.Valid {
			m.logAuthFailure(r, result.KID, result.Code, result.Error)
			m.writeError(w, http.StatusUnauthorized, result.Code, result.Error)
			return
		}

		// Check JTI replay using the jti claim extracted by the validator
		isReplay, err := m.jtiCache.Record(result.JTI)
		if err != nil {
			if err == ErrCacheFull {
				m.logger.Error("jti cache full", "error", err)
				m.writeError(w, http.StatusServiceUnavailable, "dpop.service_unavailable", "service temporarily unavailable")
				return
			}
			// Other errors (invalid input) - treat as replay for safety
			m.logAuthFailure(r, result.KID, "dpop.replay", "jti validation error")
			m.writeError(w, http.StatusUnauthorized, "dpop.replay", "token replay detected")
			return
		}
		if isReplay {
			m.logAuthFailure(r, result.KID, "dpop.replay", "duplicate jti")
			m.writeError(w, http.StatusUnauthorized, "dpop.replay", "token replay detected")
			return
		}

		// Look up identity
		identity, err := m.identityLookup.LookupByKID(r.Context(), result.KID)
		if err != nil {
			m.logger.Error("identity lookup error",
				"kid", sanitizeForLog(result.KID),
				"error", err,
			)
			m.writeError(w, http.StatusInternalServerError, "internal_error", "internal server error")
			return
		}
		if identity == nil {
			// Log detailed code server-side, mask in production mode
			m.logAuthFailure(r, result.KID, "dpop.unknown_key", "kid not found")
			if m.debugMode {
				m.writeError(w, http.StatusUnauthorized, "dpop.unknown_key", "unknown key")
			} else {
				// Production: mask as generic auth.failed to prevent key enumeration
				m.writeError(w, http.StatusUnauthorized, "auth.failed", "authentication failed")
			}
			return
		}

		// Check identity status (step 10 per security-architecture.md §2.5)
		// Detailed codes are ALWAYS logged server-side for forensics.
		// Response codes depend on debug mode to prevent identity enumeration.
		switch identity.Status {
		case IdentityStatusRevoked:
			m.logAuthFailure(r, result.KID, "auth.revoked", "identity revoked")
			if m.debugMode {
				m.writeError(w, http.StatusUnauthorized, "auth.revoked", "access revoked")
			} else {
				// Production: mask as generic auth.failed (prevents enumeration)
				m.writeError(w, http.StatusUnauthorized, "auth.failed", "authentication failed")
			}
			return
		case IdentityStatusSuspended:
			m.logAuthFailure(r, result.KID, "auth.suspended", "identity suspended")
			if m.debugMode {
				// Debug: 403 reveals suspension status
				m.writeError(w, http.StatusForbidden, "auth.suspended", "access suspended")
			} else {
				// Production: mask as generic 401 auth.failed (prevents enumeration)
				// Note: returning 401 instead of 403 to avoid leaking suspended vs revoked
				m.writeError(w, http.StatusUnauthorized, "auth.failed", "authentication failed")
			}
			return
		case IdentityStatusDecommissioned:
			m.logAuthFailure(r, result.KID, "auth.decommissioned", "dpu decommissioned")
			if m.debugMode {
				m.writeError(w, http.StatusUnauthorized, "auth.decommissioned", "device decommissioned")
			} else {
				// Production: mask as generic auth.failed
				m.writeError(w, http.StatusUnauthorized, "auth.failed", "authentication failed")
			}
			return
		}

		// Authentication successful - log and proceed
		latencyMS := time.Since(start).Milliseconds()
		m.logAuthSuccess(r, result.KID, latencyMS)

		// Add identity to context
		ctx := context.WithValue(r.Context(), identityKey, identity)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// normalizePath normalizes a URL path for bypass checking.
// It handles path traversal, case, and URL encoding.
func (m *AuthMiddleware) normalizePath(p string) string {
	// Decode URL encoding
	decoded, err := url.PathUnescape(p)
	if err != nil {
		// If decoding fails, use original path
		decoded = p
	}

	// Clean the path (resolves .., removes double slashes)
	cleaned := path.Clean(decoded)

	// Lowercase for case-insensitive matching
	lower := strings.ToLower(cleaned)

	// Remove trailing slash except for root
	if len(lower) > 1 && strings.HasSuffix(lower, "/") {
		lower = lower[:len(lower)-1]
	}

	return lower
}

// shouldBypass returns true if the path should bypass authentication.
func (m *AuthMiddleware) shouldBypass(normalizedPath string) bool {
	// Check exact matches
	if m.bypassPaths[normalizedPath] {
		return true
	}

	// Check prefixes
	for _, prefix := range m.bypassPrefixes {
		if strings.HasPrefix(normalizedPath, prefix) {
			return true
		}
	}

	return false
}

// buildRequestURI builds the URI string for DPoP validation.
// Per RFC 9449, this is scheme + host + path (no query string).
func (m *AuthMiddleware) buildRequestURI(r *http.Request) string {
	scheme := "https"
	if r.TLS == nil {
		scheme = "http"
	}

	// Use X-Forwarded-Host if present (behind proxy)
	host := r.Header.Get("X-Forwarded-Host")
	if host == "" {
		host = r.Host
	}

	return scheme + "://" + host + r.URL.Path
}

// writeError writes a JSON error response.
// The message parameter is intentionally not included in the response
// to prevent information disclosure (per security-architecture.md Section 5).
func (m *AuthMiddleware) writeError(w http.ResponseWriter, status int, code, _ string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{
		"error": code,
	})
}

// logAuthSuccess logs a successful authentication event and emits an audit event.
func (m *AuthMiddleware) logAuthSuccess(r *http.Request, kid string, latencyMS int64) {
	ip := getClientIP(r)
	m.logger.Info("auth.success",
		"kid", sanitizeForLog(kid),
		"method", r.Method,
		"path", r.URL.Path,
		"ip", ip,
		"latency_ms", latencyMS,
	)
	m.auditEmitter.EmitAuthSuccess(kid, ip, r.Method, r.URL.Path, latencyMS)
}

// logAuthFailure logs an authentication failure event and emits an audit event.
// The detail parameter provides additional context for server logs.
func (m *AuthMiddleware) logAuthFailure(r *http.Request, kid, reason, detail string) {
	ip := getClientIP(r)
	args := []any{
		"reason", reason,
		"kid", sanitizeForLog(kid),
		"method", r.Method,
		"path", r.URL.Path,
		"ip", ip,
	}
	if detail != "" {
		args = append(args, "detail", detail)
	}
	m.logger.Warn("auth.failure", args...)
	m.auditEmitter.EmitAuthFailure(kid, ip, reason, r.Method, r.URL.Path)
}

// sanitizeForLog sanitizes a string for logging to prevent log injection.
func sanitizeForLog(s string) string {
	// Remove newlines and other control characters
	result := strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return -1 // Remove character
		}
		return r
	}, s)

	// Truncate long values
	if len(result) > 256 {
		result = result[:256] + "..."
	}

	return result
}

// getClientIP extracts the client IP from the request.
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header (may be set by proxy)
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		// Take the first IP in the chain
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}

	// Check X-Real-IP header
	xri := r.Header.Get("X-Real-IP")
	if xri != "" {
		return xri
	}

	// Fall back to RemoteAddr
	// Strip port if present
	addr := r.RemoteAddr
	if idx := strings.LastIndex(addr, ":"); idx != -1 {
		// Check if this is IPv6 [::1]:port format
		if strings.Contains(addr, "[") {
			if closeIdx := strings.LastIndex(addr, "]"); closeIdx != -1 && closeIdx < idx {
				return addr[:idx]
			}
		} else {
			return addr[:idx]
		}
	}
	return addr
}


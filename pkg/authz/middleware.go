package authz

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

	"github.com/gobeyondidentity/secure-infra/pkg/dpop"
)

// PrincipalLookup resolves a DPoP identity to an authorization principal.
// Implementations query storage to get tenant memberships and roles.
type PrincipalLookup interface {
	// LookupPrincipal resolves an authenticated identity to a principal with role and tenants.
	// Returns an error if the lookup fails (e.g., database error).
	// Returns (nil, nil) if the identity is not found (should not happen for valid identities).
	LookupPrincipal(ctx context.Context, identity *dpop.Identity) (*Principal, error)
}

// ResourceExtractor extracts resource information from HTTP requests.
// Implementations parse path parameters and request bodies.
type ResourceExtractor interface {
	// ExtractResource determines the target resource for authorization.
	// Uses path parameters (e.g., {id}), request body, and action context.
	// For self-referential endpoints, uses the principal's identity.
	ExtractResource(r *http.Request, action Action, principal *Principal) (*Resource, error)
}

// AttestationLookup retrieves attestation status for DPUs.
// Used for attestation-gated actions (credential:push, credential:pull).
type AttestationLookup interface {
	// GetAttestationStatus returns the current attestation status for a DPU.
	// Returns AttestationUnavailable if no attestation data exists.
	GetAttestationStatus(ctx context.Context, dpuID string) (AttestationStatus, error)
}

// AuthzMiddleware enforces Cedar policy authorization on HTTP requests.
// It sits between DPoP authentication and handlers in the middleware stack.
type AuthzMiddleware struct {
	authorizer   *Authorizer
	registry     *ActionRegistry
	principal    PrincipalLookup
	resource     ResourceExtractor
	attestation  AttestationLookup
	logger       *slog.Logger
}

// MiddlewareOption configures the AuthzMiddleware.
type MiddlewareOption func(*AuthzMiddleware)

// WithLogger sets a custom logger for the middleware.
func WithLogger(l *slog.Logger) MiddlewareOption {
	return func(m *AuthzMiddleware) {
		m.logger = l
	}
}

// WithAttestationLookup sets the attestation lookup for attestation-gated actions.
func WithAttestationLookup(a AttestationLookup) MiddlewareOption {
	return func(m *AuthzMiddleware) {
		m.attestation = a
	}
}

// NewAuthzMiddleware creates authorization middleware.
// The middleware uses the provided components to:
// - Look up Cedar actions from routes via the registry
// - Resolve DPoP identities to principals via principalLookup
// - Extract resources from requests via resourceExtractor
// - Make authorization decisions via the authorizer
func NewAuthzMiddleware(
	authorizer *Authorizer,
	registry *ActionRegistry,
	principalLookup PrincipalLookup,
	resourceExtractor ResourceExtractor,
	opts ...MiddlewareOption,
) *AuthzMiddleware {
	m := &AuthzMiddleware{
		authorizer: authorizer,
		registry:   registry,
		principal:  principalLookup,
		resource:   resourceExtractor,
		logger:     slog.Default(),
	}
	for _, opt := range opts {
		opt(m)
	}
	return m
}

// Wrap wraps an HTTP handler with authorization enforcement.
// The middleware flow:
// 1. Check if endpoint is pre-auth (health, bootstrap, enroll) - bypass if so
// 2. Extract identity from DPoP context
// 3. Look up Cedar action from route
// 4. Resolve principal from identity
// 5. Extract resource from request
// 6. Call Authorizer.Authorize()
// 7. Handle decision (allow, deny, or attestation error)
func (m *AuthzMiddleware) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		method := r.Method
		path := r.URL.Path

		// Ensure request ID exists for correlation
		requestID := r.Header.Get("X-Request-ID")
		if requestID == "" {
			ctx, requestID = EnsureRequestID(ctx)
		} else {
			ctx = ContextWithRequestID(ctx, requestID)
		}
		r = r.WithContext(ctx)
		_ = requestID // Used for logging

		// Step 1: Check pre-auth bypass
		if m.registry.IsPreAuthEndpoint(method, path) {
			m.logger.Debug("pre-auth endpoint bypassed",
				"method", method,
				"path", path,
			)
			next.ServeHTTP(w, r)
			return
		}

		// Step 2: Extract identity from DPoP context
		identity := dpop.IdentityFromContext(ctx)
		if identity == nil {
			// This should not happen after DPoP auth middleware
			// But fail-secure if it does
			m.logger.Error("no identity in context for authenticated endpoint",
				"method", method,
				"path", path,
			)
			m.writeError(w, http.StatusUnauthorized, "auth.missing_identity", "authentication required")
			return
		}

		// Step 3: Look up action from route
		action, err := m.registry.Lookup(method, path)
		if err != nil {
			// Unknown route - fail-secure with 404
			authzErr := ErrUnknownRoute(method, path)
			m.logger.Warn("unknown route rejected",
				"method", method,
				"path", path,
				"kid", identity.KID,
			)
			m.writeError(w, authzErr.HTTPStatus(), authzErr.Code, authzErr.Message)
			return
		}

		// Step 4: Resolve principal from identity
		principal, err := m.principal.LookupPrincipal(ctx, identity)
		if err != nil {
			m.logger.Error("principal lookup failed",
				"error", err,
				"kid", identity.KID,
			)
			m.writeError(w, http.StatusInternalServerError, ErrCodePolicyError, "internal error")
			return
		}
		if principal == nil {
			// Identity exists in DPoP but not found in principal lookup
			// This indicates a data inconsistency
			m.logger.Error("principal not found for valid identity",
				"kid", identity.KID,
			)
			m.writeError(w, http.StatusInternalServerError, ErrCodePolicyError, "internal error")
			return
		}

		// Step 5: Extract resource from request
		resource, err := m.resource.ExtractResource(r, action, principal)
		if err != nil {
			m.logger.Error("resource extraction failed",
				"error", err,
				"method", method,
				"path", path,
				"kid", identity.KID,
			)
			m.writeError(w, http.StatusBadRequest, ErrCodePolicyError, "invalid resource")
			return
		}

		// Step 6: Build authorization request with context
		authzReq := AuthzRequest{
			Principal: *principal,
			Action:    string(action),
			Resource:  *resource,
			Context:   make(map[string]any),
		}

		// Add attestation status for attestation-gated actions
		if RequiresAttestationGate(string(action)) && m.attestation != nil {
			// For credential operations, we need the target DPU's attestation status
			dpuID := m.extractDPUID(r, resource, principal)
			if dpuID != "" {
				status, err := m.attestation.GetAttestationStatus(ctx, dpuID)
				if err != nil {
					m.logger.Error("attestation lookup failed",
						"error", err,
						"dpu_id", dpuID,
					)
					// Default to unavailable on lookup failure (fail-secure)
					status = AttestationUnavailable
				}
				authzReq.Context["attestation_status"] = string(status)
			}
		}

		// Check for force bypass header (super:admin only)
		// Header format: X-Force-Bypass: <reason>
		// The header VALUE is the bypass reason (not a separate header)
		forceBypassReason := r.Header.Get("X-Force-Bypass")
		if forceBypassReason != "" {
			authzReq.Context["force_bypass_requested"] = true
			authzReq.Context["force_bypass_reason"] = forceBypassReason
		}

		// Step 7: Make authorization decision
		decision := m.authorizer.Authorize(ctx, authzReq)

		// Handle decision
		if decision.Allowed {
			// Pass decision to handler context for audit logging
			ctx = ContextWithDecision(ctx, &decision)
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		// Not allowed - check if force bypass is applicable
		if decision.RequiresForceBypass {
			if m.handleForceBypass(r, &decision, principal, string(action)) {
				// Force bypass granted - log security warning and proceed
				ctx = ContextWithDecision(ctx, &decision)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}
		}

		// Authorization denied - determine appropriate error response
		m.writeDeniedResponse(w, &decision, principal, resource, string(action))
	})
}

// handleForceBypass checks if a force bypass should be allowed.
// Returns true if bypass is granted (super:admin with X-Force-Bypass header containing reason).
// Force bypass is only available for stale/unavailable attestation, never for failed.
// Header format: X-Force-Bypass: <reason> (the value IS the reason, not a boolean)
func (m *AuthzMiddleware) handleForceBypass(
	r *http.Request,
	decision *AuthzDecision,
	principal *Principal,
	action string,
) bool {
	// Only super:admin can use force bypass
	if principal.Role != RoleSuperAdmin {
		return false
	}

	// Check for X-Force-Bypass header - the VALUE is the bypass reason
	bypassReason := r.Header.Get("X-Force-Bypass")
	if bypassReason == "" {
		// No header present - bypass not requested
		return false
	}

	// Reject empty reason (must provide actual justification)
	bypassReason = strings.TrimSpace(bypassReason)
	if bypassReason == "" {
		// Empty reason after trimming - reject
		return false
	}

	// Log security warning for force bypass
	m.logger.Warn("SECURITY: force bypass used",
		"principal", principal.UID,
		"role", principal.Role,
		"action", action,
		"reason", decision.Reason,
		"bypass_justification", bypassReason,
		"policy_id", decision.PolicyID,
	)

	return true
}

// writeDeniedResponse writes the appropriate error response for a denied authorization.
func (m *AuthzMiddleware) writeDeniedResponse(
	w http.ResponseWriter,
	decision *AuthzDecision,
	principal *Principal,
	resource *Resource,
	action string,
) {
	// Determine error based on structured reason type (not string matching)
	var authzErr *AuthzError

	switch decision.StructuredReason.Type {
	case ReasonAttestationFailed:
		authzErr = ErrAttestationFailed(resource.UID)

	case ReasonAttestationStale:
		// For super:admin with stale attestation, indicate bypass is available
		if decision.RequiresForceBypass && principal.Role == RoleSuperAdmin {
			m.writeBypassAvailableResponse(w, resource.UID, "stale")
			return
		}
		authzErr = ErrAttestationStale(resource.UID)

	case ReasonAttestationUnavailable:
		// For super:admin with unavailable attestation, indicate bypass is available
		if decision.RequiresForceBypass && principal.Role == RoleSuperAdmin {
			m.writeBypassAvailableResponse(w, resource.UID, "unavailable")
			return
		}
		authzErr = ErrAttestationUnavailable(resource.UID)

	default:
		authzErr = ErrForbidden(decision.Reason)
	}

	m.logger.Info("authorization denied",
		"principal", principal.UID,
		"role", principal.Role,
		"action", action,
		"resource", resource.UID,
		"resource_type", resource.Type,
		"reason", decision.Reason,
		"policy_id", decision.PolicyID,
		"error_code", authzErr.Code,
	)

	m.writeError(w, authzErr.HTTPStatus(), authzErr.Code, authzErr.Message)
}

// writeBypassAvailableResponse writes a 412 response indicating force bypass is available.
func (m *AuthzMiddleware) writeBypassAvailableResponse(
	w http.ResponseWriter,
	resourceUID string,
	attestationStatus string,
) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusPreconditionFailed)
	json.NewEncoder(w).Encode(map[string]any{
		"error":              "authz.attestation_" + attestationStatus,
		"message":            "attestation " + attestationStatus + " - force bypass available",
		"attestation_status": attestationStatus,
		"bypass_available":   true,
		"bypass_header":      "X-Force-Bypass",
		"bypass_usage":       "Set X-Force-Bypass header to your justification reason (e.g., 'maintenance window')",
	})
}

// extractDPUID extracts the DPU ID for attestation lookup.
// For credential:push, the DPU is in the request body or resource.
// For credential:pull, the DPU is the principal (DPU pulling its own credentials).
func (m *AuthzMiddleware) extractDPUID(r *http.Request, resource *Resource, principal *Principal) string {
	// If the resource is a DPU, use its UID
	if resource.Type == "DPU" && resource.UID != "" {
		return resource.UID
	}

	// If the principal is a DPU, use its UID (for credential:pull)
	if principal.Type == PrincipalDPU {
		return principal.UID
	}

	// Try to get DPU ID from path
	dpuID := r.PathValue("id")
	if dpuID != "" && strings.HasPrefix(dpuID, "dpu_") {
		return dpuID
	}

	return ""
}

// writeError writes a JSON error response.
func (m *AuthzMiddleware) writeError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{
		"error":   code,
		"message": message,
	})
}

package authz

import (
	"context"

	"github.com/google/uuid"
)

// contextKey is a private type for context keys to prevent collisions.
type contextKey int

const (
	// decisionKey stores the AuthzDecision in request context.
	decisionKey contextKey = iota
	// requestIDKey stores the request ID for correlation.
	requestIDKey
)

// DecisionFromContext retrieves the authorization decision from the request context.
// Returns nil if no decision is stored (e.g., pre-auth endpoints).
// Handlers use this to access the decision for audit logging.
func DecisionFromContext(ctx context.Context) *AuthzDecision {
	d, _ := ctx.Value(decisionKey).(*AuthzDecision)
	return d
}

// ContextWithDecision returns a new context with the authorization decision attached.
// Called by the authz middleware after a successful authorization check.
func ContextWithDecision(ctx context.Context, d *AuthzDecision) context.Context {
	return context.WithValue(ctx, decisionKey, d)
}

// RequestIDFromContext retrieves the request ID from context.
// Returns empty string if no request ID is stored.
func RequestIDFromContext(ctx context.Context) string {
	id, _ := ctx.Value(requestIDKey).(string)
	return id
}

// ContextWithRequestID returns a new context with the request ID attached.
func ContextWithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey, id)
}

// EnsureRequestID returns a context with a request ID, generating one if needed.
// Returns the (possibly new) context and the request ID.
func EnsureRequestID(ctx context.Context) (context.Context, string) {
	if id := RequestIDFromContext(ctx); id != "" {
		return ctx, id
	}
	id := uuid.New().String()
	return ContextWithRequestID(ctx, id), id
}

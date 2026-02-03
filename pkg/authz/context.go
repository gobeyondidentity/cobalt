package authz

import "context"

// contextKey is a private type for context keys to prevent collisions.
type contextKey int

const (
	// decisionKey stores the AuthzDecision in request context.
	decisionKey contextKey = iota
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

// Package authz provides Cedar-based authorization for Project Cobalt.
//
// This package is the single source of truth for all authorization decisions.
// No authorization decision should be made outside the Authorizer.Authorize method.
//
// # Role Model
//
// Three-tier role model per ADR-011:
//   - operator: Can only access resources with explicit authorization
//   - tenant:admin: Can access all resources within their tenant
//   - super:admin: Can access all resources globally
//
// # Attestation Gate
//
// Credential operations (push/pull) are gated on device attestation status:
//   - verified: Access permitted (for authorized principals)
//   - stale: Operators denied; super:admin can bypass with force flag
//   - unavailable: Operators denied; super:admin can bypass with force flag
//   - failed: ALL principals denied; no bypass possible
//
// # Usage
//
//	cfg := authz.DefaultConfig()
//	cfg.Logger = myLogger
//	authorizer, err := authz.NewAuthorizer(cfg)
//
//	decision := authorizer.Authorize(ctx, authz.AuthzRequest{
//		Principal: authz.Principal{
//			UID:       "km_alice",
//			Type:      authz.PrincipalOperator,
//			Role:      authz.RoleOperator,
//			TenantIDs: []string{"tnt_acme"},
//		},
//		Action: authz.ActionCredentialPush,
//		Resource: authz.Resource{
//			UID:      "dpu_xyz",
//			Type:     "DPU",
//			TenantID: "tnt_acme",
//		},
//		Context: map[string]any{
//			"attestation_status":  "verified", // string, not typed constant
//			"operator_authorized": true,
//		},
//	})
//
//	if !decision.Allowed {
//		if decision.RequiresForceBypass {
//			// Prompt user for X-Force-Bypass header
//		}
//		return authz.ErrForbidden(decision.Reason)
//	}
//
// # Thread Safety
//
// Authorizer is safe for concurrent use. The underlying Cedar PolicySet
// is immutable after construction.
//
// # Decision Logging
//
// Every authorization decision is logged with structured fields including:
// principal, action, resource, decision, duration, and policy ID.
// Configure logging via Config.Logger.
package authz

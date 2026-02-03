package authz

import (
	"context"
	_ "embed"
	"fmt"
	"log/slog"
	"time"

	"github.com/cedar-policy/cedar-go"
)

//go:embed policies.cedar
var policiesContent []byte

// Config contains options for the Authorizer.
type Config struct {
	// Logger for structured decision logging. If nil, uses slog.Default().
	Logger *slog.Logger

	// PolicyBytes allows loading policies from a custom source (for testing).
	// If nil, embedded policies.cedar is used.
	PolicyBytes []byte
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		Logger:      nil, // Will use slog.Default() in NewAuthorizer
		PolicyBytes: nil, // Use embedded policies
	}
}

// Authorizer wraps the Cedar policy engine.
// All authorization decisions in the system flow through this single component.
type Authorizer struct {
	policies *cedar.PolicySet
	logger   *slog.Logger
}

// NewAuthorizer creates an authorizer with the given configuration.
func NewAuthorizer(cfg Config) (*Authorizer, error) {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	policyData := cfg.PolicyBytes
	if policyData == nil {
		policyData = policiesContent
	}

	ps, err := cedar.NewPolicySetFromBytes("policies.cedar", policyData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse policies: %w", err)
	}

	return &Authorizer{
		policies: ps,
		logger:   logger,
	}, nil
}

// Authorize evaluates an authorization request against Cedar policies.
// The context parameter is available for future use (cancellation, tracing).
//
// This is the single entry point for all authorization decisions.
// No authorization decision should be made outside this method.
func (a *Authorizer) Authorize(ctx context.Context, req AuthzRequest) AuthzDecision {
	start := time.Now()

	// Build Cedar entities from the request
	entities := buildEntities(req.Principal, req.Resource)

	// Build Cedar request
	cedarReq := buildCedarRequest(req)

	// Evaluate against policies
	decision, diagnostic := cedar.Authorize(a.policies, entities, cedarReq)

	// Extract policy ID from reasons (first matching policy)
	policyID := ""
	if len(diagnostic.Reasons) > 0 {
		policyID = string(diagnostic.Reasons[0].PolicyID)
	}

	// Build result
	allowed := decision == cedar.Allow
	duration := time.Since(start)

	// Attestation gate override: even if Cedar allows, attestation-gated actions
	// must have verified attestation. This enforces the attestation gate independently
	// of Cedar policy evaluation.
	if allowed && RequiresAttestationGate(req.Action) {
		attestationStatus := getAttestationStatus(req.Context)
		// Override allow if attestation is not verified
		if attestationStatus != AttestationVerified && attestationStatus != "" {
			allowed = false
		}
	}

	// Determine reason and RequiresForceBypass
	reason, requiresForceBypass := a.buildReasonAndBypass(req, allowed, diagnostic)

	result := AuthzDecision{
		Allowed:             allowed,
		Reason:              reason,
		PolicyID:            policyID,
		RequiresForceBypass: requiresForceBypass,
		Duration:            duration,
	}

	// Log the decision (structured for JSON output)
	a.logDecision(req, result, diagnostic)

	return result
}

// buildReasonAndBypass determines the human-readable reason and bypass eligibility.
// RequiresForceBypass is true only when:
// - Denied due to stale or unavailable attestation (not failed)
// - Principal is super:admin (only they can bypass)
func (a *Authorizer) buildReasonAndBypass(req AuthzRequest, allowed bool, diag cedar.Diagnostic) (string, bool) {
	if allowed {
		return "access permitted", false
	}

	// Check if denial was due to attestation status
	attestationStatus := getAttestationStatus(req.Context)

	switch attestationStatus {
	case AttestationFailed:
		// Hard deny, no bypass possible for anyone
		return "attestation failed - access permanently blocked", false

	case AttestationStale:
		// Super:admin can bypass stale attestation
		if req.Principal.Role == RoleSuperAdmin {
			return "attestation stale - force bypass available", true
		}
		return "attestation stale - access denied", false

	case AttestationUnavailable:
		// Super:admin can bypass unavailable attestation
		if req.Principal.Role == RoleSuperAdmin {
			return "attestation unavailable - force bypass available", true
		}
		return "attestation unavailable - access denied", false
	}

	// Generic policy denial
	if len(diag.Reasons) > 0 {
		return fmt.Sprintf("denied by policy %s", diag.Reasons[0].PolicyID), false
	}

	// Default deny (no permit matched)
	return "access denied - no matching permit policy", false
}

// getAttestationStatus extracts attestation status from context.
func getAttestationStatus(ctx map[string]any) AttestationStatus {
	if status, ok := ctx["attestation_status"].(AttestationStatus); ok {
		return status
	}
	if statusStr, ok := ctx["attestation_status"].(string); ok {
		return AttestationStatus(statusStr)
	}
	return AttestationVerified // Default if not set
}

// logDecision logs the authorization decision with structured fields.
func (a *Authorizer) logDecision(req AuthzRequest, result AuthzDecision, diag cedar.Diagnostic) {
	// Core decision log
	a.logger.Info("authorization decision",
		"principal", req.Principal.UID,
		"principal_type", req.Principal.Type,
		"role", req.Principal.Role,
		"action", req.Action,
		"resource", req.Resource.UID,
		"resource_type", req.Resource.Type,
		"resource_tenant", req.Resource.TenantID,
		"decision", result.Allowed,
		"reason", result.Reason,
		"policy_id", result.PolicyID,
		"requires_force_bypass", result.RequiresForceBypass,
		"duration_us", result.Duration.Microseconds(),
	)

	// Log policy errors separately
	for _, err := range diag.Errors {
		a.logger.Error("policy evaluation error",
			"policy", err.PolicyID,
			"error", err.Message,
		)
	}

	// Security warning for bypass scenarios
	if result.RequiresForceBypass {
		a.logger.Warn("SECURITY: force bypass available",
			"principal", req.Principal.UID,
			"action", req.Action,
			"resource", req.Resource.UID,
			"attestation_status", req.Context["attestation_status"],
		)
	}
}

// PolicyCount returns the number of loaded policies.
func (a *Authorizer) PolicyCount() int {
	count := 0
	for range a.policies.All() {
		count++
	}
	return count
}

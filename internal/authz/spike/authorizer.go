// Package spike is a proof-of-concept for cedar-go integration.
// This code is NOT production-ready - it's for evaluation only.
package spike

import (
	_ "embed"
	"fmt"
	"log/slog"
	"time"

	"github.com/cedar-policy/cedar-go"
)

//go:embed policies.cedar
var policiesContent []byte

// AttestationStatus represents the attestation state of a DPU.
type AttestationStatus string

const (
	AttestationVerified    AttestationStatus = "verified"
	AttestationStale       AttestationStatus = "stale"
	AttestationUnavailable AttestationStatus = "unavailable"
	AttestationFailed      AttestationStatus = "failed"
)

// Role represents a principal's role in the system.
type Role string

const (
	RoleOperator    Role = "Operator"
	RoleTenantAdmin Role = "TenantAdmin"
	RoleSuperAdmin  Role = "SuperAdmin"
)

// AuthzRequest represents an authorization request for credential push.
type AuthzRequest struct {
	PrincipalID        string            // e.g., "op_abc12345"
	PrincipalRole      Role              // Operator, TenantAdmin, SuperAdmin
	Action             string            // e.g., "push_credential"
	ResourceID         string            // DPU ID e.g., "dpu_xyz"
	AttestationStatus  AttestationStatus // Device attestation state
	OperatorAuthorized bool              // Whether operator has authorization for CA+device
}

// AuthzDecision represents the result of an authorization check.
type AuthzDecision struct {
	Allowed  bool
	Reasons  []string // Policy IDs that contributed to the decision
	Duration time.Duration
}

// Authorizer wraps the Cedar policy engine.
type Authorizer struct {
	policies *cedar.PolicySet
	entities cedar.EntityMap
	logger   *slog.Logger
}

// NewAuthorizer creates an authorizer with embedded policies.
func NewAuthorizer(logger *slog.Logger) (*Authorizer, error) {
	ps, err := cedar.NewPolicySetFromBytes("policies.cedar", policiesContent)
	if err != nil {
		return nil, fmt.Errorf("failed to parse policies: %w", err)
	}

	if logger == nil {
		logger = slog.Default()
	}

	return &Authorizer{
		policies: ps,
		entities: cedar.EntityMap{},
		logger:   logger,
	}, nil
}

// NewAuthorizerFromBytes creates an authorizer from policy bytes (for testing).
func NewAuthorizerFromBytes(policyContent []byte, logger *slog.Logger) (*Authorizer, error) {
	ps, err := cedar.NewPolicySetFromBytes("policies.cedar", policyContent)
	if err != nil {
		return nil, fmt.Errorf("failed to parse policies: %w", err)
	}

	if logger == nil {
		logger = slog.Default()
	}

	return &Authorizer{
		policies: ps,
		entities: cedar.EntityMap{},
		logger:   logger,
	}, nil
}

// Authorize evaluates an authorization request against Cedar policies.
func (a *Authorizer) Authorize(req AuthzRequest) AuthzDecision {
	start := time.Now()

	// Build Cedar request
	cedarReq := cedar.Request{
		Principal: cedar.NewEntityUID(cedar.EntityType(req.PrincipalRole), cedar.String(req.PrincipalID)),
		Action:    cedar.NewEntityUID("Action", cedar.String(req.Action)),
		Resource:  cedar.NewEntityUID("DPU", cedar.String(req.ResourceID)),
		Context: cedar.NewRecord(cedar.RecordMap{
			"attestation_status":  cedar.String(req.AttestationStatus),
			"operator_authorized": cedar.Boolean(req.OperatorAuthorized),
		}),
	}

	// Evaluate
	decision, diagnostic := cedar.Authorize(a.policies, a.entities, cedarReq)

	// Extract reasons
	var reasons []string
	for _, r := range diagnostic.Reasons {
		reasons = append(reasons, string(r.PolicyID))
	}

	result := AuthzDecision{
		Allowed:  decision == cedar.Allow,
		Reasons:  reasons,
		Duration: time.Since(start),
	}

	// Log the decision
	a.logger.Info("authorization decision",
		"principal", req.PrincipalID,
		"role", req.PrincipalRole,
		"action", req.Action,
		"resource", req.ResourceID,
		"attestation", req.AttestationStatus,
		"authorized_for_ca_device", req.OperatorAuthorized,
		"decision", result.Allowed,
		"reasons", reasons,
		"duration_us", result.Duration.Microseconds(),
	)

	// Log errors if any
	for _, err := range diagnostic.Errors {
		a.logger.Error("policy evaluation error",
			"policy", err.PolicyID,
			"error", err.Message,
		)
	}

	return result
}

// PolicyCount returns the number of loaded policies.
func (a *Authorizer) PolicyCount() int {
	count := 0
	for range a.policies.All() {
		count++
	}
	return count
}

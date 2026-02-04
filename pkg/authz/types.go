package authz

import "time"

// AttestationStatus represents the attestation state of a DPU.
type AttestationStatus string

const (
	AttestationVerified    AttestationStatus = "verified"
	AttestationStale       AttestationStatus = "stale"
	AttestationUnavailable AttestationStatus = "unavailable"
	AttestationFailed      AttestationStatus = "failed"
)

// ReasonType classifies authorization decision reasons for HTTP status mapping.
// Middleware uses this type (not free-form strings) to determine response codes.
type ReasonType string

const (
	ReasonAllowed                ReasonType = "allowed"
	ReasonAttestationFailed      ReasonType = "attestation_failed"
	ReasonAttestationStale       ReasonType = "attestation_stale"
	ReasonAttestationUnavailable ReasonType = "attestation_unavailable"
	ReasonPolicyDenied           ReasonType = "policy_denied"
)

// DecisionReason provides structured authorization decision metadata.
// Type field determines HTTP status code mapping in middleware.
// Details provides human-readable explanation for logging and debugging.
type DecisionReason struct {
	Type    ReasonType // Primary classification for status code mapping
	SubType string     // Optional qualifier (e.g., "force_bypass_available")
	Details string     // Human-readable explanation
}

// Role represents a principal's role in the system.
// Per ADR-011: three-tier model with cross-tenant support.
type Role string

const (
	RoleOperator    Role = "operator"
	RoleTenantAdmin Role = "tenant:admin"
	RoleSuperAdmin  Role = "super:admin"
)

// PrincipalType distinguishes between Operator and DPU principals.
type PrincipalType string

const (
	PrincipalOperator PrincipalType = "Operator"
	PrincipalDPU      PrincipalType = "DPU"
)

// Principal represents the entity making the request.
type Principal struct {
	UID       string        // Unique identifier (e.g., "km_abc12345" or "dpu_xyz")
	Type      PrincipalType // Operator or DPU
	Role      Role          // operator, tenant:admin, super:admin
	TenantIDs []string      // Tenants this principal belongs to (supports multi-tenant)
}

// Resource represents the entity being accessed.
type Resource struct {
	UID      string // Unique identifier (e.g., "dpu_xyz", "ca_abc")
	Type     string // DPU, CertificateAuthority, Authorization, Tenant, etc.
	TenantID string // Tenant that owns this resource (empty for global resources)
}

// AuthzRequest contains all information needed for an authorization decision.
type AuthzRequest struct {
	Principal Principal
	Action    string                 // Fine-grained action (e.g., "credential:push", "dpu:read")
	Resource  Resource               // Target resource
	Context   map[string]any // Additional context: attestation_status, operator_authorized, etc.
}

// AuthzDecision contains the result of an authorization check.
type AuthzDecision struct {
	Allowed             bool           // True if access is permitted
	Reason              string         // Human-readable explanation (for logging/audit)
	StructuredReason    DecisionReason // Structured reason for HTTP status mapping
	PolicyID            string         // ID of the policy that determined the outcome (for audit)
	RequiresForceBypass bool           // True if denied due to stale/unavailable and super:admin can bypass
	Duration            time.Duration  // How long the authorization check took
}

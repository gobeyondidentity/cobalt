package authz

// Action constants for all API endpoints.
// These map 1:1 with API endpoints per ADR-011.
const (
	// Operator management
	ActionOperatorReadSelf = "operator:read_self"
	ActionOperatorInvite   = "operator:invite"
	ActionOperatorList     = "operator:list"
	ActionOperatorRead     = "operator:read"
	ActionOperatorRevoke   = "operator:revoke"

	// Role management
	ActionRoleAssign = "role:assign"
	ActionRoleRemove = "role:remove"

	// Authorization management
	ActionAuthorizationList   = "authorization:list"
	ActionAuthorizationCreate = "authorization:create"
	ActionAuthorizationDelete = "authorization:delete"

	// DPU management
	ActionDPUList            = "dpu:list"
	ActionDPURead            = "dpu:read"
	ActionDPURegister        = "dpu:register"
	ActionDPUDelete          = "dpu:delete"
	ActionDPUReadAttestation = "dpu:read_attestation"

	// Credential distribution
	ActionCredentialPush   = "credential:push"
	ActionCredentialPull   = "credential:pull"
	ActionDistributionList = "distribution:list"

	// DPU self-access (Aegis agent operations)
	ActionDPUReportAttestation = "dpu:report_attestation"
	ActionDPUReadOwnConfig     = "dpu:read_own_config"

	// Tenant management (bluectl only)
	ActionTenantCreate = "tenant:create"
	ActionTenantList   = "tenant:list"
	ActionTenantDelete = "tenant:delete"

	// Audit
	ActionAuditExport = "audit:export"

	// Trust management [POST-MVP]
	ActionTrustCreate = "trust:create"
	ActionTrustDelete = "trust:delete"
)

// validActions is the set of all valid action strings.
// Unknown actions are rejected (fail-closed per si-d2y.3.14).
var validActions = map[string]bool{
	ActionOperatorReadSelf:     true,
	ActionOperatorInvite:       true,
	ActionOperatorList:         true,
	ActionOperatorRead:         true,
	ActionOperatorRevoke:       true,
	ActionRoleAssign:           true,
	ActionRoleRemove:           true,
	ActionAuthorizationList:    true,
	ActionAuthorizationCreate:  true,
	ActionAuthorizationDelete:  true,
	ActionDPUList:              true,
	ActionDPURead:              true,
	ActionDPURegister:          true,
	ActionDPUDelete:            true,
	ActionDPUReadAttestation:   true,
	ActionCredentialPush:       true,
	ActionCredentialPull:       true,
	ActionDistributionList:     true,
	ActionDPUReportAttestation: true,
	ActionDPUReadOwnConfig:     true,
	ActionTenantCreate:         true,
	ActionTenantList:           true,
	ActionTenantDelete:         true,
	ActionAuditExport:          true,
	ActionTrustCreate:          true,
	ActionTrustDelete:          true,
}

// attestationGatedActions require valid attestation status.
// These actions are blocked when attestation is stale, unavailable, or failed.
var attestationGatedActions = map[string]bool{
	ActionCredentialPush: true,
	ActionCredentialPull: true,
}

// ValidateAction returns true if the action is a known valid action.
// Unknown actions should be rejected (fail-closed).
func ValidateAction(action string) bool {
	return validActions[action]
}

// RequiresAttestationGate returns true if the action requires attestation verification.
// Actions that modify or deliver credentials to DPUs are gated on attestation status.
func RequiresAttestationGate(action string) bool {
	return attestationGatedActions[action]
}

// AllActions returns all valid action strings.
// Useful for documentation and testing.
func AllActions() []string {
	actions := make([]string, 0, len(validActions))
	for a := range validActions {
		actions = append(actions, a)
	}
	return actions
}

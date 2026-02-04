package authz

import "strings"

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
	ActionAuthorizationCheck  = "authorization:check"

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

	// SSH CA management
	ActionSSHCACreate = "ssh-ca:create"
	ActionSSHCAList   = "ssh-ca:list"
	ActionSSHCARead   = "ssh-ca:read"

	// DPU self-access (Aegis agent operations)
	ActionDPUReportAttestation = "dpu:report_attestation"
	ActionDPUReadOwnConfig     = "dpu:read_own_config"

	// Tenant management (bluectl only)
	ActionTenantCreate      = "tenant:create"
	ActionTenantList        = "tenant:list"
	ActionTenantDelete      = "tenant:delete"
	ActionTenantAssignDPU   = "tenant:assign_dpu"
	ActionTenantListDPUs    = "tenant:list_dpus"
	ActionTenantUnassignDPU = "tenant:unassign_dpu"

	// Audit
	ActionAuditExport = "audit:export"

	// Trust management [POST-MVP]
	ActionTrustCreate = "trust:create"
	ActionTrustDelete = "trust:delete"

	// Host management (Phase 5)
	ActionHostRegister      = "host:register"
	ActionHostReportPosture = "host:report_posture"
	ActionHostList          = "host:list"
	ActionHostRead          = "host:read"
	ActionHostDelete        = "host:delete"
	ActionHostReadPosture   = "host:read_posture"
	ActionHostRequestCert   = "host:request_cert"
	ActionHostScan          = "host:scan"
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
	ActionAuthorizationCheck:   true,
	ActionDPUList:              true,
	ActionDPURead:              true,
	ActionDPURegister:          true,
	ActionDPUDelete:            true,
	ActionDPUReadAttestation:   true,
	ActionCredentialPush:       true,
	ActionCredentialPull:       true,
	ActionDistributionList:     true,
	ActionSSHCACreate:          true,
	ActionSSHCAList:            true,
	ActionSSHCARead:            true,
	ActionDPUReportAttestation: true,
	ActionDPUReadOwnConfig:     true,
	ActionTenantCreate:         true,
	ActionTenantList:           true,
	ActionTenantDelete:         true,
	ActionTenantAssignDPU:      true,
	ActionTenantListDPUs:       true,
	ActionTenantUnassignDPU:    true,
	ActionAuditExport:          true,
	ActionTrustCreate:          true,
	ActionTrustDelete:          true,
	ActionHostRegister:         true,
	ActionHostReportPosture:    true,
	ActionHostList:             true,
	ActionHostRead:             true,
	ActionHostDelete:           true,
	ActionHostReadPosture:      true,
	ActionHostRequestCert:      true,
	ActionHostScan:             true,
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

// Action represents a Cedar action string.
type Action string

// NoAuthRequired is a special marker indicating the endpoint does not require authentication.
// The middleware ONLY bypasses auth for endpoints explicitly marked with this value.
// SECURITY NOTE: Unknown endpoints return an error, NOT this marker. Fail-secure design.
const NoAuthRequired Action = "no-auth-required"

// ActionRegistry maps HTTP routes to Cedar actions.
// IMPORTANT: Any new endpoint must be added to this registry.
// Unknown routes return an error (fail-secure), not silent pass or auth bypass.
type ActionRegistry struct {
	routes map[routeKey]Action
}

// routeKey combines HTTP method and path pattern for lookup.
type routeKey struct {
	method  string
	pattern string
}

// NewActionRegistry creates a registry with all endpoint-to-action mappings.
// Maps are defined per ADR-011 Amendment and phase3-authz-epic-plan.md Appendix.
func NewActionRegistry() *ActionRegistry {
	r := &ActionRegistry{
		routes: make(map[routeKey]Action),
	}

	// ----- Pre-Authentication Endpoints (no auth required) -----
	// These are the ONLY endpoints that bypass authentication.
	r.register("GET", "/health", NoAuthRequired)
	r.register("POST", "/api/v1/admin/bootstrap", NoAuthRequired)
	r.register("POST", "/api/v1/enroll/init", NoAuthRequired)
	r.register("POST", "/api/v1/enroll/dpu/init", NoAuthRequired)
	r.register("POST", "/api/v1/enroll/complete", NoAuthRequired)

	// ----- Operator Endpoints -----
	r.register("GET", "/api/v1/operators/me", Action(ActionOperatorReadSelf))
	r.register("POST", "/api/v1/operators/invite", Action(ActionOperatorInvite))
	r.register("GET", "/api/v1/operators", Action(ActionOperatorList))
	r.register("GET", "/api/v1/operators/{id}", Action(ActionOperatorRead))
	r.register("DELETE", "/api/v1/operators/{id}", Action(ActionOperatorRevoke))

	// ----- Role Management Endpoints -----
	r.register("POST", "/api/v1/operators/{id}/roles", Action(ActionRoleAssign))
	r.register("DELETE", "/api/v1/operators/{id}/roles/{tenant_id}", Action(ActionRoleRemove))

	// ----- Authorization Endpoints -----
	r.register("GET", "/api/v1/authorizations", Action(ActionAuthorizationList))
	r.register("POST", "/api/v1/authorizations", Action(ActionAuthorizationCreate))
	r.register("DELETE", "/api/v1/authorizations/{id}", Action(ActionAuthorizationDelete))
	r.register("POST", "/api/v1/authorizations/check", Action(ActionAuthorizationCheck))

	// ----- DPU Management Endpoints -----
	r.register("GET", "/api/v1/dpus", Action(ActionDPUList))
	r.register("GET", "/api/v1/dpus/{id}", Action(ActionDPURead))
	r.register("POST", "/api/v1/dpus", Action(ActionDPURegister))
	r.register("DELETE", "/api/v1/dpus/{id}", Action(ActionDPUDelete))
	r.register("GET", "/api/v1/dpus/{id}/attestation", Action(ActionDPUReadAttestation))

	// ----- Credential Distribution Endpoints -----
	r.register("POST", "/api/v1/push", Action(ActionCredentialPush))
	r.register("GET", "/api/v1/distributions", Action(ActionDistributionList))

	// ----- SSH CA Endpoints -----
	r.register("POST", "/api/v1/ssh-cas", Action(ActionSSHCACreate))
	r.register("GET", "/api/v1/credentials/ssh-cas", Action(ActionSSHCAList))
	r.register("GET", "/api/v1/credentials/ssh-cas/{name}", Action(ActionSSHCARead))

	// ----- DPU Agent Endpoints (Aegis) -----
	r.register("GET", "/api/v1/dpus/{id}/credentials", Action(ActionCredentialPull))
	r.register("POST", "/api/v1/dpus/{id}/attestation", Action(ActionDPUReportAttestation))
	r.register("GET", "/api/v1/dpus/{id}/config", Action(ActionDPUReadOwnConfig))

	// ----- Tenant Management Endpoints (bluectl) -----
	r.register("POST", "/api/v1/tenants", Action(ActionTenantCreate))
	r.register("GET", "/api/v1/tenants", Action(ActionTenantList))
	r.register("DELETE", "/api/v1/tenants/{id}", Action(ActionTenantDelete))
	r.register("POST", "/api/v1/tenants/{id}/dpus", Action(ActionTenantAssignDPU))
	r.register("GET", "/api/v1/tenants/{id}/dpus", Action(ActionTenantListDPUs))
	r.register("DELETE", "/api/v1/tenants/{id}/dpus/{dpuId}", Action(ActionTenantUnassignDPU))

	// ----- Audit Endpoints -----
	r.register("GET", "/api/v1/audit", Action(ActionAuditExport))

	// ----- Trust Management [POST-MVP] -----
	r.register("POST", "/api/v1/trust-relationships", Action(ActionTrustCreate))
	r.register("DELETE", "/api/v1/trust-relationships/{id}", Action(ActionTrustDelete))

	// ----- Host Management Endpoints (Phase 5) -----
	r.register("POST", "/api/v1/hosts/register", Action(ActionHostRegister))
	r.register("POST", "/api/v1/hosts/{id}/posture", Action(ActionHostReportPosture))
	r.register("GET", "/api/v1/hosts", Action(ActionHostList))
	r.register("GET", "/api/v1/hosts/{id}", Action(ActionHostRead))
	r.register("DELETE", "/api/v1/hosts/{id}", Action(ActionHostDelete))
	r.register("GET", "/api/v1/hosts/{dpuName}/posture", Action(ActionHostReadPosture))
	r.register("POST", "/api/v1/hosts/{hostname}/cert", Action(ActionHostRequestCert))
	r.register("POST", "/api/v1/hosts/{hostname}/scan", Action(ActionHostScan))

	return r
}

// register adds a route-to-action mapping.
func (r *ActionRegistry) register(method, pattern string, action Action) {
	r.routes[routeKey{method: method, pattern: pattern}] = action
}

// Lookup returns the Cedar action for a given HTTP method and path.
// Returns an error for unknown routes (fail-secure design).
// SECURITY: Middleware ONLY bypasses auth for NoAuthRequired, never for errors.
func (r *ActionRegistry) Lookup(method, path string) (Action, error) {
	// Validate path format before matching
	// SECURITY: Reject malformed paths (e.g., double slashes) to prevent path confusion attacks
	if err := validatePath(path); err != nil {
		return "", err
	}

	// Try exact match first
	if action, ok := r.routes[routeKey{method: method, pattern: path}]; ok {
		return action, nil
	}

	// Try pattern matching for parameterized routes
	for key, action := range r.routes {
		if key.method != method {
			continue
		}
		if matchPattern(key.pattern, path) {
			return action, nil
		}
	}

	// Unknown route: return error (fail-secure)
	// SECURITY: Do NOT return NoAuthRequired for unknown routes.
	return "", ErrUnknownRoute(method, path)
}

// LookupOrDefault returns the action for a route, or a default if not found.
// This is NOT recommended for security-critical paths; use Lookup instead.
func (r *ActionRegistry) LookupOrDefault(method, path string, defaultAction Action) Action {
	action, err := r.Lookup(method, path)
	if err != nil {
		return defaultAction
	}
	return action
}

// IsPreAuthEndpoint returns true if the route does not require authentication.
// SECURITY: Only explicitly registered NoAuthRequired endpoints return true.
// Unknown endpoints return false (fail-secure).
func (r *ActionRegistry) IsPreAuthEndpoint(method, path string) bool {
	action, err := r.Lookup(method, path)
	if err != nil {
		return false // Unknown routes require auth (fail-secure)
	}
	return action == NoAuthRequired
}

// AllRoutes returns all registered route patterns.
// Useful for documentation and testing.
func (r *ActionRegistry) AllRoutes() []string {
	routes := make([]string, 0, len(r.routes))
	for k := range r.routes {
		routes = append(routes, k.method+" "+k.pattern)
	}
	return routes
}

// validatePath checks if a path is well-formed.
// SECURITY: Rejects paths that could cause confusion or bypass issues.
// Returns an error for malformed paths, nil if valid.
func validatePath(path string) error {
	// Reject empty paths
	if path == "" {
		return ErrMalformedPath(path, "empty path")
	}

	// Reject paths with double slashes (e.g., /api/v1//dpus)
	// These could be used to confuse path matching or bypass security checks
	if strings.Contains(path, "//") {
		return ErrMalformedPath(path, "contains double slashes")
	}

	return nil
}

// matchPattern checks if a path matches a pattern with {param} placeholders.
// Example: matchPattern("/api/v1/dpus/{id}", "/api/v1/dpus/dpu_xyz") returns true.
func matchPattern(pattern, path string) bool {
	patternParts := splitPath(pattern)
	pathParts := splitPath(path)

	if len(patternParts) != len(pathParts) {
		return false
	}

	for i, pp := range patternParts {
		// {param} matches any non-empty segment
		if len(pp) > 2 && pp[0] == '{' && pp[len(pp)-1] == '}' {
			if pathParts[i] == "" {
				return false // Param must be non-empty
			}
			continue
		}
		// Literal segment must match exactly
		if pp != pathParts[i] {
			return false
		}
	}

	return true
}

// splitPath splits a path into segments, handling leading/trailing slashes.
func splitPath(path string) []string {
	if path == "" {
		return nil
	}
	// Remove leading slash
	if path[0] == '/' {
		path = path[1:]
	}
	// Remove trailing slash
	if len(path) > 0 && path[len(path)-1] == '/' {
		path = path[:len(path)-1]
	}
	if path == "" {
		return nil
	}

	var parts []string
	start := 0
	for i := 0; i <= len(path); i++ {
		if i == len(path) || path[i] == '/' {
			parts = append(parts, path[start:i])
			start = i + 1
		}
	}
	return parts
}

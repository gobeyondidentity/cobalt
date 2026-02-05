// Cedar Policy Set for Project Cobalt Authorization
// Production policies implementing ADR-011 decisions
//
// Role model: operator < tenant:admin < super:admin
// Attestation gate: failed=hard block, stale/unavailable=soft block (super:admin can bypass)

// ============================================================================
// ROLE-BASED ACCESS: Three-tier role model
// ============================================================================

// Operators can only access resources they have explicit authorization for
permit(
    principal is Operator,
    action,
    resource
) when {
    principal.role == "operator" &&
    context.operator_authorized == true
};

// Tenant admins can access all resources within their tenant
// Checks if resource's tenant is in the principal's tenant_ids set
permit(
    principal is Operator,
    action,
    resource
) when {
    principal.role == "tenant:admin" &&
    principal.tenant_ids.contains(resource.tenant)
};

// Super admins can access all resources globally
permit(
    principal is Operator,
    action,
    resource
) when {
    principal.role == "super:admin"
};

// ============================================================================
// OPERATOR SELF-ACCESS
// ============================================================================

// Any operator can read their own info (regardless of role)
permit(
    principal is Operator,
    action == Action::"operator:read_self",
    resource is Operator
) when {
    principal == resource
};

// ============================================================================
// SSH CA MANAGEMENT: Operators can create and manage SSH CAs
// ============================================================================

// Any operator can create SSH CAs in their own tenant
permit(
    principal is Operator,
    action == Action::"ssh-ca:create",
    resource
) when {
    principal.tenant_ids.contains(resource.tenant)
};

// Operators can list and read SSH CAs in their tenant
permit(
    principal is Operator,
    action in [Action::"ssh-ca:list", Action::"ssh-ca:read"],
    resource is SSHCA
) when {
    principal.tenant_ids.contains(resource.tenant)
};

// Operators can check their own authorizations
permit(
    principal is Operator,
    action == Action::"authorization:check",
    resource
);

// ============================================================================
// DPU SELF-ACCESS: Devices can access their own resources
// ============================================================================

// DPU can pull its own credentials
permit(
    principal is DPU,
    action == Action::"credential:pull",
    resource is DPU
) when {
    principal == resource
};

// DPU can report its own attestation
permit(
    principal is DPU,
    action == Action::"dpu:report_attestation",
    resource is DPU
) when {
    principal == resource
};

// DPU can read its own config
permit(
    principal is DPU,
    action == Action::"dpu:read_own_config",
    resource is DPU
) when {
    principal == resource
};

// ============================================================================
// ATTESTATION GATE: Blocks based on device attestation status
// ============================================================================

// FORBID: Failed attestation ALWAYS blocks (highest priority deny)
// This applies to ALL principals, including super:admin - no bypass possible
forbid(
    principal,
    action == Action::"credential:push",
    resource
) when {
    context.attestation_status == "failed"
};

forbid(
    principal,
    action == Action::"credential:pull",
    resource
) when {
    context.attestation_status == "failed"
};

// FORBID: Stale attestation blocks operators
// (tenant:admin and super:admin not blocked - they can force bypass at app layer)
forbid(
    principal is Operator,
    action == Action::"credential:push",
    resource
) when {
    principal.role == "operator" &&
    context.attestation_status == "stale"
};

forbid(
    principal is Operator,
    action == Action::"credential:pull",
    resource
) when {
    principal.role == "operator" &&
    context.attestation_status == "stale"
};

// FORBID: Unavailable attestation blocks operators
forbid(
    principal is Operator,
    action == Action::"credential:push",
    resource
) when {
    principal.role == "operator" &&
    context.attestation_status == "unavailable"
};

forbid(
    principal is Operator,
    action == Action::"credential:pull",
    resource
) when {
    principal.role == "operator" &&
    context.attestation_status == "unavailable"
};

// ============================================================================
// DPU CROSS-ACCESS DENIAL
// ============================================================================

// DPU cannot access other DPUs' credentials (explicit deny for defense in depth)
forbid(
    principal is DPU,
    action == Action::"credential:pull",
    resource is DPU
) when {
    principal != resource
};

// ============================================================================
// LIFECYCLE MANAGEMENT (Phase 4)
// ============================================================================

// ----- KeyMaker Revocation -----
// Operators can revoke their OWN KeyMakers only
// Uses context.is_resource_owner set by the application
permit(
    principal is Operator,
    action == Action::"keymaker:revoke",
    resource is KeyMaker
) when {
    principal.role == "operator" &&
    context.is_resource_owner == true
};

// tenant:admin can revoke KeyMakers for operators in their tenant
// (handled by generic tenant:admin policy, included here for documentation)

// super:admin can revoke any KeyMaker
// (handled by generic super:admin policy)

// ----- AdminKey Revocation -----
// ONLY super:admin can revoke admin keys (security-critical)
// Tenant admins are explicitly forbidden
forbid(
    principal is Operator,
    action == Action::"adminkey:revoke",
    resource
) when {
    principal.role == "tenant:admin"
};

// Operators cannot revoke admin keys
forbid(
    principal is Operator,
    action == Action::"adminkey:revoke",
    resource
) when {
    principal.role == "operator"
};

// ----- Operator Suspension -----
// tenant:admin can suspend/unsuspend operators in their tenant
// (handled by generic tenant:admin policy)

// super:admin can suspend/unsuspend any operator
// (handled by generic super:admin policy)

// Operators cannot suspend other operators
forbid(
    principal is Operator,
    action in [Action::"operator:suspend", Action::"operator:unsuspend"],
    resource
) when {
    principal.role == "operator"
};

// ----- DPU Decommissioning -----
// tenant:admin can decommission DPUs in their tenant
// (handled by generic tenant:admin policy)

// super:admin can decommission any DPU
// (handled by generic super:admin policy)

// Operators cannot decommission DPUs
forbid(
    principal is Operator,
    action == Action::"dpu:decommission",
    resource
) when {
    principal.role == "operator"
};

// ----- DPU Reactivation -----
// ONLY super:admin can reactivate DPUs (security-critical recovery operation)
// Tenant admins are explicitly forbidden
forbid(
    principal is Operator,
    action == Action::"dpu:reactivate",
    resource
) when {
    principal.role == "tenant:admin"
};

// Operators cannot reactivate DPUs
forbid(
    principal is Operator,
    action == Action::"dpu:reactivate",
    resource
) when {
    principal.role == "operator"
};

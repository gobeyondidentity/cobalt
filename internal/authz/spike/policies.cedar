// Cedar Policy Set for Project Cobalt Authorization
// Spike: Evaluate cedar-go integration for MVP authorization layer

// ============================================================================
// ROLE-BASED ACCESS: Operators can push credentials to DPUs they're authorized for
// ============================================================================

// Operator can push credentials if they have an authorization for the CA and device
permit(
    principal is Operator,
    action == Action::"push_credential",
    resource is DPU
) when {
    // Check operator has authorization for this CA and device
    context.operator_authorized == true
};

// Tenant admin inherits operator permissions plus can manage authorizations
permit(
    principal is TenantAdmin,
    action == Action::"push_credential",
    resource is DPU
) when {
    context.operator_authorized == true
};

// Super admin can push credentials without authorization check
permit(
    principal is SuperAdmin,
    action == Action::"push_credential",
    resource is DPU
);

// ============================================================================
// ATTESTATION GATE: All credential pushes gated on device attestation status
// ============================================================================

// FORBID: Failed attestation always blocks (highest priority deny)
// This applies to ALL principals, including super-admin
forbid(
    principal,
    action == Action::"push_credential",
    resource is DPU
) when {
    context.attestation_status == "failed"
};

// FORBID: Stale attestation blocks operators and tenant-admins
// Super-admin bypasses this check (no forbid rule for them)
forbid(
    principal is Operator,
    action == Action::"push_credential",
    resource is DPU
) when {
    context.attestation_status == "stale"
};

forbid(
    principal is TenantAdmin,
    action == Action::"push_credential",
    resource is DPU
) when {
    context.attestation_status == "stale"
};

// FORBID: Unavailable attestation blocks operators and tenant-admins
forbid(
    principal is Operator,
    action == Action::"push_credential",
    resource is DPU
) when {
    context.attestation_status == "unavailable"
};

forbid(
    principal is TenantAdmin,
    action == Action::"push_credential",
    resource is DPU
) when {
    context.attestation_status == "unavailable"
};

// ============================================================================
// ADDITIONAL ACTIONS (stub for future expansion)
// ============================================================================

// Super admin can manage all operations
permit(
    principal is SuperAdmin,
    action,
    resource
);

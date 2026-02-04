// Cedar Policies: Role-Based Access Control
// Implements three-tier role model per ADR-011 Decision 2
//
// Role Hierarchy: operator < tenant:admin < super:admin
//
// - operator: Access only to resources with explicit Authorization
// - tenant:admin: Access to all resources within assigned tenant(s)
// - super:admin: Global access across all tenants

// ============================================================================
// OPERATOR ROLE: Explicit Authorization Required
// ============================================================================

// Operators can access resources only when they have explicit authorization.
// The authorization check is performed at the application layer and passed
// via context.operator_authorized.
@id("roles-operator-explicit-auth")
permit(
    principal is Cobalt::Operator,
    action,
    resource
) when {
    principal.role == "operator" &&
    context.operator_authorized == true
};

// ============================================================================
// TENANT ADMIN ROLE: Full Tenant Access
// ============================================================================

// Tenant admins can access all resources within their assigned tenant(s).
// Multi-tenant support: tenant_ids is a set of all tenants the admin belongs to.
// Resource must belong to one of the admin's tenants.
@id("roles-tenant-admin-own-tenant")
permit(
    principal is Cobalt::Operator,
    action,
    resource
) when {
    principal.role == "tenant:admin" &&
    principal.tenant_ids.contains(resource.tenant)
};

// ============================================================================
// SUPER ADMIN ROLE: Global Access
// ============================================================================

// Super admins can access any resource globally, regardless of tenant.
// No tenant check required.
@id("roles-super-admin-global")
permit(
    principal is Cobalt::Operator,
    action,
    resource
) when {
    principal.role == "super:admin"
};

// ============================================================================
// SELF-ACCESS: Any Operator Can Read Their Own Info
// ============================================================================

// Regardless of role, operators can always read their own profile.
// This ensures whoami/me endpoints work for everyone.
@id("roles-operator-self-read")
permit(
    principal is Cobalt::Operator,
    action == Cobalt::Action::"operator:read_self",
    resource is Cobalt::Operator
) when {
    principal == resource
};

// ============================================================================
// ROLE ASSIGNMENT CONSTRAINTS
// ============================================================================

// Tenant admin can assign roles: operator, tenant:admin (not super:admin)
// This is enforced via forbid: tenant:admin cannot assign super:admin
@id("roles-tenant-admin-cannot-grant-super")
forbid(
    principal is Cobalt::Operator,
    action == Cobalt::Action::"role:assign",
    resource is Cobalt::Operator
) when {
    principal.role == "tenant:admin" &&
    context.target_role == "super:admin"
};

// Operators cannot assign any roles (they're not admins)
@id("roles-operator-cannot-assign")
forbid(
    principal is Cobalt::Operator,
    action == Cobalt::Action::"role:assign",
    resource is Cobalt::Operator
) when {
    principal.role == "operator"
};

// Super admin can assign any role including super:admin
// This is implicitly permitted by the super-admin-global policy above.
// No additional rule needed.

// Cedar Policies: Attestation Gate
// Implements hardware-enforced Zero Trust per ADR-011 Decision 6
//
// Attestation States:
//   - verified: Fresh attestation, all checks passed
//   - stale: Attestation older than threshold (configurable)
//   - unavailable: No attestation data available (new DPU, connection issues)
//   - failed: Attestation failed validation (measurements mismatch, chain invalid)
//
// Access Rules:
//   - failed: HARD BLOCK for everyone, no bypass possible
//   - stale/unavailable: Soft block, super:admin can bypass with audit trail
//   - verified: Normal access per role-based policies

// ============================================================================
// ATTESTATION GATE: credential:push (Operator -> DPU)
// ============================================================================

// FORBID: Failed attestation ALWAYS blocks credential:push.
// This is the highest priority deny. Even super:admin CANNOT bypass.
// A DPU with failed attestation has potentially compromised integrity.
@id("attestation-forbid-push-failed")
forbid(
    principal,
    action == Cobalt::Action::"credential:push",
    resource
) when {
    context.attestation_status == "failed"
};

// FORBID: Stale attestation blocks operators from credential:push.
// Only operators are blocked; tenant:admin and super:admin can bypass
// at the application layer (with force flag and audit trail).
@id("attestation-forbid-push-stale-operator")
forbid(
    principal is Cobalt::Operator,
    action == Cobalt::Action::"credential:push",
    resource
) when {
    principal.role == "operator" &&
    context.attestation_status == "stale"
};

// FORBID: Stale attestation blocks tenant:admin from credential:push.
// Tenant:admin also blocked; only super:admin can bypass.
@id("attestation-forbid-push-stale-tenant-admin")
forbid(
    principal is Cobalt::Operator,
    action == Cobalt::Action::"credential:push",
    resource
) when {
    principal.role == "tenant:admin" &&
    context.attestation_status == "stale"
};

// FORBID: Unavailable attestation blocks operators from credential:push.
@id("attestation-forbid-push-unavailable-operator")
forbid(
    principal is Cobalt::Operator,
    action == Cobalt::Action::"credential:push",
    resource
) when {
    principal.role == "operator" &&
    context.attestation_status == "unavailable"
};

// FORBID: Unavailable attestation blocks tenant:admin from credential:push.
@id("attestation-forbid-push-unavailable-tenant-admin")
forbid(
    principal is Cobalt::Operator,
    action == Cobalt::Action::"credential:push",
    resource
) when {
    principal.role == "tenant:admin" &&
    context.attestation_status == "unavailable"
};

// NOTE: super:admin is NOT blocked by stale/unavailable for credential:push.
// Policy permits via roles.cedar. App layer handles force bypass with audit.

// ============================================================================
// ATTESTATION GATE: credential:pull (DPU self-access)
// ============================================================================

// FORBID: Failed attestation blocks DPU from pulling credentials.
// A compromised DPU should not receive credentials.
@id("attestation-forbid-pull-failed")
forbid(
    principal is Cobalt::DPU,
    action == Cobalt::Action::"credential:pull",
    resource
) when {
    context.attestation_status == "failed"
};

// FORBID: Stale attestation blocks DPU from pulling credentials.
// DPU must re-attest before receiving credentials.
@id("attestation-forbid-pull-stale")
forbid(
    principal is Cobalt::DPU,
    action == Cobalt::Action::"credential:pull",
    resource
) when {
    context.attestation_status == "stale"
};

// FORBID: Unavailable attestation blocks DPU from pulling credentials.
// DPU must complete attestation before receiving credentials.
@id("attestation-forbid-pull-unavailable")
forbid(
    principal is Cobalt::DPU,
    action == Cobalt::Action::"credential:pull",
    resource
) when {
    context.attestation_status == "unavailable"
};

// ============================================================================
// APPLICATION LAYER NOTES (not Cedar policy, but documented here)
// ============================================================================
//
// When Cedar returns deny for super:admin with stale/unavailable attestation:
//   - Actually, super:admin is NOT denied by these policies (no forbid rule)
//   - So super:admin IS permitted to credential:push with stale/unavailable
//   - The app layer should:
//     1. Recognize stale/unavailable status
//     2. Require explicit --force flag for bypass
//     3. Log bypass with full audit trail including:
//        - Who bypassed (principal)
//        - What resource
//        - What attestation status was at time of bypass
//        - Reason/justification if provided
//
// For DPU credential:pull with stale/unavailable:
//   - DPU is blocked by policy (forbid rules above)
//   - No bypass available for DPU self-access
//   - DPU must re-attest to become verified
//
// RequiresForceBypass flag in AuthzDecision:
//   - Set to true when:
//     a. Decision is deny (from Cedar or app layer)
//     b. Attestation status is stale or unavailable (not failed)
//     c. Principal is super:admin
//   - Signals to caller that --force can override this deny

// Cedar Policies: Resource Access Control (DPU Self-Access)
// Implements DPU-to-own-resource access per ADR-011 Amendment
//
// DPUs are both principals (when Aegis makes requests) and resources
// (when operators manage them). This policy file handles DPU self-access.
//
// Security Boundary: DPU-001 MUST NOT access DPU-002's resources

// ============================================================================
// DPU SELF-ACCESS: Pull Own Credentials
// ============================================================================

// DPU can pull credentials where the credential is targeted at itself.
// The resource is an IssuedCredential with target_dpu attribute.
@id("resources-dpu-pull-own-credentials")
permit(
    principal is Cobalt::DPU,
    action == Cobalt::Action::"credential:pull",
    resource is Cobalt::IssuedCredential
) when {
    resource.target_dpu == principal
};

// DPU can also pull credentials when principal == resource (DPU pulling from itself).
// This handles the case where resource type is DPU, not IssuedCredential.
@id("resources-dpu-pull-self")
permit(
    principal is Cobalt::DPU,
    action == Cobalt::Action::"credential:pull",
    resource is Cobalt::DPU
) when {
    principal == resource
};

// ============================================================================
// DPU SELF-ACCESS: Report Own Attestation
// ============================================================================

// DPU can report its own attestation status.
// Aegis reports measurements, chain status, etc. for its own DPU only.
@id("resources-dpu-report-own-attestation")
permit(
    principal is Cobalt::DPU,
    action == Cobalt::Action::"dpu:report_attestation",
    resource is Cobalt::DPU
) when {
    principal == resource
};

// ============================================================================
// DPU SELF-ACCESS: Read Own Config
// ============================================================================

// DPU can read its own configuration.
// Aegis needs to fetch its configuration from Nexus.
@id("resources-dpu-read-own-config")
permit(
    principal is Cobalt::DPU,
    action == Cobalt::Action::"dpu:read_own_config",
    resource is Cobalt::DPU
) when {
    principal == resource
};

// ============================================================================
// DPU CROSS-ACCESS DENIAL: Defense in Depth
// ============================================================================

// FORBID: DPU cannot pull credentials from another DPU.
// This is critical: DPU-001 must NEVER see DPU-002's credentials.
@id("resources-forbid-dpu-cross-pull")
forbid(
    principal is Cobalt::DPU,
    action == Cobalt::Action::"credential:pull",
    resource is Cobalt::DPU
) when {
    principal != resource
};

// FORBID: DPU cannot report attestation for another DPU.
// This prevents spoofing another DPU's attestation status.
@id("resources-forbid-dpu-cross-attestation")
forbid(
    principal is Cobalt::DPU,
    action == Cobalt::Action::"dpu:report_attestation",
    resource is Cobalt::DPU
) when {
    principal != resource
};

// FORBID: DPU cannot read another DPU's config.
@id("resources-forbid-dpu-cross-config")
forbid(
    principal is Cobalt::DPU,
    action == Cobalt::Action::"dpu:read_own_config",
    resource is Cobalt::DPU
) when {
    principal != resource
};

// FORBID: DPU cannot pull credentials targeted at another DPU.
// Even for IssuedCredential resources, check target_dpu != principal.
@id("resources-forbid-dpu-cross-credential")
forbid(
    principal is Cobalt::DPU,
    action == Cobalt::Action::"credential:pull",
    resource is Cobalt::IssuedCredential
) when {
    resource.target_dpu != principal
};

// ============================================================================
// DPU SELF-ACCESS: Register Connected Host (Phase 5)
// ============================================================================

// DPU can register its connected host with Nexus.
// Aegis reports host information for the machine this DPU is installed in.
@id("resources-dpu-register-host")
permit(
    principal is Cobalt::DPU,
    action == Cobalt::Action::"host:register",
    resource is Cobalt::DPU
) when {
    principal == resource
};

// FORBID: DPU cannot register a host for another DPU.
@id("resources-forbid-dpu-cross-host-register")
forbid(
    principal is Cobalt::DPU,
    action == Cobalt::Action::"host:register",
    resource is Cobalt::DPU
) when {
    principal != resource
};

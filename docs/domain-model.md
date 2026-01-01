# Fabric Console Domain Model

This document defines the conceptual entities, relationships, and states that comprise Fabric Console. It serves as the authoritative reference for understanding what the system manages and how components relate to each other.

---

## Overview

Fabric Console is a control plane for managing NVIDIA BlueField DPUs with hardware-rooted trust. The domain model captures:

- **What we manage**: DPUs, their attestation state, network flows, and associated hosts
- **How we organize**: Tenants as isolation boundaries, policies as access control
- **What we observe**: Certificates, measurements, flows, firmware inventory

This model follows the principle that expert-grade visibility precedes simplification. Every entity exposes its full state before abstractions (status badges, health scores) are layered on top.

---

## Connection to Beyond Identity

Fabric Console operates in a complementary domain to Beyond Identity's identity platform:

| Beyond Identity | Fabric Console | Relationship |
|-----------------|----------------|--------------|
| Tenant | Tenant | Same organization, can be linked |
| Identity | (Operator via BI auth) | Operators authenticate via Beyond Identity |
| Device | Host | BI Device = endpoint; FC Host = server with DPU |
| Credential | DICE Certificate | Both are hardware-bound, immovable identity |

**Trust Chain Integration**:
```
Beyond Identity                          Fabric Console
─────────────────                        ──────────────
Identity (operator)
    │
    └── Device (workstation)
            │
            │ [authenticated session]
            ▼
                                         Tenant
                                             │
                                             └── DPU ←── DICE attestation
                                                   │
                                                   └── Host ←── DPU's view
                                                         │
                                                         └── Workloads
```

Future integration: DPU attestation as a Beyond Identity credential type, enabling policies like "allow access only from hosts with verified DPU attestation."

---

## Entity Hierarchy

```
FabricConsole (1)                                    api(read)
│
└── Tenant (0:N)                                     api(create,read,list,update,delete)
    │
    ├── AuditLog (1:N)                               api(read,list)
    │
    ├── Policy [namespace]
    │   └── Rule (0:N)                               api(create,read,list,update,delete)
    │
    └── DPU (0:N)                                    api(create,read,list,update,delete)
        │
        ├── Agent (1)                                api(read)
        │
        ├── SystemInfo (1)                           api(read)
        │
        ├── Attestation [namespace]
        │   ├── Chain (0:2)                          api(read,list)
        │   │   └── Certificate (1:N)                api(read,list)
        │   ├── Measurement (0:N)                    api(read,list)
        │   ├── ReferenceValue (0:N)                 api(read,list,upload)
        │   └── Result (0:N)                         api(read,list)
        │
        ├── Network [namespace]
        │   ├── Bridge (0:N)                         api(read,list)
        │   └── Flow (0:N)                           api(read,list,create,delete)
        │
        └── Host (0:1)                               api(read)
            ├── FirmwareInventory (1)                api(read)
            │   └── Package (0:N)                    api(read,list)
            ├── KernelModule (0:N)                   api(read,list)
            └── SecurityPosture (1)                  api(read)
```

**Notation**:
- `(0:N)` = zero to many instances
- `(0:1)` = zero or one instance
- `(1)` = exactly one instance
- `(1:N)` = one or more instances
- `[namespace]` = logical grouping, not a separate entity
- `api(...)` = available API operations

---

## Entity Definitions

### FabricConsole

The root entity representing the control plane installation.

| Dimension | Attributes |
|-----------|------------|
| **Capabilities** | version, supported_features[], max_tenants |
| **Configuration** | listen_address, tls_config, database_path |
| **Operational State** | uptime, tenant_count, connected_agents |

---

### Tenant

An isolation boundary for DPUs and policies. Maps to organizational ownership.

| Dimension | Attributes |
|-----------|------------|
| **Capabilities** | max_dpus, enabled_features[] |
| **Configuration** | name, description, beyond_identity_tenant_id (optional) |
| **Operational State** | dpu_count, healthy_count, attestation_summary |

**Relationships**:
- Contains 0:N DPUs
- Contains 0:N Policy Rules
- Contains 1:N AuditLog entries

---

### DPU

A BlueField Data Processing Unit under management.

| Dimension | Attributes |
|-----------|------------|
| **Capabilities** | model, serial_number, arm_cores, memory_gb, firmware_version, psid |
| **Configuration** | name, address, agent_port, bmc_endpoint, bmc_credentials_ref, polling_interval |
| **Operational State** | connection_status, last_seen, uptime, attestation_status |

**States**:
```
                    ┌──────────┐
          register  │          │  agent connects
    ───────────────►│ Pending  │────────────────────┐
                    │          │                    │
                    └──────────┘                    ▼
                         │                   ┌───────────┐
                         │ timeout           │           │
                         │                   │ Connected │◄────┐
                         ▼                   │           │     │ reconnect
                    ┌──────────┐             └───────────┘     │
                    │          │                    │          │
                    │  Error   │◄───────────────────┤          │
                    │          │  connection lost   │          │
                    └──────────┘                    ▼          │
                                             ┌───────────┐     │
                                             │           │─────┘
                                             │Disconnected
                                             │           │
                                             └───────────┘
```

**Relationships**:
- Belongs to 1 Tenant
- Has 1 Agent (embedded)
- Has 1 SystemInfo
- Has 0:2 Attestation Chains (IRoT, ERoT)
- Has 0:N Network Bridges
- Has 0:1 Host

---

### Agent

The software agent running on the DPU's ARM cores.

| Dimension | Attributes |
|-----------|------------|
| **Capabilities** | version, supported_commands[], grpc_version |
| **Configuration** | listen_port, tls_cert_ref |
| **Operational State** | connected_since, last_heartbeat, commands_executed |

---

### SystemInfo

Hardware and software information about the DPU.

| Dimension | Attributes |
|-----------|------------|
| **Capabilities** | (derived from hardware) |
| **Configuration** | (none) |
| **Operational State** | model, serial_number, firmware_version, psid, part_number, arm_cores, memory_gb, uptime, os_version, kernel_version |

---

### Chain (Attestation)

A DICE or SPDM certificate chain from the DPU's roots of trust.

| Dimension | Attributes |
|-----------|------------|
| **Capabilities** | chain_type (irot/erot), max_depth |
| **Configuration** | reference_values_source |
| **Operational State** | certificates[], validation_result, last_validated, chain_valid_until |

**Chain Types**:
- **IRoT (Internal Root of Trust)**: DICE chain from DPU's internal secure boot
- **ERoT (External Root of Trust)**: SPDM chain from BMC's external attestation

---

### Certificate

An X.509 certificate within an attestation chain.

| Dimension | Attributes |
|-----------|------------|
| **Capabilities** | (none, immutable artifact) |
| **Configuration** | (none) |
| **Operational State** | subject, issuer, serial_number, not_before, not_after, public_key_algorithm, signature_algorithm, extensions[], dice_layer, pem |

**DICE Layers**:
| Layer | Component | Measures |
|-------|-----------|----------|
| L0 | ROM | Immutable boot code |
| L1 | Firmware Loader | Primary bootloader |
| L2 | Firmware | UEFI/ARM-TF |
| L3 | OS Loader | GRUB/systemd-boot |
| L4 | OS Kernel | Linux kernel |
| L5 | OS Services | Systemd, drivers |
| L6 | Application | DOCA agent |

---

### Measurement

A cryptographic hash of a firmware or software component.

| Dimension | Attributes |
|-----------|------------|
| **Capabilities** | algorithm (sha256/sha384/sha512) |
| **Configuration** | expected_value (from ReferenceValue) |
| **Operational State** | index, actual_value, component_name, match_status |

**Match Status**:
- `matched`: Actual equals expected
- `mismatched`: Actual differs from expected
- `unknown`: No reference value available

---

### ReferenceValue

A known-good measurement value from a CoRIM (Concise Reference Integrity Manifest).

| Dimension | Attributes |
|-----------|------------|
| **Capabilities** | format (corim/manual) |
| **Configuration** | source_url, auto_update |
| **Operational State** | component_name, expected_hash, algorithm, valid_firmware_versions[], last_updated |

---

### Result (Attestation)

The outcome of validating a DPU's attestation state.

| Dimension | Attributes |
|-----------|------------|
| **Capabilities** | (none) |
| **Configuration** | (none) |
| **Operational State** | timestamp, chain_type, overall_status, certificate_validations[], measurement_matches[], issues[] |

**Overall Status**:
```
           ┌─────────────────────────────────────────────────┐
           │                                                 │
           ▼                                                 │
      ┌─────────┐      ┌──────────┐      ┌─────────┐        │
      │         │      │          │      │         │        │
      │ Unknown │─────►│ Verified │─────►│ Failed  │────────┘
      │         │      │          │      │         │
      └─────────┘      └──────────┘      └─────────┘
           │                │                 │
           │                │                 │
           ▼                ▼                 ▼
      No attestation   All certs valid,   Cert invalid,
      data available   measurements match  measurement mismatch,
                                           or chain broken
```

---

### Bridge (Network)

An OVS bridge on the DPU.

| Dimension | Attributes |
|-----------|------------|
| **Capabilities** | datapath_type, protocols[] |
| **Configuration** | name, fail_mode, stp_enable |
| **Operational State** | ports[], controller, flow_count |

---

### Flow (Network)

An OpenFlow rule in an OVS bridge.

| Dimension | Attributes |
|-----------|------------|
| **Capabilities** | (none) |
| **Configuration** | table_id, priority, match, actions, idle_timeout, hard_timeout |
| **Operational State** | packet_count, byte_count, duration, age |

**Match Criteria Examples**:
- `in_port=1,dl_type=0x0800,nw_src=10.0.0.0/8`
- `dl_dst=ff:ff:ff:ff:ff:ff`
- `tcp,tp_dst=443`

---

### Host

The server machine containing the DPU, as observed by the DPU.

| Dimension | Attributes |
|-----------|------------|
| **Capabilities** | cpu_model, memory_gb, gpu_count, gpu_models[], pcie_topology |
| **Configuration** | hostname, host_agent_address |
| **Operational State** | connection_status, os_version, kernel_version, last_seen |

**Trust Model**: The DPU's view of the host is authoritative. When host agent reports conflict with DPU observations, the DPU's view takes precedence (hardware root of trust).

**States**:
- `unobserved`: No host agent connected, no DPU observation
- `observed`: DPU can see host via PCIe but no host agent
- `connected`: Host agent connected, reports validated against DPU view
- `conflict`: Host agent reports differ from DPU observations

---

### FirmwareInventory

Firmware packages installed on the host, as reported by host agent.

| Dimension | Attributes |
|-----------|------------|
| **Capabilities** | (none) |
| **Configuration** | (none) |
| **Operational State** | packages[], last_scanned |

---

### Package

A firmware or software package.

| Dimension | Attributes |
|-----------|------------|
| **Capabilities** | (none) |
| **Configuration** | (none) |
| **Operational State** | name, version, vendor, install_date, signature_status |

---

### SecurityPosture

The security state of the host.

| Dimension | Attributes |
|-----------|------------|
| **Capabilities** | (none) |
| **Configuration** | (none) |
| **Operational State** | secure_boot_enabled, tpm_present, tpm_version, disk_encryption, firewall_enabled, selinux_mode |

---

### Rule (Policy)

A Cedar policy rule for access control.

| Dimension | Attributes |
|-----------|------------|
| **Capabilities** | language (cedar) |
| **Configuration** | effect (permit/forbid), principal, action, resource, conditions |
| **Operational State** | last_evaluated, evaluation_count, permit_count, deny_count |

---

### AuditLog

An immutable record of actions taken in the system.

| Dimension | Attributes |
|-----------|------------|
| **Capabilities** | (none, immutable) |
| **Configuration** | (none) |
| **Operational State** | timestamp, actor, action, resource, outcome, details, source_ip |

---

## Credentials

Fabric Console manages multiple credential types for authentication across the infrastructure stack. All credentials follow the principle of reference-by-ID: the actual secret material is stored in a secure vault and referenced by identifier.

### Entity Hierarchy (Credentials)

```
Tenant
│
└── Credential [namespace]
    │
    ├── SSHKeyPair (0:N)                    api(create,read,list,delete,rotate)
    │
    ├── MungeKey (0:N)                      api(create,read,list,delete,distribute)
    │
    ├── TLSCertificate (0:N)                api(create,read,list,delete,renew)
    │
    ├── APIToken (0:N)                      api(create,read,list,revoke)
    │
    └── BMCCredential (0:N)                 api(create,read,list,update,delete)
```

---

### SSHKeyPair

SSH key pairs for secure shell access to hosts and DPUs.

| Dimension | Attributes |
|-----------|------------|
| **Capabilities** | key_type (ed25519/rsa/ecdsa), key_size_bits |
| **Configuration** | name, comment, allowed_principals[], force_command, valid_before, valid_after |
| **Operational State** | fingerprint, created_at, last_used, associated_hosts[], revoked |

**Key Types**:
- `ed25519`: Preferred, fast, small keys
- `ecdsa-sha2-nistp384`: FIPS-compliant environments
- `rsa-sha2-512`: Legacy compatibility (4096-bit minimum)

**Distribution Model**:
- Public keys pushed to authorized_keys on targets via DPU agent
- Private keys never leave secure vault
- Certificate-based SSH supported (signed by tenant CA)

---

### MungeKey

MUNGE (MUNGE Uid 'N' Gid Emporium) keys for HPC cluster authentication.

| Dimension | Attributes |
|-----------|------------|
| **Capabilities** | algorithm (aes-256-cbc), key_size_bits (256) |
| **Configuration** | name, cluster_id, encode_host, decode_hosts[] |
| **Operational State** | created_at, last_rotated, distributed_to[], rotation_due |

**Use Cases**:
- Slurm job authentication between nodes
- MPI process identity verification
- Cross-cluster job submission

**Security Properties**:
- Symmetric key shared across cluster
- Must be identical on all nodes in a cluster
- Time-synchronized (default 120s credential lifetime)

**Distribution Workflow**:
```
FabricConsole                    DPU Agent                     Host
─────────────                    ─────────                     ────
     │                               │                           │
     │── Generate MungeKey ──►      │                           │
     │                               │                           │
     │── Distribute to DPU ────────►│                           │
     │                               │                           │
     │                               │── Inject via PCIe/rshim ─►│
     │                               │                           │
     │                               │── Verify munge -n ───────►│
     │                               │                           │
     │◄── Confirm distribution ──────│                           │
```

---

### TLSCertificate

X.509 certificates for transport security.

| Dimension | Attributes |
|-----------|------------|
| **Capabilities** | key_algorithm (ecdsa-p384/rsa-2048), key_usage[], extended_key_usage[] |
| **Configuration** | common_name, san_dns[], san_ip[], validity_days, issuer_ref |
| **Operational State** | serial_number, not_before, not_after, fingerprint_sha256, revoked, crl_distribution_points[] |

**Certificate Types**:

| Type | Purpose | Issued By |
|------|---------|-----------|
| Agent TLS | DPU agent gRPC server | Tenant CA |
| Host Agent TLS | Host agent gRPC server | Tenant CA |
| Console TLS | Dashboard HTTPS | Public or Tenant CA |
| mTLS Client | Agent-to-console mutual auth | Tenant CA |

**Trust Chain**:
```
NVIDIA Root CA (DICE)           Tenant Root CA
        │                              │
        ▼                              ▼
   DPU Identity                  Tenant Intermediate CA
   (hardware-bound)                     │
                                        ├── Agent TLS Cert
                                        ├── Host Agent TLS Cert
                                        └── mTLS Client Certs
```

---

### APIToken

Bearer tokens for API authentication.

| Dimension | Attributes |
|-----------|------------|
| **Capabilities** | token_type (bearer/jwt), algorithm (HS256/RS256/ES256) |
| **Configuration** | name, scopes[], expires_at, allowed_ips[], rate_limit |
| **Operational State** | token_prefix (first 8 chars for identification), created_at, last_used, revoked |

**Scopes**:
- `dpus:read` / `dpus:write` / `dpus:admin`
- `attestation:read` / `attestation:validate`
- `flows:read` / `flows:write`
- `tenants:read` / `tenants:admin`

**Token Format** (JWT claims):
```json
{
  "sub": "service:dpu-agent-bf3-01",
  "aud": "fabric-console",
  "iat": 1704067200,
  "exp": 1735689600,
  "scope": ["dpus:read", "attestation:read"],
  "tenant_id": "t_abc123"
}
```

---

### BMCCredential

Credentials for Baseboard Management Controller access.

| Dimension | Attributes |
|-----------|------------|
| **Capabilities** | protocol (redfish/ipmi), supported_operations[] |
| **Configuration** | name, bmc_endpoint, username, password_vault_ref |
| **Operational State** | last_verified, connection_status, firmware_version |

**Security Notes**:
- Password stored in external vault (HashiCorp Vault, AWS Secrets Manager)
- Only vault reference stored in FabricConsole database
- IPMI deprecated; Redfish over HTTPS required for new deployments

---

### Attestation-Gated Credential Deployment

Credentials are only deployed to targets that have passed attestation. This ensures secrets never reach compromised or unverified infrastructure.

**Deployment Prerequisites**:

| Target | Required Attestation | Credential Types Unlocked |
|--------|---------------------|---------------------------|
| DPU | DICE chain valid, measurements match | Agent TLS, mTLS Client |
| Host (via DPU) | DPU attested + Host Agent connected | SSHKeyPair, MungeKey |
| Host (direct) | Not allowed | None (must go through DPU) |
| Cluster | All member DPUs attested | MungeKey distribution |

**Trust Flow**:
```
                                    Credential Vault
                                          │
                                          │ (release only if attested)
                                          ▼
┌─────────────────────────────────────────────────────────────────┐
│                        Fabric Console                           │
│                                                                  │
│   ┌──────────────┐      ┌──────────────┐      ┌──────────────┐  │
│   │  Attestation │─────►│   Policy     │─────►│  Credential  │  │
│   │   Verifier   │      │   Engine     │      │  Distributor │  │
│   └──────────────┘      └──────────────┘      └──────────────┘  │
│          ▲                                           │          │
└──────────┼───────────────────────────────────────────┼──────────┘
           │                                           │
           │ DICE/SPDM evidence                        │ encrypted credential
           │                                           │
           │                                           ▼
    ┌──────┴──────┐                            ┌──────────────┐
    │             │                            │              │
    │     DPU     │◄───────────────────────────│   (target)   │
    │             │   only if attestation OK   │              │
    └─────────────┘                            └──────────────┘
```

**Policy Conditions for Credential Release**:
```cedar
// Only release SSH keys to hosts behind attested DPUs
permit(
  principal == FabricConsole::"credential-distributor",
  action == Credential::"deploy",
  resource is SSHKeyPair
) when {
  resource.target.dpu.attestation.status == "verified" &&
  resource.target.dpu.attestation.last_validated > (now() - duration("1h"))
};

// Require fresh attestation for MungeKey distribution
permit(
  principal == FabricConsole::"credential-distributor",
  action == Credential::"deploy",
  resource is MungeKey
) when {
  resource.target_cluster.all_dpus.attestation.status == "verified" &&
  resource.target_cluster.all_dpus.attestation.measurements.all_match == true
};
```

**Revocation on Attestation Failure**:

When a DPU's attestation transitions from `verified` to `failed` or `unknown`:
1. All credentials deployed through that DPU are marked `compromised_risk`
2. Credential distributor initiates rotation for affected credentials
3. Audit log records the attestation-triggered revocation
4. Policy engine blocks new credential deployments until re-attestation

---

### Credential Lifecycle

All credentials follow a standard lifecycle:

```
                ┌──────────┐
    create      │          │     rotate
───────────────►│  Active  │◄──────────────┐
                │          │               │
                └────┬─────┘               │
                     │                     │
         ┌───────────┼───────────┐         │
         │           │           │         │
         ▼           ▼           ▼         │
    ┌─────────┐ ┌─────────┐ ┌─────────┐    │
    │         │ │         │ │         │    │
    │ Expired │ │ Revoked │ │ Rotated │────┘
    │         │ │         │ │         │
    └─────────┘ └─────────┘ └─────────┘
```

**Rotation Policy**:

| Credential Type | Recommended Rotation | Automated |
|-----------------|---------------------|-----------|
| SSHKeyPair | 90 days | Yes |
| MungeKey | 30 days | Yes |
| TLSCertificate | 365 days (or shorter) | Yes |
| APIToken | Never (use short expiry) | No |
| BMCCredential | 90 days | Manual |

---

## IETF RATS Terminology Mapping

Fabric Console follows IETF Remote ATtestation procedureS (RATS) terminology:

| RATS Term | Fabric Console Entity | Description |
|-----------|----------------------|-------------|
| Attester | DPU | Generates evidence (DICE/SPDM certs, measurements) |
| Verifier | FabricConsole | Validates attestation against reference values |
| Relying Party | Operators, Cedar Policies | Consumes attestation results for decisions |
| Endorser | NVIDIA | Provides CoRIM reference values |
| Evidence | Chain, Certificate, Measurement | Cryptographic proof of DPU state |
| Reference Values | ReferenceValue | Known-good measurements from endorser |
| Attestation Result | Result | Validation outcome with claims |

---

## Trust Model

### DPU Authority

The DPU sits between the untrusted host and the trusted network. Its observations are authoritative:

1. **Host claims require DPU validation**: Host agent reports (firmware inventory, security posture) are cross-checked against DPU's PCIe/DOCA observations
2. **Conflict resolution**: When host agent and DPU disagree, DPU's view wins
3. **Independent attestation**: DPU attestation does not depend on host cooperation

### Fail-Secure Defaults

When attestation cannot be verified:

| Condition | Result | Rationale |
|-----------|--------|-----------|
| BMC unreachable | `unknown` | Cannot retrieve certificates |
| CoRIM unavailable | `unknown` | Cannot validate measurements |
| Certificate expired | `failed` | Cryptographic guarantee lost |
| Measurement mismatch | `failed` | Firmware may be compromised |
| No attestation data | `unknown` | Cannot make security decision |

Operators must explicitly accept `unknown` status to proceed with operations.

### No Credential Exposure

Credentials (BMC passwords, API keys) are:
- Never logged
- Never included in error messages
- Never transmitted beyond intended scope
- Referenced by ID, not value, in configuration

---

## Standards Alignment

| Domain | Standard | Application |
|--------|----------|-------------|
| Attestation terminology | IETF RATS | Entity naming, workflow |
| Measurement format | TCG DICE, CoRIM | Certificate chains, reference values |
| Hardware attestation | SPDM 1.2+ | BMC Redfish endpoints |
| Platform security | OCP Cerberus/Caliptra | Future GPU attestation |
| Policy language | Cedar (AWS) | Access control rules |
| Network flows | OpenFlow 1.3+ | OVS integration |

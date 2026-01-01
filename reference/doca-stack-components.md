# DOCA Stack Components for Identity Fabric

> **Document Status**: Living document, updated during exploration session
> **Last Updated**: 2024-12-23
> **BF3 Version**: DOCA 3.2.1 (bf-bundle-3.2.1-34) on Ubuntu 24.04

## Overview

This document maps NVIDIA DOCA stack components to our Identity Fabric use cases. The goal is to understand which components are available, how they work, and how they fit into hardware-enforced Zero Trust authentication for AI infrastructure.

## DOCA Stack Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              APPLICATIONS                                    │
│   Networking    Security    Storage    HPC/AI    Telco    Media             │
└─────────────────────────────────────────────────────────────────────────────┘
┌──────────────────┬──────────────────────────────────────────────────────────┐
│  DOCA SERVICES   │                    DOCA LIBRARIES                        │
│                  │  ┌────────┬─────┬───────────┬────────┬──────────┐       │
│  Orchestration   │  │ FLOW   │ DPI │ App Shield│ HPC/AI │ RiverMax │       │
│  Telemetry       │  │Gateway │     │           │        │          │       │
│  Firefly (PTP)   │  │Firewall│RegEx│  Storage  │  DPA   │Comm Chan │       │
│  SDN/HBN         │  └────────┴─────┴───────────┴────────┴──────────┘       │
│  DPU Management  │                                                          │
└──────────────────┴──────────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────────────────────────┐
│                              DOCA DRIVERS                                    │
│  ┌──────────────┬───────────────┬─────────────┬─────────┬─────────┐        │
│  │  Networking  │   Security    │   Storage   │ UCX/UCC │   P4    │        │
│  │  ASAP²       │  DPDK RegEx   │  SPDK SNAP  │         │         │        │
│  │  DPDK        │  DPDK SFT     │  VirtIO-FS  │  RDMA   │ FlexIO  │        │
│  │  XLIO        │  Inline Crypto│  XTS Crypto │         │         │        │
│  └──────────────┴───────────────┴─────────────┴─────────┴─────────┘        │
└─────────────────────────────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────────────────────────┐
│                    DPU - BlueField and BlueField-X                          │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Lab Environment

### Hardware
- **Model**: BlueField-3 B3210E E-Series FHHL
- **CPU**: 16-core ARM Cortex-A78AE @ 2GHz
- **RAM**: 32 GB DDR5
- **Network**: Dual 100GbE QSFP112 (ConnectX-7)
- **Host**: Workbench PC (Ryzen 9 9950X3D, RTX 5080)

### Software
- **DOCA Version**: 3.2.1025
- **Bundle**: bf-bundle-3.2.1-34_25.11_ubuntu-24.04_64k_prod
- **OVS Version**: 3.2.1005
- **Mode**: EMBEDDED_CPU (ARM runs on DPU)

### Connectivity
- **Tailscale**: `ssh ubuntu@100.106.76.67`
- **BCM Network**: 10.141.0.3
- **Physical Ports**: p0, p1 (QSFP, currently not connected)
- **Host Communication**: Via PCIe representors (pf0hpf, pf1hpf)

---

## Component Deep Dives

### 1. DOCA Flow (CRITICAL for Identity Fabric)

**What it does**: Hardware-accelerated packet processing and flow management. The foundation for building firewall, gateway, and policy enforcement applications.

**Relevance**: This is how we enforce identity-based access control at line rate.

**Capabilities on our BF3**:
```
flow_ct (Connection Tracking): unsupported (in current mode)
ETH RX/TX: supported
Checksum offload: supported
Max packet size: 16384 bytes
```

**Available Samples** (50+):
| Sample | Description | Identity Relevance |
|--------|-------------|-------------------|
| `flow_acl` | Access Control Lists | HIGH - permit/deny by identity |
| `flow_control_pipe` | Control plane flows | HIGH - policy distribution |
| `flow_drop` | Drop rules | HIGH - block unauthorized |
| `flow_switch` | OVS integration | CRITICAL - ASAP² offload |
| `flow_esp` | IPsec flows | MEDIUM - encrypted tunnels |
| `flow_ct_tcp` | TCP connection tracking | HIGH - session state |
| `flow_monitor_meter` | Rate limiting | MEDIUM - DoS protection |

**Sample Location**: `/opt/mellanox/doca/samples/doca_flow/`

### 2. AES-GCM Crypto (CRITICAL for mTLS)

**What it does**: Hardware-accelerated AES-GCM encryption/decryption for TLS offload.

**Capabilities on our BF3**:
```
task_encrypt: supported
task_decrypt: supported
Key sizes: 128-bit, 256-bit
Tag sizes: 96-bit, 128-bit
Max IV length: 12 bytes
Max buffer size: 2 MB
Max concurrent tasks: 65,536
```

**Relevance**: Core to mTLS certificate validation. Can offload TLS handshake crypto from host CPU.

**Sample Location**: `/opt/mellanox/doca/samples/doca_aes_gcm/`

**Identity Fabric Use Case**:
1. Endpoint presents TPM-bound certificate
2. DPU validates certificate using AES-GCM acceleration
3. On success, install OVS flow rule to permit traffic
4. On failure, drop or redirect to remediation

### 3. Comm Channel (HIGH for Host-DPU Messaging)

**What it does**: Message passing between host applications and DPU applications. Enables identity token/context sharing.

**Capabilities on our BF3**:
```
server: supported
client: supported
Max message size: 4,080 bytes
Max queue size: 8,192 messages
Max clients: 512
Max send tasks: 8,192
```

**Relevance**: How we pass identity context (tokens, claims, cert validation results) between host and DPU.

**Sample Location**: `/opt/mellanox/doca/samples/doca_comch/`

**Identity Fabric Use Case**:
1. Host application extracts user identity from request
2. Sends identity token to DPU via Comm Channel
3. DPU validates token, installs corresponding flow rules
4. Returns authorization result to host

### 4. SHA Offload (NOT AVAILABLE)

**Status**: Hardware SHA offload is **unsupported** on B3210E model.

```
sha1: unsupported
sha256: unsupported
sha512: unsupported
```

**Impact**: Certificate fingerprint hashing must be done on ARM cores, not in hardware accelerator. Minor performance impact for our use case.

### 5. OVS with ASAP² (CRITICAL for Policy Enforcement)

**What it does**: Open vSwitch with hardware offload. Flow rules are pushed to ConnectX-7 hardware for line-rate enforcement.

**Current Configuration**:
```
OVS Version: 3.2.1005
hw-offload: true
Bridges: ovsbr1 (port 0), ovsbr2 (port 1)
Offload status: Active (flows show offloaded:yes, dp:tc)
```

**Network Topology**:
```
Physical Port (p0) ──► ovsbr1 ──► Host Representor (pf0hpf) ──► Host (PCIe)
Physical Port (p1) ──► ovsbr2 ──► Host Representor (pf1hpf) ──► Host (PCIe)
```

**Identity Fabric Use Case**:
1. Define OVS flow rules based on identity (source MAC, VLAN, tunnel ID)
2. Rules offloaded to hardware via ASAP²
3. 200 Gbps enforcement with zero ARM CPU involvement
4. Identity changes trigger flow rule updates

### 6. Telemetry (HIGH for Security Visibility)

**What it does**: Metrics collection, export, and analysis. Provides visibility into DPU operations.

**Packages Installed**:
- `doca-sdk-telemetry`
- `doca-sdk-telemetry-exporter`
- `doca-telemetry-utils`

**Relevance**: Security audit trail, policy enforcement metrics, anomaly detection signals.

### 7. PKA Crypto Acceleration

**What it does**: Public Key Acceleration for RSA, ECDSA, ECDH operations.

**Kernel Module**: `mlxbf_pka` (loaded)

**Status**: Module loaded, but sysfs interface not exposed. Need to investigate DOCA API access.

**Relevance**: Certificate signature verification, key exchange acceleration for mTLS.

---

## Components NOT Relevant to Identity Fabric

| Component | Purpose | Why Not Relevant |
|-----------|---------|------------------|
| RiverMax | Media streaming | Not doing video |
| DPA | Data Path Accelerator for HPC | GPU Direct focus |
| Storage drivers | NVMe, VirtIO-FS | Not doing storage |
| Firefly | PTP time sync | Nice to have, not critical |
| Compress | LZ4/Deflate | Not compressing identity data |

---

## Mapping to Identity Fabric Patterns

### Pattern A: mTLS Client Certificate Enforcement

```
┌─────────────┐     ┌──────────────────────────────────────┐     ┌─────────────┐
│   Client    │     │            BlueField-3 DPU            │     │    Host     │
│  (Endpoint  │     │                                      │     │  (GPU       │
│   w/ TPM)   │     │  ┌────────────┐    ┌─────────────┐   │     │  Cluster)   │
│             │─────┼─►│ AES-GCM    │───►│  OVS/ASAP²  │───┼────►│             │
│  Presents   │     │  │ TLS Offload│    │ Flow Rules  │   │     │  Access     │
│  mTLS Cert  │     │  └────────────┘    └─────────────┘   │     │  Granted    │
└─────────────┘     └──────────────────────────────────────┘     └─────────────┘

Components Used:
- AES-GCM: Validate certificate (crypto operations)
- DOCA Flow: Install permit/deny rules
- OVS/ASAP²: Hardware-offloaded enforcement
```

### Pattern B: OVS + Identity for AI Workloads

```
┌─────────────┐     ┌──────────────────────────────────────┐     ┌─────────────┐
│   Model A   │     │            BlueField-3 DPU            │     │   Model B   │
│             │     │                                      │     │             │
│  Identity:  │     │  ┌────────────┐    ┌─────────────┐   │     │  Identity:  │
│  tenant-1   │─────┼─►│ Flow Match │───►│  OVS/ASAP²  │───┼────►│  tenant-1   │
│             │     │  │ on Identity│    │ Enforce     │   │     │             │
│             │     │  └────────────┘    └─────────────┘   │     │             │
└─────────────┘     └──────────────────────────────────────┘     └─────────────┘

Components Used:
- DOCA Flow: Match on identity markers (VLAN, tunnel ID, metadata)
- OVS/ASAP²: Hardware-offloaded flow rules
- Telemetry: Audit model-to-model communication
```

### Pattern C: Host-DPU Identity Context Sharing

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              HOST                                           │
│                                                                             │
│  ┌─────────────────┐          Comm Channel           ┌──────────────────┐  │
│  │  Application    │◄───────────────────────────────►│  DPU Service     │  │
│  │  (Identity      │    - Identity tokens            │  (Flow Control)  │  │
│  │   Extraction)   │    - Auth results               │                  │  │
│  └─────────────────┘    - Policy updates             └──────────────────┘  │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘

Components Used:
- Comm Channel: 4KB messages, 512 clients, bidirectional
- Host: Extract identity from application layer
- DPU: Translate identity to flow rules
```

---

---

## HPC Multi-Tenant Security Gap

### NVIDIA's HPC Positioning

NVIDIA positions BlueField for HPC with explicit multi-tenant security claims:

> "Zero-trust architecture providing secure multi-tenant environments with complete
> resource cleanup and trust re-establishment for new tenants"

**Key HPC features on DPU**:
- MPI/SHMEM offload (DPU progresses comms while GPU computes)
- Performance isolation (multi-tenant with bare-metal perf)
- Storage offloads (checkpointing, NVMe emulation)
- 400 Gbps InfiniBand integration

### The Identity Gap in HPC

| HPC Problem | NVIDIA Provides | Gap We Fill |
|-------------|-----------------|-------------|
| Tenant isolation | Network separation | Identity-based access |
| Trust establishment | Resource cleanup | Cryptographic attestation |
| Job boundaries | Performance isolation | Auth at DPU layer |
| MPI security | Offload/acceleration | Verify MPI participants |

### MPI Authentication Problem

Traditional MPI relies on **SSH keys** for process launching:

```
mpirun -np 4 -host node1,node2,node3,node4 ./my_app
        │
        └── SSHs into each node to spawn processes
```

**Security weaknesses**:
- Passwordless SSH keys distributed to all nodes
- Any user with SSH access can impersonate MPI traffic
- No cryptographic binding between job identity and network flows
- Multi-tenant environments share SSH trust boundaries

**Our opportunity**: Replace SSH-based trust with hardware-bound identity:
- TPM-bound credentials on compute nodes
- DPU verifies identity before allowing MPI traffic
- Job scheduler (Slurm) issues short-lived certs per job
- DPU enforces job-to-node mapping at network layer

### BlueField MPI Offload Architecture

NVIDIA offloads MPI collectives to DPU ARM cores for compute/communication overlap:

```
Host CPU (computation)          BlueField DPU (communication)
┌─────────────────────┐         ┌─────────────────────────────┐
│ App calls           │         │ ARM cores execute           │
│ MPI_Ialltoall()     │────────►│ collective while host       │
│ (returns immediate) │  PCIe   │ continues computing         │
│                     │         │         │                   │
│ ... computation ... │         │         ▼                   │
│                     │         │ ConnectX-7 RDMA to peers    │
└─────────────────────┘         └─────────────────────────────┘
```

**Software stack**: MVAPICH2-DPU or HPC-X MPI → UCX → DOCA SDK → BlueField

**Performance claims**:
- 100% overlap between computation and MPI_Ialltoall
- 21% faster on P3DFFT (real FFT application)
- $18M savings on large supercomputers (NVIDIA claim)

**The security gap**: DPU accelerates MPI but does not authenticate participants.
Any traffic arriving on the wire is trusted and accelerated. A compromised node
can inject, read, or forge MPI messages and the DPU will happily process them.

**Our value-add**: Authenticate MPI participants at the DPU before allowing
communication. NVIDIA makes MPI faster; we make MPI secure.

### Strategic Implication

HPC is moving from single-tenant (university cluster) to multi-tenant (AI cloud).
CoreWeave, Lambda Labs, Together AI all run multi-tenant GPU infrastructure.

They need identity verification, not just network isolation.

---

## Next Steps for Exploration

1. **[ ] Run AES-GCM sample** - Test crypto acceleration performance
2. **[ ] Build simple Flow ACL** - Permit/deny based on MAC address
3. **[ ] Test Comm Channel** - Host-to-DPU message passing
4. **[ ] Investigate PKA** - How to access public key acceleration
5. **[ ] Connect physical ports** - Test with real traffic through DPU
6. **[ ] DICE attestation** - Verify DPU identity chain

---

## References

- [DOCA Documentation](https://docs.nvidia.com/doca/)
- [DOCA Flow Programming Guide](https://docs.nvidia.com/doca/sdk/doca+flow/index.html)
- [BlueField Cryptographic Primitives](../docs/bluefield-cryptographic-primitives.md)
- [Project CLAUDE.md](../CLAUDE.md)

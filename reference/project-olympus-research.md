# OCP Project Olympus Research

**Date**: December 2025
**Author**: Claude (research for Fabric Console)
**Purpose**: Document intersections between OCP Project Olympus specifications and Fabric Console DPU management

---

## What is Project Olympus?

Project Olympus is Microsoft's next-generation cloud hardware design contributed to the Open Compute Project (OCP). Announced in November 2016 and fully open-sourced in November 2017, it represents a modular, open-source server architecture that powers Azure's hyperscale cloud infrastructure across 100+ datacenters worldwide.

**Key Contribution**: Microsoft open-sourced the complete design under the OWFa1.0 license, making it the de facto open-compute standard for cloud workloads.

**GitHub Repository**: [https://github.com/opencomputeproject/Project_Olympus](https://github.com/opencomputeproject/Project_Olympus)

---

## Hardware Components

| Component | Description |
|-----------|-------------|
| Universal Motherboard | Computational element supporting multiple processor families (Intel Xeon, AMD EPYC) |
| 1U/2U Server Chassis | Standardized enclosures with mix-and-match motherboard support |
| Power Supply Unit | Battery-backed 12V PSU with integrated management |
| Rack Manager Card | Rack-level management and monitoring |
| Universal PDU | Integrated A/C power distribution |
| PCIe Riser Boards | Expansion for GPUs, NICs, NVMe storage |
| FPGA Card | Full-height half-length x16 PCIe FPGA support |

### GPU/Accelerator Support (HGX)

The Project Olympus ecosystem includes HGX (Hyperscale GPU Accelerator), originally HGX-1 supporting 8 NVIDIA GPUs with NVLink interconnects. NVIDIA contributed the HGX-H100 baseboard physical specification to OCP's Open Accelerator Infrastructure (OAI) sub-project.

**HGX Specifications**:
- 8-GPU baseboard design with high-speed intra-GPU interconnects
- NVLink 5 (1.8 TB/s in latest HGX B300)
- 800 Gb/s InfiniBand and Ethernet via ConnectX/BlueField
- AMC (Accelerator Management Controller) with Redfish interface
- MCTP/PLDM/SPDM support for out-of-band management

---

## Software and Firmware Components

| Component | Purpose |
|-----------|---------|
| BMC Firmware | OpenBMC-based baseboard management |
| System BIOS/UEFI | Secure boot, platform initialization |
| Rack Manager Software | Centralized rack management |
| RESTful API | Redfish-based management interfaces |

### OpenBMC

OpenBMC is the reference BMC implementation for Project Olympus. Founding members include Microsoft, Intel, IBM, Google, and Facebook.

**Key Capabilities**:
- Full Redfish 1.0+ specification support
- Hardware security implementations (HRoT, Image Signing)
- Secure Boot enforcement
- Firmware update management
- OCP base server profile compliance

---

## Security Specifications

This section covers OCP security initiatives directly relevant to Fabric Console.

### Project Cerberus

**What It Is**: NIST 800-193 compliant hardware root of trust designed by Microsoft, contributed to OCP in 2017.

**Purpose**: Provides robust firmware integrity verification for motherboard components (UEFI BIOS, BMC, Option ROMs) and peripheral I/O devices.

**Key Features**:
- Hardware-based identity that cannot be cloned
- Firmware integrity enforcement
- Malware persistence prevention in BMC
- Access control and integrity verification for platform firmware

**Relationship to NVIDIA IRoT**: BlueField's IRoT (Initial Root of Trust) serves a similar purpose. Project Cerberus targets x86 server platforms; BlueField IRoT targets ARM-based DPU platforms. Both establish trust anchors for firmware attestation.

### Caliptra

**What It Is**: Open-source silicon root of trust (RoT) specification from AMD, Google, Microsoft, and NVIDIA, hosted under CHIPS Alliance.

**Purpose**: Defines core RoT capabilities for any SoC or ASIC in cloud infrastructure.

**Key Capabilities**:
- RTM (Root of Trust for Measurement) block for SoC integration
- Device identity via DICE-derived keys
- Measured boot and attestation
- Quantum-resilient cryptography (Caliptra 2.1)
- Hardware-based key management

**Adoption**: Committed intercept for Google and Microsoft first-party cloud silicon, and AMD server silicon products.

**Relevance**: Caliptra represents the future direction of hardware root of trust. BlueField's IRoT/DICE implementation aligns conceptually with Caliptra's goals, though Caliptra targets integration at the silicon RTL level.

### OCP Attestation Specifications

**Document**: "Attestation of System Components v1.0" (November 2020)

**Framework**:
- Defines attester, verifier, and reference integrity measurement roles (aligned with IETF RATS terminology)
- Platform RoT can reside in BMC, dedicated device, or trusted environment
- Non-hierarchical attestation model (attesters don't include other attesters)
- Attested devices may act as bridges, relaying communication between attester and verifier

**Implementation on BlueField**:
- BMC acts as the platform's attestation bridge
- DPU IRoT and ERoT are attestation targets
- Redfish API exposes SPDM attestation interface

### OCP S.A.F.E. Program

**What It Is**: Security Appraisal Framework and Enablement program launched October 2023.

**Purpose**: Independent security reviews of firmware implementations.

**Outputs**:
- Cryptographically signed Short Form Reports (SFR)
- Published in OCP GitHub with firmware hashes and security issue status
- Approved Security Review Providers: Atredis Partners, IOActive, NCC Group, Keysight Riscure, Trail of Bits, others

**Relevance**: If Fabric Console validates firmware measurements against reference values, S.A.F.E. reviewed firmware provides an additional trust signal.

---

## Protocol Standards

### SPDM (Security Protocol and Data Model)

**Standard Body**: DMTF

**Purpose**: Secure communication between device entities for hardware/firmware identification, authentication, and attestation.

**Version**: SPDM v1.1 implemented in BlueField-3, ConnectX-8, ConnectX-7

**Capabilities**:
- Hardware and firmware measurement collection
- Certificate-based authentication
- Measurement attestation with signed responses
- Similar to TLS but optimized for device-to-device communication

### MCTP (Management Component Transport Protocol)

**Standard Body**: DMTF

**Purpose**: Transport protocol for management traffic between BMC and devices.

**Bindings**:
- MCTP over PCIe (for GPU/accelerator management)
- MCTP over SMBus/I2C (for legacy support)

### PLDM (Platform Level Data Model)

**Standard Body**: DMTF

**Key Types for Fabric Console**:
- DSP0267 (Type 5): Firmware update
- DSP0248: Monitoring and control
- PLDM for FRU: Hardware inventory

**Relevance**: PLDM provides standardized firmware management and inventory collection, which aligns with Fabric Console's host introspection and firmware inventory features.

### Redfish

**Standard Body**: DMTF

**Purpose**: RESTful API for hardware management, designed as secure IPMI-over-LAN replacement.

**OCP Integration**:
- OpenBMC fully implements Redfish
- GPU/accelerator management via AMC Redfish interface
- SPDM attestation exposed via Redfish endpoints
- OCP base server profile defines minimum required resources

---

## GPU and Accelerator Management

### OCP GPU & Accelerator Management Interfaces (v1.1)

**Purpose**: Standardized management profiles for GPUs to reduce integration work for CSPs.

**Architecture**:

```
┌─────────────────────────────────────┐
│          System BMC                 │
│   (Manages platform + accelerators) │
└──────────────────┬──────────────────┘
                   │
        ┌──────────┴──────────┐
        │                     │
   High-Speed Net         I2C/I3C OOB
   (Redfish API)          (MCTP/PLDM/SPDM)
        │                     │
        ▼                     ▼
┌───────────────────────────────────────┐
│     Universal Baseboard (UBB)          │
│  ┌─────────────────────────────────┐  │
│  │   AMC (Accelerator Mgmt Ctrl)   │  │
│  │   - Redfish interface           │  │
│  │   - MCTP/PLDM/SPDM support      │  │
│  └─────────────────────────────────┘  │
│  ┌─────┐ ┌─────┐ ┌─────┐ ┌─────┐    │
│  │GPU 0│ │GPU 1│ │GPU 2│ │ ... │    │
│  └─────┘ └─────┘ └─────┘ └─────┘    │
└───────────────────────────────────────┘
```

**Key Points**:
- UBB (Universal Base Board) must expose Redfish interface
- SPDM attestation managed by hyperscaler BMC
- Low-level attestation through AMC Redfish
- GPU devices without Redfish use PLDM over MCTP

### OCP DPU Management

**Specification**: OCP NIC 3.0 includes optional MCTP over PCIe

**Management Methods**:
| Method | Purpose |
|--------|---------|
| NIC Management | Traditional NIC control |
| NC-SI | Network Controller Sideband Interface |
| PLDM for FW Update | Standardized firmware management |
| PLDM for Monitoring | Telemetry and health |
| RDE | Redfish Device Enablement |
| Redfish Host Interface | In-band management |
| SPDM | Security and attestation |

---

## Intersections with Fabric Console

This section maps OCP specifications to Fabric Console requirements.

### 1. SPDM Attestation (Direct Alignment)

**OCP Specification**: Attestation of System Components v1.0, SPDM v1.1
**Fabric Console Feature**: DICE/SPDM certificate retrieval and validation

**Current Implementation**:
- Fabric Console retrieves DICE chains from BlueField BMC via Redfish
- Certificates display IRoT and ERoT attestation targets
- Phase 2 plans CoRIM validation of measurements

**OCP Alignment Opportunity**:
- Adopt IETF RATS terminology (attester, verifier, reference value provider)
- Implement OCP attestation workflow patterns
- Consider SPDM direct communication (beyond Redfish wrapper)

### 2. CoRIM Reference Measurements (Direct Alignment)

**OCP Specification**: Relies on IETF RATS CoRIM/CoMID
**NVIDIA Implementation**: Publishes CoRIM files for BlueField firmware

**Fabric Console Feature**: Attestation validation (Phase 2)

**Current Implementation**:
- CoRIM parsing implemented in `pkg/attestation/corim.go`
- Validates measurements against reference values from NVIDIA

**OCP Alignment Opportunity**:
- Follow OCP remediation guidance when validation fails
- Implement firmware update workflow for failed devices
- Track S.A.F.E. reviewed firmware status

### 3. Redfish API (Direct Alignment)

**OCP Specification**: OCP Base Server Profile, Redfish standard
**Fabric Console Feature**: BMC communication for attestation

**Current Implementation**:
- Fabric Console's DPU agent queries BMC Redfish for attestation
- Uses NVIDIA-specific Oem/Nvidia endpoints

**OCP Alignment Opportunity**:
- Abstract Redfish client for vendor-neutral base + vendor extensions
- Support OCP base server profile resources (Chassis, Systems, Managers)
- Leverage Redfish for host introspection via BMC (in addition to DPU agent)

### 4. Hardware Root of Trust (Conceptual Alignment)

**OCP Specifications**: Project Cerberus, Caliptra
**NVIDIA Implementation**: BlueField IRoT (Platform Security Controller)

**Fabric Console Feature**: Trust anchor for DPU attestation

**Analysis**:
- Cerberus targets x86 server platforms; BlueField has equivalent IRoT
- Caliptra targets silicon-level integration; BlueField IRoT is device-specific
- All three establish unforgeable device identity and measured boot

**Alignment Opportunity**:
- Reference OCP security specs when documenting Fabric Console trust model
- Track Caliptra adoption in future NVIDIA silicon
- Consider attestation workflow that could work across Cerberus and IRoT platforms

### 5. GPU/Accelerator Management (Opportunity)

**OCP Specification**: OCP GPU & Accelerator Management Interfaces v1.1
**Fabric Console Feature**: Host introspection (Phase 2), GPU status

**Current Status**: Fabric Console focuses on DPU, not GPU management

**Alignment Opportunity**:
- Use PLDM/MCTP for GPU inventory collection via DPU
- Implement OCP-compliant GPU monitoring through AMC interface
- Extend attestation to cover GPU firmware (via UBB attestation)
- Align with OCP firmware update specification for GPU updates

### 6. OpenBMC (Indirect Alignment)

**OCP Specification**: OpenBMC reference implementation
**BlueField Status**: BlueField BMC is proprietary but Redfish-compliant

**Fabric Console Impact**:
- OpenBMC adoption would provide standardized BMC management
- Current Redfish abstraction should work with OpenBMC platforms
- Consider OpenBMC as target for non-NVIDIA DPU support

### 7. OCP L.O.C.K. (Future Consideration)

**Status**: Presented January 2025, September 2025 at OCP Security
**Purpose**: Hardware and crypto security framework

**Relevance**: Track for potential alignment with Fabric Console security architecture.

---

## Integration Opportunities

### Short-Term (Phase 2)

1. **Adopt RATS Terminology**
   - Rename internal concepts to match IETF RATS: attester (DPU), verifier (Fabric Console), endorser (NVIDIA)
   - Update documentation to reference OCP attestation spec

2. **CoRIM Validation Enhancement**
   - Verify CoRIM format aligns with IETF draft-ietf-rats-corim
   - Add support for vendor-signed CoRIM files
   - Implement measurement comparison per OCP guidance

3. **Redfish Abstraction Layer**
   - Create vendor-neutral Redfish client interface
   - Implement NVIDIA-specific adapter
   - Prepare for future vendor support

### Medium-Term (Phase 3)

4. **SPDM Direct Protocol Support**
   - Consider direct SPDM over MCTP (bypassing Redfish wrapper)
   - Enables lower-latency attestation operations
   - Aligns with OCP device attestation patterns

5. **GPU Attestation Integration**
   - Extend attestation to cover NVIDIA GPU firmware
   - Use OCP GPU management interface for inventory
   - Support UBB (Universal Base Board) attestation if HGX systems are managed

6. **Cross-Platform Trust Model**
   - Document how Fabric Console trust model maps to Cerberus and Caliptra
   - Prepare for attestation of non-NVIDIA devices that implement these specs

### Long-Term (Post-GTC)

7. **OpenBMC Support**
   - Enable management of OpenBMC-based servers
   - Leverage OCP base server profile for standardized resources
   - Extend Fabric Console beyond DPU-only management

8. **S.A.F.E. Integration**
   - Query OCP S.A.F.E. database for firmware security status
   - Display S.A.F.E. review status in attestation UI
   - Alert on firmware not covered by S.A.F.E. reviews

---

## Key OCP Resources

### Specifications

| Document | URL | Relevance |
|----------|-----|-----------|
| Attestation v1.0 | [OCP Documents](https://www.opencompute.org/documents/attestation-v1-0-20201104-pdf) | Core attestation framework |
| GPU Management v1.1 | [OCP Documents](https://www.opencompute.org/documents/ocp-gpu-accelerator-management-interfaces-v1-1-pdf) | Accelerator management patterns |
| Caliptra Spec | [OCP Documents](https://www.opencompute.org/documents/caliptra-silicon-rot-services-09012022-pdf) | Silicon RoT reference |
| Secure Firmware Recovery | [OCP Documents](https://www.opencompute.org/documents/ocp-recovery-document-1p1-final-pdf) | Firmware remediation |

### GitHub Repositories

| Repository | URL | Content |
|------------|-----|---------|
| Project_Olympus | [GitHub](https://github.com/opencomputeproject/Project_Olympus) | Hardware specifications |
| Security | [GitHub](https://github.com/opencomputeproject/Security) | Security project specs |
| OCP-Security-SAFE | [GitHub](https://github.com/opencomputeproject/OCP-Security-SAFE) | S.A.F.E. program documentation |
| Caliptra | [GitHub](https://github.com/chipsalliance/Caliptra) | Silicon RoT RTL and firmware |

### Related Standards

| Standard | Body | Document |
|----------|------|----------|
| SPDM | DMTF | DSP0274 |
| Redfish | DMTF | DSP0266 |
| MCTP | DMTF | DSP0236 |
| PLDM | DMTF | DSP0240 (base), DSP0267 (FW update) |
| CoRIM | IETF | draft-ietf-rats-corim |

---

## Summary

Project Olympus and the broader OCP security ecosystem provide a standardized foundation that aligns well with Fabric Console's goals:

**Direct Alignment**:
- SPDM attestation protocol (already implemented)
- CoRIM reference measurements (Phase 2 validation)
- Redfish API for BMC communication (core transport)

**Conceptual Alignment**:
- Hardware root of trust model (IRoT maps to Cerberus/Caliptra concepts)
- Attestation workflow patterns (RATS terminology and roles)

**Expansion Opportunities**:
- GPU/accelerator management via OCP interfaces
- Cross-platform attestation for non-NVIDIA hardware
- S.A.F.E. firmware security tracking

Adopting OCP terminology and patterns strengthens Fabric Console's position as an enterprise-ready DPU management tool that integrates with industry-standard security practices. The GTC demo should reference OCP alignment to demonstrate commitment to open standards.

---

## Sources

- [Microsoft Project Olympus on OCP](https://www.opencompute.org/blog/microsoft-project-olympus-specifications-and-designs-are-now-available-on-the-ocp-marketplace)
- [Project Olympus Wiki](https://www.opencompute.org/wiki/Server/ProjectOlympus)
- [Project Cerberus Documentation](https://learn.microsoft.com/en-us/azure/security/fundamentals/project-cerberus)
- [Caliptra on CHIPS Alliance](https://github.com/chipsalliance/Caliptra)
- [NVIDIA Device Attestation](https://docs.nvidia.com/networking/display/dpunicattestation)
- [DPU BMC SPDM Attestation](https://docs.nvidia.com/networking/display/bluefieldbmcv2507/dpu+bmc+spdm+attestation+via+redfish)
- [OCP Security Wiki](https://www.opencompute.org/wiki/Security)
- [OCP GPU Management Interfaces](https://www.opencompute.org/documents/ocp-gpu-accelerator-management-interfaces-v1-1-pdf)
- [OCP Hardware Management](https://www.opencompute.org/wiki/Hardware_Management/SpecsAndDesigns)

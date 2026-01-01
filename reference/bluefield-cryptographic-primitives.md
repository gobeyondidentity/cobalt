# Bluefield Cryptographic Primitives Reference

**Last Updated**: December 2025
**Purpose**: Technical reference for Bluefield DPU security capabilities

---

## Key Distinction: Bluefield vs TPM

**IMPORTANT**: NVIDIA Bluefield DPUs do NOT use TPM (Trusted Platform Module). They have their own ARM-based cryptographic architecture with distinct technologies.

| Technology | Where It Lives | Standard | Purpose |
|------------|---------------|----------|---------|
| **TPM** | Endpoint devices (laptops, workstations) | TCG TPM 2.0 | User/device credential storage |
| **DICE/SPDM** | Bluefield DPU | TCG DICE, DMTF SPDM | DPU attestation and identity |
| **PKA** | Bluefield DPU | Proprietary (NVIDIA) | Crypto acceleration |
| **IRoT** | Bluefield DPU | NVIDIA | Hardware root of trust |

---

## Bluefield Security Architecture

### Root of Trust Hierarchy

```
┌─────────────────────────────────────────────────────────┐
│                    IRoT (Internal Root of Trust)        │
│           Platform Security Controller                   │
│           Stores measurements, anchors secure boot       │
└─────────────────────────┬───────────────────────────────┘
                          │
┌─────────────────────────▼───────────────────────────────┐
│                    DICE Certificate Chain                │
│           L5, L6 certs with TCG_DICE_FWID               │
│           SHA2-384 hashes of firmware                    │
└─────────────────────────┬───────────────────────────────┘
                          │
┌─────────────────────────▼───────────────────────────────┐
│                    SPDM v1.1 Attestation                 │
│           Remote verification of DPU state              │
│           GET_CERTIFICATE, GET_MEASUREMENTS             │
└─────────────────────────┬───────────────────────────────┘
                          │
┌─────────────────────────▼───────────────────────────────┐
│                    PKA Crypto Operations                 │
│           RSA, ECDSA signing/verification               │
│           TLS offload, IPsec acceleration               │
└─────────────────────────────────────────────────────────┘
```

---

## DICE (Device Identifier Composition Engine)

### Overview
- **Standard**: TCG Implicit Identity-Based Device Attestation v1.0, Rev 0.93
- **Purpose**: Hardware-based cryptographic device identity and attestation
- **Implementation**: BlueField-3 specific

### Certificate Chain
The complete certificate chain is returned via SPDM GET_CERTIFICATE command and stored in SPDM certificate slot 0.

**Key Certificates**:
- **L5, L6**: Contain evidence as X.509 certificate extensions
- **OID**: `2.23.133.5.4.1` (TCG-DICE-FWID)

### Firmware Identity (FWID)

| Field | Algorithm | Contents |
|-------|-----------|----------|
| `TCG_DICE_FWID-0` | SHA2-384 | Hash of hardware configuration + first mutable firmware |
| `TCG_DICE_FWID-1` | SHA2-384 | Hash of runtime firmware code |

### Use Cases
- Prove DPU identity cryptographically
- Verify firmware integrity before trust
- Enable remote attestation workflows

---

## SPDM v1.1 (Security Protocol and Data Model)

### Overview
- **Standard**: DMTF SPDM 1.1 (OCP-aligned)
- **Transport**: MCTP (Management Component Transport Protocol)
- **Access**: Redfish API for remote attestation

### Attestation Targets

| Target | Description | What It Attests |
|--------|-------------|-----------------|
| `Bluefield_DPU_IRoT` | BlueField Internal Root of Trust | Platform Security Controller measurements |
| `Bluefield_ERoT` | BlueField BMC External Root of Trust | DPU BMC measurements |

### Key SPDM Commands

| Command | Purpose |
|---------|---------|
| `GET_VERSION` | Negotiate SPDM version |
| `GET_CAPABILITIES` | Query device capabilities |
| `GET_CERTIFICATE` | Retrieve DICE certificate chain |
| `GET_MEASUREMENTS` | Get runtime measurements |
| `CHALLENGE` | Authenticate device |

### Verification Flow
```
1. Verifier → DPU: GET_CERTIFICATE
2. DPU → Verifier: Certificate chain (L5, L6 with DICE FWIDs)
3. Verifier: Validate chain against NVIDIA CA
4. Verifier: Compare FWIDs against reference measurements (CoRIM)
5. Verifier → DPU: CHALLENGE (with nonce)
6. DPU → Verifier: Signed response
7. Verifier: Validate signature, trust established
```

---

## IRoT (Internal Root of Trust)

### Overview
- **Component**: Platform Security Controller (PSC)
- **Function**: Hardware root of trust for secure boot chain
- **Access**: Via SPDM attestation target `Bluefield_DPU_IRoT`

### Capabilities
- Stores boot measurements
- Anchors secure boot chain
- Provides cryptographic identity for DICE
- Cannot be modified by software

### Secure Boot Chain
```
IRoT (immutable) → Boot ROM → Primary Bootloader →
    Secondary Bootloader → Arm Trusted Firmware →
        Linux Kernel → User Space
```

Each stage measures the next before execution, creating a chain of trust.

---

## ERoT (External Root of Trust)

### Overview
- **Component**: BMC (Baseboard Management Controller)
- **Function**: Out-of-band attestation of DPU BMC
- **Access**: Via SPDM attestation target `Bluefield_ERoT`

### Measurements
- BMC firmware integrity
- BMC configuration state
- Management interface state

---

## PKA (Public Key Accelerator)

### Overview
- **Type**: Hardware cryptographic engine
- **Interface**: OpenSSL engine (`-engine pka`)
- **Location**: On-die crypto accelerator in Bluefield SoC

### Supported Operations

| Operation | Algorithms |
|-----------|------------|
| Signing | RSA (2048, 3072, 4096), ECDSA (P-256, P-384) |
| Verification | RSA, ECDSA |
| Key Generation | RSA, ECC |

### OpenSSL Integration

**Sign a file**:
```bash
openssl dgst -engine pka -sha256 -sign <privatekey> -out <signature> <filename>
```

**Verify a signature**:
```bash
openssl dgst -engine pka -sha256 -verify <publickey> -signature <signature> <filename>
```

### Performance
- Hardware acceleration: Line-rate crypto operations
- Offloads CPU: ARM cores free for other tasks
- Integrated with TLS offload engine

---

## Crypto Acceleration

### TLS Offload (kTLS)
- **Function**: Kernel TLS encryption/decryption in hardware
- **Verification**: `flint -d /dev/mst/<device> dc | grep Crypto`
- **Output**: `Crypto Enabled` indicates hardware support

### IPsec Acceleration
- **Function**: ESP encryption/decryption in hardware
- **Verification**: `dmesg | grep "mlx5e: IPSec ESP acceleration enabled"`

### SHA Offload
- **Function**: Hash computation in hardware
- **Interface**: DOCA SHA offload engine for OpenSSL

### AES-XTS
- **Function**: Storage encryption
- **Use case**: SPDK crypto for NVMe-oF

---

## Reference Measurements (CoRIM)

### Overview
- **Standard**: CoRIM/CoMID model for reference measurements
- **Source**: NVIDIA RIM service
- **Availability**: BlueField-3 CoRIM files expected April 2025

### Verification Workflow
1. Obtain CoRIM from NVIDIA RIM service
2. Retrieve measurements from DPU via SPDM
3. Compare measurements against CoRIM reference
4. Trust decision based on match/mismatch

---

## BlueField-4 Preview (Announced October 2025)

### Security Enhancements
- **ASTRA**: Advanced Secure Trusted Resource Architecture
- Zero-trust tenant isolation
- Secure boot with hardware root of trust
- Encrypted firmware updates
- Device attestation via SPDM 1.1

### Specifications
- 800 Gbps network throughput
- 64 ARM Neoverse V2 cores
- PCIe Gen 6 x16 host interface
- 128 GB LPDDR5 memory

### Timeline
- Early access: 2026 (part of NVIDIA Vera Rubin AI systems)

---

## Integration with Beyond Identity

### Two-Domain Trust Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                     ENDPOINT DEVICE                          │
│  ┌────────────────────────────────────────────────────────┐  │
│  │  Beyond Identity Authenticator                         │  │
│  │  ┌──────────────┐                                      │  │
│  │  │     TPM      │  ← Device-bound passkey storage      │  │
│  │  │  (TPM 2.0)   │  ← Private key never leaves TPM      │  │
│  │  └──────────────┘                                      │  │
│  └────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────┘
                              │
                              │ mTLS certificate (signed by TPM)
                              ▼
┌──────────────────────────────────────────────────────────────┐
│                     BLUEFIELD DPU                            │
│  ┌────────────────────────────────────────────────────────┐  │
│  │  Bluefield Authenticator (our code)                    │  │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │  │
│  │  │     IRoT     │  │     PKA      │  │  DICE/SPDM   │  │  │
│  │  │  (Sec Boot)  │  │  (Crypto)    │  │ (Attestation)│  │  │
│  │  └──────────────┘  └──────────────┘  └──────────────┘  │  │
│  │         │                │                  │          │  │
│  │         └────────────────┴──────────────────┘          │  │
│  │                          │                             │  │
│  │                    TLS Validation                      │  │
│  │                    Policy Enforcement                  │  │
│  │                    OVS Flow Rules                      │  │
│  └────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────┘
                              │
                              ▼
                      GPU Cluster Access
```

### Trust Chain
1. **User authenticates** with Beyond Identity passkey (TPM-bound)
2. **Certificate issued** by Beyond Identity, signed by TPM
3. **DPU validates certificate** using PKA crypto acceleration
4. **DPU attested** via DICE/SPDM (can prove its identity)
5. **Policy enforced** at line rate through OVS flow rules
6. **Access granted** to GPU cluster

### Value Proposition
> **Endpoint TPM-bound passkeys** (Beyond Identity) + **DICE-attested DPU enforcement** (Bluefield) = End-to-end hardware trust chain from user device to GPU cluster.

---

## References

### NVIDIA Documentation
- [NVIDIA Device Attestation](https://docs.nvidia.com/networking/display/dpunicattestation)
- [BlueField-3 Certificates](https://docs.nvidia.com/networking/display/nvidiadeviceattestationandcorimbasedreferencemeasurementsharingv20/bluefield-3+certificates)
- [DPU BMC SPDM Attestation](https://docs.nvidia.com/networking/display/bluefieldbmcv2507/dpu+bmc+spdm+attestation+via+redfish)
- [DOCA Crypto Acceleration](https://docs.nvidia.com/doca/sdk/doca+crypto+acceleration/index.html)

### Standards
- [TCG DICE Architecture](https://trustedcomputinggroup.org/work-groups/dice-architectures/)
- [DMTF SPDM Specification](https://www.dmtf.org/standards/spdm)
- [OCP Security Guidelines](https://www.opencompute.org/wiki/Security)

### Beyond Identity
- [Developer Documentation](https://developer.beyondidentity.com/)
- [Passkey Architecture](https://www.beyondidentity.com/resources/universal-passkeys)

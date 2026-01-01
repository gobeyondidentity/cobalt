# NVIDIA CoRIM and SPDM Measurement Research

## DICE Certificate Chains: ERoT vs IRoT

BlueField-3 DPUs expose **two independent attestation chains**, both terminating at the same NVIDIA Device Identity CA root:

### IRoT (Internal Root of Trust)

The Platform Security Controller (PSC) embedded in the BlueField ARM cores. This is the **primary attestation chain** for the DPU itself.

**6-Layer DICE Hierarchy:**
```
L0: NVIDIA Device Identity CA (root)
L1: NVIDIA BF3 Identity
L2: Provisioner CA
L3: Internal ROT A0 PSC ROM
L4: Internal ROT A0 PSC FMC CA
L5: Internal ROT A0 PSC FMC LF (leaf)
```

The hierarchy reflects boot stages: ROM → First Mutable Code CA → First Mutable Code Leaf. Each layer measures and certifies the next, creating a chain of trust from silicon to runtime.

**Redfish Endpoint:** `/redfish/v1/ComponentIntegrity/Bluefield_DPU_IRoT`

### ERoT (External Root of Trust)

The BMC controller (Microchip CEC173x). Provides **out-of-band attestation** accessible even when the DPU host is powered off or unresponsive.

**5-Layer DICE Hierarchy:**
```
L0: NVIDIA Device Identity CA (root)
L1: NVIDIA ERoT Identity
L2: Microchip Product CA
L3: CEC173x FMC CA
L4: CEC173x Runtime (leaf)
```

The chain includes Microchip's product CA since they manufacture the BMC silicon. This enables verification that the BMC firmware is authentic Microchip code running on genuine hardware.

**Redfish Endpoint:** `/redfish/v1/ComponentIntegrity/Bluefield_ERoT`

### Why Two Chains?

| Aspect | IRoT | ERoT |
|--------|------|------|
| **What it attests** | DPU ARM cores, PSC firmware, runtime | BMC controller, out-of-band management |
| **Availability** | Requires DPU powered on | Always available (BMC has standby power) |
| **Trust anchor** | NVIDIA Device Identity CA | NVIDIA Device Identity CA |
| **Silicon vendor** | NVIDIA (BlueField SoC) | Microchip (CEC173x) |
| **Use case** | Runtime attestation, workload isolation | Remote attestation, pre-boot verification |

Both chains allow **unified trust anchoring** since they share the same NVIDIA root CA. A verifier can validate either chain against the same trust store.

---

## Executive Summary

NVIDIA provides a comprehensive attestation framework for BlueField-3 DPUs using SPDM v1.1 protocol with DICE certificate chains. Golden measurements are published via the **NVIDIA RIM Service** in **CBOR-encoded CoRIM format** following the draft-ietf-rats-corim-06 specification.

## 1. Where Are NVIDIA Golden Measurements Published?

### Primary Source: NVIDIA RIM Service

**API Endpoints:**
```
Base URL: https://rim.attestation.nvidia.com/v1/rim/

GET /ids          - List all available RIM identifiers
GET /{ID}         - Retrieve specific CoRIM file by ID
```

**Query Example:**
```bash
curl -X GET "https://rim.attestation.nvidia.com/v1/rim/ids" -H 'accept: application/json'
```

**Response Fields:**
- `id`: RIM identifier (format: `NV_NIC_FIRMWARE_<ASIC>_<version>_<SKU>`)
- `rim`: Base64-encoded CoRIM file
- `sha256`: Integrity verification hash
- `last_updated`: Timestamp of latest modification

**Authentication:** No API key or registration required (public access).

### BlueField-3 Availability

**Status (December 2025):** BlueField-3 CoRIMs are **documented but NOT YET PUBLISHED** to the NVIDIA RIM service. The official documentation states "Support will be available in a future release."

**What's available now:**
- ConnectX-7 NIC firmware (CX7) - multiple versions
- GPU drivers (GH100, GB100, GB202)
- GPU VBIOS
- Switch BIOS

**What's missing:**
- BlueField-3 DPU firmware (no `NV_NIC_FIRMWARE_BF3_*` entries)
- BlueField-2 DPU firmware

The measurement specification and DICE certificate chains are fully functional on BF3 hardware. Only the golden reference values (CoRIMs) for validation are pending publication.

### CoRIM Files NOT Bundled with BFB

The DPU filesystem search found no local CoRIM or manifest files under `/opt`. Reference measurements must be retrieved from the NVIDIA RIM service at runtime.

## 2. What Format Are They In?

### CBOR-Encoded CoRIM (RFC 9393 Draft)

NVIDIA implements **draft-ietf-rats-corim-06** (Concise Reference Integrity Manifest).

**CDDL Structure:**
```
corim = #6.500 (corim-type-choice)
$corim-type-choice /= #6.501 (corim-map)      ; unsigned
$corim-type-choice /= #6.502 (signed-corim)   ; signed with COSE
```

**Key Characteristics:**
- **Encoding:** CBOR (Concise Binary Object Representation)
- **Signing:** COSE (CBOR Object Signing and Encryption) per RFC 8152
- **Nesting:** CoRIM contains one or more CoMIDs
- **Metadata:** Signer identification in protected header (`{"signer": {"name": "NVIDIA"}}`)

### Processing NVIDIA CoRIM Files

NVIDIA CoRIM files begin with an IANA tag. To use with standard Veraison `cocli` tool, strip the first 6 bytes:

```bash
# Install compatible cocli version
go install github.com/veraison/cocli@v0.0.1-compat

# Strip IANA tag and process
dd if=nvidia.corim bs=1 skip=6 of=stripped.corim
cocli comid display -f stripped.corim
```

## 3. What Measurements Are Included?

### BlueField-3 Measurement Indices (Version 1.0.0)

| Index | Purpose | Hash Algorithm | Size |
|-------|---------|----------------|------|
| 1 | Raw bitstream and FW config | Semver2.0 | 4 bytes |
| 2 | PSC firmware hash | SHA2-512 | 64 bytes |
| 3 | NIC firmware hash | SHA2-512 | 64 bytes |
| 4 | ARM firmware hash | SHA2-512 | 64 bytes |
| 5 | NIC rollback counters | SHA2-512 | 64 bytes |
| 6 | ARM rollback counters | SHA2-512 | 64 bytes |
| 7 | NIC security config | SHA2-512 | 64 bytes |
| 8 | ARM security config | SHA2-512 | 64 bytes |
| 9 | PSC first mutable code security config | SHA2-512 | 64 bytes |
| 10 | PSC runtime firmware security config | SHA2-512 | 64 bytes |
| 11 | Device identifier (DID, VID, SVID, SID) | Raw bitstream | 50 bytes |

**CoRIM Inclusion:** Indices 1-4 and 11 are included in CoRIM reference manifests. Indices 5-10 (rollback counters, security configs) are excluded from CoRIM but available for runtime attestation.

### DICE Certificate Chain Content

The L5 and L6 certificates contain evidence as X.509 extensions:
- **OID:** `2.23.133.5.4.1` (TCG-DICE-FWID)
- **TCG_DICE_FWID-0:** SHA2-384 hash of hardware configuration + first mutable firmware
- **TCG_DICE_FWID-1:** SHA2-384 hash of runtime firmware code

## 4. How Are They Signed/Verified?

### CoRIM Signing

**Mechanism:** COSE Single Signer (COSE-Sign1)

**Signature Coverage:**
- Protected header parameters
- Payload (CoMID content)

**Verification Process:**
1. Retrieve CoRIM from NVIDIA RIM service
2. Strip 6-byte IANA tag prefix
3. Parse CBOR structure
4. Validate COSE signature against NVIDIA signing certificate
5. Compare embedded measurements against device SPDM responses

### SPDM Measurement Signing

**Protocol:** SPDM v1.1 over MCTP

**Signing Algorithm:** ECDSA with P-384 curve (TPM_ALG_ECDSA_ECC_NIST_P384)

**Hashing Algorithm:** SHA-512 (TPM_ALG_SHA_512)

**Verification Flow:**
```
1. GET /redfish/v1/ComponentIntegrity/Bluefield_DPU_IRoT
2. POST to SPDMGetSignedMeasurements action with nonce
3. Retrieve signed response (base64-encoded)
4. Verify signature against certificate chain
5. Compare measurements to CoRIM reference values
```

## 5. Live Redfish API Endpoints (Confirmed on Lab DPU)

### ComponentIntegrity Collection
```
GET https://192.168.1.203/redfish/v1/ComponentIntegrity
```

**Available Targets:**
- `/redfish/v1/ComponentIntegrity/Bluefield_DPU_IRoT` (DPU Internal Root of Trust)
- `/redfish/v1/ComponentIntegrity/Bluefield_ERoT` (BMC External Root of Trust)

### Certificate Chain Retrieval
```
GET https://192.168.1.203/redfish/v1/Chassis/Bluefield_DPU_IRoT/Certificates/CertChain
```

Returns 6-certificate PEM chain (L0-L6 DICE hierarchy):
1. **NVIDIA Device Identity CA** (root)
2. **NVIDIA BF3 Identity**
3. **Provisioner CA**
4. **Internal ROT A0 PSC ROM**
5. **Internal ROT A0 PSC FMC CA**
6. **Internal ROT A0 PSC FMC LF** (leaf)

### Signed Measurements Request
```
POST https://192.168.1.203/redfish/v1/ComponentIntegrity/Bluefield_DPU_IRoT/Actions/ComponentIntegrity.SPDMGetSignedMeasurements

{
  "SlotId": 0,
  "Nonce": "<64-char-hex>",
  "MeasurementIndices": [2, 3, 4]   // Optional, omit for all
}
```

**Response:**
```json
{
  "HashingAlgorithm": "TPM_ALG_SHA_512",
  "SignedMeasurements": "<base64-encoded>",
  "SigningAlgorithm": "TPM_ALG_ECDSA_ECC_NIST_P384",
  "Version": "1.1.0"
}
```

## 6. Go Libraries Required

### Veraison cocli (Compatible Version)
```bash
go install github.com/veraison/cocli@v0.0.1-compat
```

### Go Packages for Programmatic Access
- `github.com/veraison/corim/corim` - CoRIM manipulation
- `github.com/veraison/corim/comid` - CoMID manipulation
- `github.com/veraison/go-cose` - COSE signature handling
- `github.com/fxamacker/cbor/v2` - CBOR encoding/decoding

## 7. Implementation Recommendations for Fabric Console

### Phase 1: Measurement Retrieval (Completed)
- Certificate chain retrieval via GetCertificateChain()
- Display DICE hierarchy in dashboard

### Phase 2: Signed Measurements (Next)
1. Add `GetSignedMeasurements()` to Redfish client
2. Parse SPDM measurement response
3. Display individual measurement hashes in UI

### Phase 3: CoRIM Validation
1. Integrate NVIDIA RIM service API to fetch CoRIM by firmware version
2. Parse CBOR/COSE structure
3. Compare measurement hashes against CoRIM reference values
4. Display validation status (match/mismatch per index)

### Phase 4: Full Attestation Workflow
1. Verify COSE signature on CoRIM
2. Validate DICE certificate chain to NVIDIA root
3. Verify SPDM measurement signatures
4. Integrate attestation status into Cedar policy decisions

## 8. Key Documentation Sources

| Resource | URL |
|----------|-----|
| NVIDIA Device Attestation (v3.0) | https://docs.nvidia.com/networking/display/dpunicattestation |
| CoRIM Structure | https://docs.nvidia.com/networking/display/dpunicattestation/concise-reference-integrity-manifest-(corim) |
| SPDM Reference Measurements | https://docs.nvidia.com/networking/display/dpunicattestation/spdm+reference+measurements |
| NVIDIA RIM Service | https://docs.nvidia.com/networking/display/dpunicattestation/nvidia+rim+service |
| DPU BMC SPDM Attestation | https://docs.nvidia.com/networking/display/bluefieldbmcv2507/dpu+bmc+spdm+attestation+via+redfish |
| Tools and Utilities | https://docs.nvidia.com/networking/display/dpunicattestation/tools+and+utilities |

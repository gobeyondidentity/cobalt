# MVP: DPU Hardware Identity Demo

**Target**: December 13, 2025 (Prashanth demo)
**Complexity**: Low (1-2 days)
**Language**: Go with CGO

---

## Objective

Demonstrate that a Bluefield-3 DPU can generate and hold a cryptographic identity using hardware-accelerated PKA (Public Key Accelerator), proving Beyond Identity can issue credentials to the enforcement layer.

---

## Demo Story for Prashanth

> "This DPU has a hardware-bound cryptographic identity. The keypair was generated using the Bluefield's PKA engine - the same hardware that does line-rate TLS offload. This is the foundation: the enforcement point now has its own verifiable identity that Beyond Identity can manage."

---

## Technical Approach

### What PKA Provides

The Bluefield PKA library (`libpka1`) provides hardware-accelerated cryptographic primitives:

| Operation | PKA Function | Use Case |
|-----------|--------------|----------|
| Modular exponentiation | `pka_modular_exp()` | RSA encrypt/decrypt/sign |
| RSA with CRT | `pka_rsa_crt()` | Optimized RSA operations |
| EC point multiplication | `pka_ecc_pt_mult()` | ECDSA key derivation |
| DSA signature | `pka_dsa_signature_generate()` | Digital signatures |

### What PKA Does NOT Provide

- Random number generation (use OS `/dev/urandom`)
- Prime generation (must generate in software)
- High-level key generation APIs (must compose from primitives)

### Chosen Approach: ECDSA with PKA

**Why ECDSA over RSA**:
1. Simpler key generation (random scalar + point multiplication)
2. Smaller keys (256-bit vs 2048-bit)
3. Faster operations
4. Modern standard (used by Beyond Identity passkeys)

**Key Generation Flow**:
```
1. Generate random 256-bit scalar (d) using OS RNG
2. Use PKA to compute public key: Q = d * G (point multiplication)
3. Store private scalar securely on DPU
4. Export public key for certificate signing
```

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Go Application                        │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────┐  │
│  │ Key Manager │  │ CSR Builder │  │ Device Info     │  │
│  └──────┬──────┘  └──────┬──────┘  └────────┬────────┘  │
│         │                │                   │           │
│         ▼                ▼                   ▼           │
│  ┌─────────────────────────────────────────────────────┐│
│  │                   CGO Bridge                         ││
│  │  - pka_init_global() / pka_init_local()             ││
│  │  - pka_ecc_pt_mult() for key derivation             ││
│  │  - pka_term_local() / pka_term_global()             ││
│  └──────────────────────┬──────────────────────────────┘│
└─────────────────────────┼───────────────────────────────┘
                          │ CGO
                          ▼
┌─────────────────────────────────────────────────────────┐
│                    libpka1 (C Library)                   │
│  - Hardware ring buffer management                       │
│  - PKA engine communication                              │
└─────────────────────────┬───────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────┐
│              Bluefield-3 PKA Hardware                    │
│  - EIP-154 crypto accelerator                           │
│  - Line-rate modular arithmetic                          │
│  - Hardware isolation from host                          │
└─────────────────────────────────────────────────────────┘
```

---

## Implementation Plan

### Phase 1: PKA Integration (Day 1)

**File**: `pkg/pka/pka.go`

```go
package pka

/*
#cgo CFLAGS: -I/usr/include
#cgo LDFLAGS: -lpka
#include <pka.h>
#include <stdlib.h>
*/
import "C"

// Initialize PKA engine
func Init() error { ... }

// Generate ECDSA keypair using PKA point multiplication
func GenerateECDSAKeyPair() (*ECDSAKeyPair, error) { ... }

// Clean up PKA resources
func Shutdown() error { ... }
```

**Tasks**:
- [ ] Create CGO bindings for `pka_init_global`, `pka_init_local`
- [ ] Create CGO bindings for `pka_ecc_pt_mult`
- [ ] Implement ECDSA key generation using P-256 curve
- [ ] Create CGO bindings for cleanup functions

### Phase 2: Key Management (Day 1)

**File**: `pkg/identity/identity.go`

```go
package identity

// DPUIdentity represents the DPU's cryptographic identity
type DPUIdentity struct {
    PrivateKey  []byte    // Stored securely on DPU
    PublicKey   []byte    // Can be exported
    DeviceInfo  DeviceInfo
    GeneratedAt time.Time
}

// Generate creates a new DPU identity using PKA
func Generate() (*DPUIdentity, error) { ... }

// CreateCSR generates a certificate signing request
func (id *DPUIdentity) CreateCSR() ([]byte, error) { ... }
```

### Phase 3: Demo CLI (Day 2)

**File**: `cmd/dpu-identity/main.go`

```go
func main() {
    // 1. Initialize PKA
    // 2. Generate identity
    // 3. Display device info
    // 4. Create and display CSR
    // 5. Cleanup
}
```

**Demo Output**:
```
=== Bluefield DPU Identity Generator ===

Device Information:
  Model:     BlueField-3 B3210E
  Serial:    MT2310X00000
  Firmware:  32.41.1000
  PKA:       EIP-154 (hardware accelerated)

Generating ECDSA P-256 keypair using PKA...
  Private key: [stored securely on DPU]
  Public key:  04:a1:b2:c3:... (65 bytes)

Certificate Signing Request:
-----BEGIN CERTIFICATE REQUEST-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
-----END CERTIFICATE REQUEST-----

Subject: CN=bluefield3-dpu,O=BeyondIdentity,OU=DPU-Identity

Ready for Beyond Identity certificate issuance.
```

---

## Files to Create

```
engineering/mvp-dpu-identity/
├── README.md           # This document
├── go.mod              # Go module definition
├── go.sum
├── cmd/
│   └── dpu-identity/
│       └── main.go     # CLI entry point
├── pkg/
│   ├── pka/
│   │   ├── pka.go      # CGO bindings to libpka
│   │   └── pka_test.go # Unit tests
│   ├── identity/
│   │   ├── identity.go # Key management
│   │   └── csr.go      # CSR generation
│   └── device/
│       └── info.go     # Bluefield device info
└── Makefile            # Build for ARM64
```

---

## Build & Run

```bash
# On development machine (cross-compile for ARM64)
GOOS=linux GOARCH=arm64 CGO_ENABLED=1 \
  CC=aarch64-linux-gnu-gcc \
  go build -o dpu-identity ./cmd/dpu-identity

# Copy to Bluefield
scp dpu-identity nmelo@bluefield3:~/

# On Bluefield
ssh nmelo@bluefield3
sudo ./dpu-identity
```

**Note**: CGO cross-compilation requires `aarch64-linux-gnu-gcc` toolchain. Alternative: build directly on Bluefield.

---

## Dependencies

**On Bluefield (already installed)**:
- `libpka1` - PKA runtime library
- `libpka1-dev` - PKA headers

**On Development Machine** (if cross-compiling):
- `gcc-aarch64-linux-gnu` - ARM64 cross-compiler
- Go 1.21+ with CGO support

---

## Success Criteria

1. [ ] PKA initializes without error
2. [ ] ECDSA keypair generated using hardware acceleration
3. [ ] CSR created with DPU device info in subject
4. [ ] Demo runs in <5 seconds
5. [ ] Clean shutdown without resource leaks

---

## Risks & Mitigations

| Risk | Mitigation |
|------|------------|
| PKA API complexity | Start with simplest operation (point mult) |
| CGO debugging difficult | Build directly on Bluefield first |
| Cross-compile issues | Fall back to native ARM64 build |
| P-256 curve params wrong | Use well-known test vectors to verify |

---

## Future Extensions (Post-Demo)

1. **Option B**: Call Beyond Identity API to sign the CSR
2. **Attestation**: Add DICE/SPDM device attestation
3. **Storage**: Secure key storage (not just memory)
4. **mTLS**: Use generated cert for mTLS server

---

## References

- `/usr/include/pka.h` - PKA API documentation
- [NIST P-256 curve parameters](https://neuromancer.sk/std/nist/P-256)
- [Beyond Identity API](https://developer.beyondidentity.com/)

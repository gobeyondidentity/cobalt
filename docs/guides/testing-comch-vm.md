# Testing ComCh in VMs

Test DOCA ComCh integration code without BlueField hardware using VMs. This guide covers VM setup, test layers, and DOCA API behavior without hardware.

## 1. Overview

### Why VM Testing?

| Benefit | Description |
|---------|-------------|
| CI coverage | Run tests without hardware access |
| Faster iteration | No physical DPU required for development |
| CGO validation | Test C-to-Go bindings |
| Cost efficiency | Reduce hardware test time |

### What Can Be Tested

| Test Layer | Environment | Coverage |
|------------|-------------|----------|
| Unit (MockTransport) | CI, no hardware | Go-level logic, message handling |
| Protocol (dpuemu) | CI, no hardware | Message formats, request/response flows |
| CGO wrapper | CI with DOCA SDK | C callback bridging, progress loop |
| Integration | Hardware only | Actual PCIe communication |

## 2. VM Setup

### Prerequisites

- VM with Ubuntu 22.04 or 24.04 (amd64 or arm64)
- 4GB+ RAM, 20GB+ disk
- Internet access for package download

### Option A: Multipass (Recommended)

```bash
# Create VM
multipass launch -n doca-test -c 2 -m 4G -d 20G 24.04

# Enter VM
multipass shell doca-test
```

### Option B: Docker

```bash
docker run -it --name doca-test ubuntu:24.04 /bin/bash
```

## 3. Installing DOCA SDK

### Add NVIDIA Repository

```bash
# Install prerequisites
sudo apt update
sudo apt install -y curl gnupg

# Add NVIDIA DOCA repository
curl -fsSL https://linux.mellanox.com/public/keys/GPG-KEY-Mellanox.pub | sudo gpg --dearmor -o /usr/share/keyrings/mellanox.gpg

echo "deb [signed-by=/usr/share/keyrings/mellanox.gpg] https://linux.mellanox.com/public/repo/doca/2.9.1/ubuntu24.04/aarch64/ ./" | sudo tee /etc/apt/sources.list.d/doca.list

sudo apt update
```

### Install ComCh Packages

```bash
# Runtime and development packages
sudo apt install -y doca-sdk-comch libdoca-sdk-comch-dev libdoca-sdk-common-dev

# Verify installation
ls /opt/mellanox/doca/include/doca_comch.h
# Expected: /opt/mellanox/doca/include/doca_comch.h
```

**Note:** The full `doca-devel` metapackage has unmet dependencies in VMs. Install individual packages instead.

### Installed Files

| Path | Purpose |
|------|---------|
| `/opt/mellanox/doca/lib/*/libdoca_comch.so.*` | Runtime library |
| `/opt/mellanox/doca/include/doca_comch.h` | Header file |
| `/opt/mellanox/doca/include/doca_pe.h` | Progress engine header |

## 4. DOCA API Behavior Without Hardware

The DOCA library runs in VMs but returns 0 devices at enumeration. This table shows what works:

| API Call | Result | Notes |
|----------|--------|-------|
| `doca_devinfo_create_list()` | SUCCESS (0 devices) | Library loads, no hardware |
| `doca_pe_create()` | SUCCESS | Progress engine works |
| `doca_pe_progress()` | SUCCESS (0 events) | Runs without hardware |
| `doca_comch_client_create(NULL, ...)` | DOCA_ERROR_INVALID_VALUE | Graceful failure |
| `doca_comch_server_create(dev, ...)` | DOCA_ERROR_INVALID_VALUE | Requires valid device |
| `doca_ctx_start()` | N/A | Never reached without device |

### Key Insight

Only device enumeration needs stubbing. The rest of DOCA either:
- Works without hardware (progress engine)
- Fails gracefully with clear error codes

### Test Program Output

```
=== DOCA ComCh Test (No Hardware) ===

Step 1: doca_devinfo_create_list()
  Result: DOCA_SUCCESS
  Devices found: 0

FAILED: No devices found - BlueField hardware required
```

```
=== DOCA API Boundary Test ===

Test 1: doca_pe_create() - no device required
  Result: DOCA_SUCCESS
  PE ptr: 0xb086486a0340

  SUCCESS: Progress engine created without hardware!

Test 2: doca_pe_progress() - empty progress loop
  Events processed: 0

Test 3: doca_comch_client_create() with NULL device
  Result: DOCA_ERROR_INVALID_VALUE
  Expected: DOCA_ERROR_INVALID_VALUE or similar

=== Summary ===
- Progress engine: works without hardware
- ComCh client: requires valid device
```

## 5. Test Layers

### Layer 1: MockTransport (Go-Level)

Tests Go logic without CGO. Already available at `pkg/transport/mock.go`.

```bash
# Run unit tests
go test ./pkg/transport/... -v
```

**Coverage:**
- Message serialization/deserialization
- State machine transitions
- Error handling paths

### Layer 2: Protocol Tests (dpuemu)

Tests message formats using TCP emulator. Same protocol, different transport.

```bash
# Start emulator
bin/dpuemu --control-plane http://localhost:18080

# Run protocol tests
go test ./internal/sentry/... -tags=emulator
```

**Coverage:**
- Request/response cycles
- Enrollment flow
- Credential distribution

### Layer 3: CGO Wrapper (C Stub)

Tests C-to-Go bridging with a minimal stub library.

**Stub scope (minimal):**

| Stubbed Function | Behavior |
|------------------|----------|
| `doca_devinfo_create_list()` | Returns 1 fake device |
| Device property getters | Return test values |

Everything else uses the real DOCA library.

```bash
# Build with stub
CGO_LDFLAGS="-L./stub -ldoca_stub" go build ./...

# Run CGO tests
go test ./pkg/transport/doca_comch_test.go -v
```

### Layer 4: Hardware Tests

Required for actual PCIe communication. Run on real BlueField hardware.

```bash
# On hardware test host
go test ./pkg/transport/... -tags=hardware -v
```

## 6. Running Tests

### CI Configuration

```yaml
# .github/workflows/test.yml
jobs:
  unit-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run unit tests
        run: go test ./... -v

  protocol-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Start emulator
        run: bin/dpuemu &
      - name: Run protocol tests
        run: go test ./... -tags=emulator -v

  hardware-tests:
    runs-on: [self-hosted, bluefield]
    steps:
      - uses: actions/checkout@v4
      - name: Run hardware tests
        run: go test ./... -tags=hardware -v
```

### Local Development

```bash
# Quick iteration (no hardware)
make test

# Full protocol tests
make test-emulator

# Hardware validation (requires BF3)
make test-hardware
```

## 7. Coverage Goals

### CI Coverage (No Hardware)

| Metric | Target |
|--------|--------|
| Line coverage (transport pkg) | 80% |
| Branch coverage | 70% |
| Protocol message types | 100% |
| Error injection scenarios | 10+ |

### Hardware Coverage (Pre-Release)

| Test | Pass Criteria |
|------|---------------|
| Device discovery | Finds BF3 device |
| ComCh connection | Establishes successfully |
| Enrollment flow | Completes end-to-end |
| Posture reporting | 100 reports without error |
| Credential push | Delivered to host |
| Reconnection | Reconnects within 5s |

## 8. Troubleshooting

### "Package not found" during DOCA install

**Cause:** Wrong repository URL for your architecture/OS version.

**Fix:** Verify repository URL matches your system:
```bash
# Check architecture
uname -m
# aarch64 = arm64, x86_64 = amd64

# Check OS version
lsb_release -cs
```

### Tests pass in VM but fail on hardware

**Cause:** VM tests don't exercise actual PCIe paths.

**Fix:** This is expected. VM tests validate logic; hardware tests validate communication. Both are needed.

### CGO build errors

**Cause:** Missing DOCA headers or libraries.

**Fix:**
```bash
export CGO_CFLAGS="-I/opt/mellanox/doca/include"
export CGO_LDFLAGS="-L/opt/mellanox/doca/lib/$(uname -m)-linux-gnu -ldoca_comch -ldoca_common"
```

## 9. References

- `qa/memos/eng-vm-comch-test-exploration.md` - Original VM validation findings
- `qa/memos/eng-comch-test-strategy.md` - Full test strategy
- `pkg/transport/mock.go` - MockTransport implementation
- `eng/dpuemu/` - Protocol emulator

# dpuemu - DPU Emulator

> **Public repo**: https://github.com/nmelo/dpuemu (placeholder for SEO/discovery)

A BlueField DPU emulator that implements the same gRPC interface as the real agent. Enables development, testing, and demos without physical hardware.

## Why This Exists

- **1 physical DPU** = development bottleneck
- **CI/CD** can't run without hardware access
- **Multi-DPU testing** impossible with single device
- **Demos** require live hardware availability

dpuemu solves all of these by providing a fake DPU that responds identically to a real one.

## Modes

### Static Mode (default)
Responds from fixture files. No real DPU needed.

```bash
dpuemu --mode=static --fixture=fixtures/bf3-default.json --listen=:50051
```

### Proxy Mode
Transparent pass-through to real DPU. For verifying emulator accuracy.

```bash
dpuemu --mode=proxy --upstream=bluefield3:50051 --listen=:50052
```

### Learning Mode
Records responses from real DPU to create fixtures.

```bash
dpuemu --mode=learn --upstream=bluefield3:50051 --output=recordings/session.json
```

## Quick Start

```bash
# Build
go build -o dpuemu ./cmd/dpuemu

# Run with default fixture
./dpuemu --mode=static --fixture=fixtures/bf3-default.json

# Test with bluectl
bluectl dpu add emu localhost:50051
bluectl dpu info emu
```

## Multi-Emulator Setup

Spin up 10 fake DPUs:

```bash
docker-compose up --scale dpuemu=10
```

Or with explicit instances:

```bash
docker-compose -f docker-compose.multi.yml up
```

## Fixture Format

```json
{
  "system_info": {
    "hostname": "bf3-emu-{{.InstanceID}}",
    "model": "BlueField-3 B3210E",
    "serial_number": "MT2349X{{.InstanceID}}",
    "firmware_version": "32.47.1026",
    "doca_version": "2.9.1",
    "arm_cores": 16,
    "memory_gb": 32,
    "uptime_seconds": 86400,
    "ovs_version": "3.3.0",
    "kernel_version": "5.15.0-1033-bluefield"
  },
  "bridges": [
    {
      "name": "ovs-br0",
      "ports": ["p0", "pf0hpf", "en3f0pf0sf0"]
    }
  ],
  "flows": {
    "ovs-br0": [
      {
        "table": 0,
        "priority": 100,
        "match": "in_port=1,dl_type=0x0800",
        "actions": "output:2",
        "packets": 1234567,
        "bytes": 98765432,
        "age": "1d2h"
      }
    ]
  },
  "attestation": {
    "certificates": [
      {
        "level": 0,
        "subject": "CN=NVIDIA BlueField IRoT",
        "issuer": "CN=NVIDIA BlueField IRoT",
        "not_before": "2024-01-01T00:00:00Z",
        "not_after": "2034-01-01T00:00:00Z",
        "algorithm": "ECDSA-P384",
        "pem": "-----BEGIN CERTIFICATE-----\n..."
      }
    ],
    "measurements": {
      "firmware": "sha384:abc123...",
      "bootloader": "sha384:def456..."
    }
  }
}
```

### Template Variables

When `--instance-id` is provided, these placeholders are replaced:

| Variable | Example | Description |
|----------|---------|-------------|
| `{{.InstanceID}}` | `001` | Zero-padded instance ID |
| `{{.InstanceNum}}` | `1` | Numeric instance ID |
| `{{.Hostname}}` | `bf3-emu-001` | Generated hostname |
| `{{.RandomSerial}}` | `MT2349X00ABC` | Random serial suffix |

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      dpuemu                                  │
│  ┌───────────────────────────────────────────────────────┐  │
│  │           gRPC Server (agent.v1.DPUAgent)              │  │
│  └────────────────────────┬──────────────────────────────┘  │
│                           │                                  │
│  ┌────────────────────────▼──────────────────────────────┐  │
│  │                   Mode Router                          │  │
│  │  ┌──────────┐  ┌───────────┐  ┌──────────┐           │  │
│  │  │  Static  │  │   Proxy   │  │ Learning │           │  │
│  │  │  Mode    │  │   Mode    │  │   Mode   │           │  │
│  │  └────┬─────┘  └─────┬─────┘  └────┬─────┘           │  │
│  └───────┼──────────────┼─────────────┼─────────────────┘  │
│          │              │             │                     │
│          ▼              ▼             ▼                     │
│     Fixture         Real DPU     Record to                 │
│     Files           (gRPC)       File + Forward            │
└─────────────────────────────────────────────────────────────┘
```

## Directory Structure

```
dpuemu/
├── cmd/dpuemu/main.go       # Entry point
├── internal/
│   ├── server/server.go     # gRPC server wrapper
│   ├── static/static.go     # Static mode handler
│   ├── proxy/proxy.go       # Proxy mode handler
│   └── recorder/recorder.go # Learning mode handler
├── fixtures/                # Sample fixtures
│   ├── bf3-default.json     # Minimal BF3
│   ├── bf3-full.json        # Full data
│   └── bf3-no-ovs.json      # No OVS configured
├── recordings/              # Recorded sessions (gitignored)
├── Dockerfile
└── docker-compose.yml
```

## Development

```bash
# Run tests
go test ./dpuemu/...

# Build for local
go build -o dpuemu ./dpuemu/cmd/dpuemu

# Build Docker image
docker build -t dpuemu -f dpuemu/Dockerfile .

# Record from real DPU
./dpuemu --mode=learn --upstream=bluefield3:50051 --output=fixtures/recorded.json

# Verify recording matches real DPU
./dpuemu --mode=static --fixture=fixtures/recorded.json &
# Compare outputs...
```

## CI/CD Integration

```yaml
# .github/workflows/test.yml
jobs:
  integration-test:
    runs-on: ubuntu-latest
    services:
      dpuemu:
        image: ghcr.io/org/dpuemu:latest
        ports:
          - 50051:50051
    steps:
      - uses: actions/checkout@v4
      - run: go test ./... -tags=integration
```

## Relationship to Main Project

- **Depends on**: `proto/agent/v1/agent.proto` (shared gRPC definition)
- **Shares**: `gen/go/` generated protobuf code
- **Independent of**: Real agent implementation (`cmd/agent/`)

Can be developed in parallel with agent once proto is defined.

# Secure Infrastructure

Hardware-bound credential management for AI infrastructure using NVIDIA BlueField DPUs.

## Overview

Secure Infrastructure binds credentials to hardware so they can't be extracted, even by root. Private keys live in the DPU's hardware root of trust. They can sign operations, but they can't be read out or copied to another machine.

When a node is compromised, your IR doesn't include a credential rotation fire drill. The credentials couldn't move.

The system uses BlueField-3 DPUs as enforcement points, checking both hardware attestation (DICE) and host posture before any credential is created or used.

## Features

- **Hardware-bound credentials**: Private keys in DPU hardware root of trust, not files on disk
- **Posture-aware operations**: Credentials only created/used when hardware and OS attestation pass
- **No secret sprawl**: Credentials die with the node; fresh ones created automatically on reimage
- **Audit trail**: Every credential push tied to point-in-time attestation state
- **SSH CA management**: Create, sign, push certificate authorities to attested infrastructure
- **Automation-ready**: Structured output (`-o json`), idempotent commands, exit codes

## Quick Start

For complete setup instructions, see the [Setup Guide](docs/setup-guide.md).

**Demo the attestation gate with the emulator:**

```bash
# Terminal 1: Start server
bin/server --listen :8080

# Terminal 2: Start DPU emulator
bin/dpuemu serve --port 50051
```

```bash
# Terminal 3: Set up and demo

# 1. Create tenant and register DPU
bluectl tenant add demo
bluectl dpu add bf3-emu localhost --port 50051
bluectl tenant assign demo bf3-emu

# 2. Verify hardware attestation
bluectl attestation bf3-emu

# 3. Create SSH CA and push to attested DPU
km ssh-ca create ops-ca
km push ssh-ca ops-ca bf3-emu    # Succeeds (fresh attestation)

# 4. The gate in action: wait for staleness or simulate
#    After 1 hour, attestation becomes stale:
km push ssh-ca ops-ca bf3-emu    # BLOCKED: attestation stale

# 5. Re-attest and retry
bluectl attestation bf3-emu      # Re-verify hardware
km push ssh-ca ops-ca bf3-emu    # Succeeds again
```

The attestation gate blocks credential distribution when hardware verification is stale or failed. This is the core security property: credentials only flow to verified infrastructure.

## Components

| Component | Description |
|-----------|-------------|
| `bluectl` | Admin CLI: DPU management, tenants, operators, attestation |
| `km` | Operator CLI: SSH CA lifecycle, credential push |
| `agent` | DPU agent running on BlueField ARM cores |
| `host-agent` | Host agent for credential receipt via tmfifo and posture reporting |
| `server` | Control plane server |
| `dpuemu` | DPU emulator for local development |
| `web/` | Next.js dashboard (in development) |

## Tech Stack

- **API/Agent**: Go 1.22+
- **Policy**: Cedar (AWS policy language)
- **Dashboard**: Next.js 14, Tailwind, shadcn/ui
- **Communication**: gRPC/protobuf
- **Storage**: SQLite (encrypted)

## Development

```bash
# Build all binaries
make

# Run tests
make test

# Build release binaries for all platforms
make release

# Dashboard
cd web && npm install && npm run dev
```

## Project Structure

```
eng/
├── cmd/           # CLI and agent entrypoints
├── internal/      # Private application code
├── pkg/           # Shared libraries
├── proto/         # Protobuf definitions
├── gen/           # Generated gRPC code
├── dpuemu/        # DPU emulator
├── web/           # Dashboard (Next.js)
└── deploy/        # Install scripts
```

## License

Proprietary - Beyond Identity, Inc.

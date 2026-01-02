# Secure Infrastructure

Attestation-gated credential management for AI infrastructure using NVIDIA BlueField DPUs.

## Overview

Secure Infrastructure provides hardware-enforced Zero Trust authentication for GPU clusters. It uses BlueField-3 Data Processing Units (DPUs) as trust anchors, requiring cryptographic attestation before deploying credentials. Attestation proves that hardware is genuine and firmware is unmodified, preventing credential theft even if host systems are compromised.

## Features

- SSH CA lifecycle management (create, list, show, sign)
- Attestation gate with automatic refresh
- Distribution history with audit trail
- Operator identity and authorization
- Structured CLI output (`-o json`)
- Idempotent create commands

## Quick Start

```bash
# Start the DPU emulator for local development
dpuemu serve --port 50051

# Register the emulated DPU with the control plane
bluectl dpu add localhost --port 50051

# Create an SSH Certificate Authority
km ssh-ca create ops-ca

# Push CA to DPU (requires valid attestation)
km push ssh-ca ops-ca localhost
```

## Components

| Component | Description |
|-----------|-------------|
| `bluectl` | Admin CLI: DPU management, tenants, operators, attestation |
| `km` | Operator CLI: SSH CA lifecycle, credential distribution |
| `agent` | DPU agent running on BlueField ARM cores |
| `host-agent` | Host agent for credential receipt via tmfifo and posture reporting |
| `api` | Control plane API server |
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

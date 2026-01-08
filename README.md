# Secure Infrastructure

**v0.4.0** | [Quickstart](docs/guides/quickstart-emulator.md) | [Hardware Setup](docs/guides/setup-hardware.md) | [Changelog](CHANGELOG.md)

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

Choose your path:

| Path | Time | Requirements |
|------|------|--------------|
| [Emulator Quickstart](docs/guides/quickstart-emulator.md) | 10 min | Go 1.22+, Make |
| [Hardware Setup](docs/guides/setup-hardware.md) | 30 min | BlueField-3 DPU |

**Try the emulator first** to learn the system without hardware. The quickstart walks you through the full flow: create a tenant, register a DPU, set up operators, and push credentials to attested infrastructure.

The core security property: credentials only flow to verified infrastructure. When attestation is stale or failed, credential distribution is blocked.

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
secure-infra/
├── cmd/           # CLI and agent entrypoints
├── pkg/           # Shared libraries
├── internal/      # Private application code
├── proto/         # Protobuf definitions
├── gen/           # Generated gRPC code
├── dpuemu/        # DPU emulator
├── web/           # Dashboard (Next.js)
├── deploy/        # Install scripts
└── docs/          # Setup guides
```

## License

Proprietary - Beyond Identity, Inc.

# Secure Infrastructure

**v0.6.4** | [Quickstart](docs/guides/quickstart-emulator.md) | [Hardware Setup](docs/guides/setup-hardware.md) | [Changelog](CHANGELOG.md)

Hardware-bound credential management for AI infrastructure using NVIDIA BlueField DPUs.

## Overview

Secure Infrastructure binds credentials to hardware so they can't be extracted, even by root. Private keys live in the DPU's hardware root of trust. They can sign operations, but they can't be read out or copied to another machine.

When a node is compromised, your IR doesn't include a credential rotation fire drill. The credentials couldn't move.

The system uses BlueField-3 DPUs as enforcement points, checking both hardware attestation (DICE) and host posture before any credential is created or used.

## Features

- **Hardware-bound credentials**: Private keys in DPU hardware root of trust, not files on disk
- **DOCA ComCh transport**: Native PCIe communication between host and DPU (no IP configuration)
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

## Installation

### macOS (Homebrew)

```bash
brew install nmelo/tap/bluectl nmelo/tap/km                    # CLI tools
brew install nmelo/tap/sentry nmelo/tap/nexus nmelo/tap/dpuemu # Agents and emulator
```

### Linux (Debian/Ubuntu)

```bash
# Add repository (auto-detects your distro)
curl -1sLf 'https://dl.cloudsmith.io/public/beyond-identity/secure-infra/cfg/setup/bash.deb.sh' | sudo bash
sudo apt update && sudo apt install bluectl km
```

### Linux (RHEL/Fedora)

```bash
# Add repository (auto-detects your distro)
curl -1sLf 'https://dl.cloudsmith.io/public/beyond-identity/secure-infra/cfg/setup/bash.rpm.sh' | sudo bash
sudo yum install bluectl km
```

### Docker

```bash
docker pull ghcr.io/gobeyondidentity/nexus:0.6.4   # Control plane
docker pull ghcr.io/gobeyondidentity/sentry:0.6.4  # Host agent
docker pull ghcr.io/gobeyondidentity/aegis:0.6.4   # DPU agent
```

For local development with Docker Compose, see [Local Dev: Docker](docs/guides/local-dev-docker.md).

### From Source

```bash
git clone git@github.com:gobeyondidentity/secure-infra.git
cd secure-infra
make
```

Check for updates anytime: `bluectl version --check`

## Documentation

### Guides

| Guide | Description |
|-------|-------------|
| [Quickstart: Emulator](docs/guides/quickstart-emulator.md) | Get started without hardware |
| [Local Dev: Docker](docs/guides/local-dev-docker.md) | Run locally with Docker Compose |
| [Hardware Setup](docs/guides/setup-hardware.md) | Deploy on BlueField-3 DPU |
| [Testing ComCh in VMs](docs/guides/testing-comch-vm.md) | Test DOCA integration without hardware |
| [fTPM Key Storage](docs/guides/ftpm-key-storage.md) | Store secrets in firmware TPM |
| [Discovery](docs/guides/discovery.md) | Scan infrastructure for SSH keys |

### Reference

| Reference | Description |
|-----------|-------------|
| [Attestation Architecture](docs/reference/attestation-architecture.md) | DICE/SPDM via PSC and BMC |
| [CLI Version](docs/reference/cli-version.md) | Version check and upgrade commands |
| [Discovery Schema](docs/reference/discovery.md) | JSON output format and jq recipes |
| [Encryption Keys](docs/reference/encryption-keys.md) | Key management internals |

## Components

| Component | Package | Description |
|-----------|---------|-------------|
| `bluectl` | bluectl | Admin CLI: DPU management, tenants, operators, attestation |
| `km` | km | Operator CLI: SSH CA lifecycle, credential push |
| `agent` | aegis | DPU agent running on BlueField ARM cores |
| `host-agent` | sentry | Host agent for credential receipt via ComCh/tmfifo and posture reporting |
| `server` | nexus | Control plane server |
| `dpuemu` | - | DPU emulator for local development |
| `web/` | - | Next.js dashboard (in development) |

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

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.

Copyright 2024-2026 Beyond Identity, Inc.

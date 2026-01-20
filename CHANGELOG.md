# Changelog

All notable changes to the Secure Infrastructure project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.6.3] - 2026-01-20

### Changed
- **Docker Image Renames** to match package naming:
  - `secureinfra-control-plane` → `nexus`
  - `secureinfra-host-agent` → `sentry`
  - `secureinfra-dpu-agent` → `aegis`
- Parallelized Cloudsmith uploads using matrix build strategy (faster releases)

### Added
- **New Homebrew Formulas**:
  - `brew install nmelo/tap/sentry` (host agent)
  - `brew install nmelo/tap/nexus` (control plane)
  - `brew install nmelo/tap/dpuemu` (DPU emulator for local development)

## [0.6.1] - 2026-01-20

### Changed
- **Package Renames** for clearer product identity:
  - `host-agent` → `sentry` (host security agent)
  - `control-plane` → `nexus` (central management server)
  - `dpu-agent` → `aegis` (DPU security agent)
- Linux packages now published to Cloudsmith at `packages.beyondidentity.com`
  - Debian/Ubuntu: `deb [signed-by=...] https://packages.beyondidentity.com/public/secure-infra/deb/any-distro any-version main`
  - RHEL/Fedora: `https://packages.beyondidentity.com/public/secure-infra/rpm/any-distro/any-version/$basearch`

### Added
- README installation instructions for apt and yum/dnf package managers
- Cloudsmith GPG key and repository setup commands

## [0.6.0] - 2026-01-20

### Added
- **DOCA ComCh Transport** for BlueField DPU communication (si-w4z)
  - Production-grade PCIe channel replaces tmfifo (higher throughput, no IP config required)
  - Ed25519 authentication with Trust-On-First-Use (TOFU) key management
  - Automatic PCI device discovery eliminates manual address configuration
  - Connection state machine: Connected → Authenticated → Enrolled
  - Transport priority: ComCh → Tmfifo → Network (automatic fallback)
  - 89.7% test coverage with protocol, error injection, and hardware test suites

- **Version Check CLI** for bluectl and km (si-853.6)
  - `bluectl version --check` / `km version --check` to check for updates
  - `--skip-update-check` flag to disable update checking
  - 24-hour cache to minimize GitHub API calls
  - 2-second timeout for graceful network handling
  - Install-method detection with appropriate upgrade hints (Homebrew, apt, rpm, Docker)

- **Release Infrastructure** (si-853)
  - Homebrew tap: `brew install nmelo/tap/bluectl` and `brew install nmelo/tap/km`
  - Linux packages: `.deb` (Debian/Ubuntu) and `.rpm` (RHEL/Fedora)
  - DPU agent container image: `ghcr.io/gobeyondidentity/secureinfra-dpu-agent`
  - Docker Compose for local development (`docker-compose up`)
  - Self-hosted runners for ARM64 builds and hardware testing

### Changed
- Transport selection priority: ComCh (if available) → Tmfifo → Network
- Host agent requires `--auth-key` flag for Ed25519 authentication key storage (default: `/etc/secureinfra/host-agent.key`)
- DPU agent requires `--keystore` flag for TOFU known-hosts database (default: `/var/lib/secureinfra/known_hosts.json`)
- `bluectl version` and `km version` now use subcommand instead of `--version` flag

### Fixed
- Data race in TmfifoNetListener.watchTransportClose (found by race detector on self-hosted runners)
- Host-agent connection using correct `--dpu-agent` flag
- Docker Compose port mapping for host-agent to DPU-agent communication
- nfpm package config: use `depends` instead of `dependencies`

## [0.5.1] - 2026-01-09

### Fixed
- Duplicate tenant error now shows `tenant 'X' already exists` instead of raw SQL constraint error
- `km discover scan --parallel 0` now validates with clear error before attempting network operations

## [0.5.0] - 2026-01-09

### Added
- `km discover scan` command to scan hosts for SSH authorized_keys files
- SSH fallback mode for hosts without agent (`--ssh`, `--ssh-fallback` flags)
- `ScanSSHKeys` RPC in host-agent for remote key enumeration
- `POST /api/v1/hosts/{hostname}/scan` API endpoint
- `pkg/sshscan` package for SSH key parsing and SHA256 fingerprint generation
- Progress indicators during multi-host scans (suppressed for non-TTY/JSON output)
- Bootstrap mode warning when using SSH without agent
- Audit logging for discovery operations

### Changed
- Exit codes for discover command: 0 (success), 1 (all failed), 2 (partial), 3 (config error)

## [0.4.1] - 2026-01-08

### Added
- `make demo-*` targets for quickstart verification and regression testing
- `make hw-*` targets for hardware setup guide verification

### Changed
- Centralized version management in `internal/version/version.go`
- CLI output no longer exposes internal IDs (tenant add, dpu add, ssh-ca show, tenant show)
- Default server port changed from 8080 to 18080
- Default `km init --control-plane` port updated to match (18080)

### Fixed
- Server and agent binaries were reporting version 0.3.0 instead of current version

### Documentation
- Restructured docs into `docs/guides/` and `docs/reference/` subdirectories
- Rewrote quickstart guide with expanded explanations (DPU, tenants, attestation, SSH CA purpose)
- Added Terminal 1/2/3 labels and "why" context for each step
- All expected outputs now match exact CLI output
- Added `docs/reference/encryption-keys.md` for key management in CI/CD and multi-machine setups
- Added troubleshooting entries for km init issues

## [0.4.0] - 2026-01-07

### Added
- Auto-generated encryption key on first run (no more SECURE_INFRA_KEY setup required)
- Emulator `--control-plane` flag to relay host registrations to control plane
- Emulator returns valid mock attestation (enables demo flow without --force)

### Fixed
- Invite code double-dash bug (e.g., "GPU--KBTK" now "GPU-KBTK")
- CA authorization lookup now matches by name or ID
- `km ssh-ca create` no longer exposes internal ID to users

### Documentation
- Split setup guide into Quick Start (Emulator) and Hardware Setup
- Added clean slate instructions for fresh database starts
- Added ROADMAP.md

## [0.3.0] - 2026-01-07

### Added
- dpuemu local REST API (/local/v1/register, /local/v1/posture, /local/v1/cert)
- `km ssh-ca delete` command with confirmation prompt
- Host-agent can now test against emulator

### Changed
- Renamed cmd/api to cmd/server for clarity
- Authorization responses now show human-readable names instead of UUIDs
- `km whoami` shows CA/device names by default (--verbose for IDs)

### Fixed
- ID/name consistency across authorization checks
- Setup guide corrections from validation walkthrough
- README quick start demonstrates attestation gate flow

### Documentation
- Comprehensive setup guide with emulator support
- README polish (overview, features, quick start)

## [0.2.0] - 2026-01-02

### Added
- SSH CA lifecycle: create, list, show, sign certificates
- Operator identity system with invite codes and authorization grants
- Trust relationships between DPUs and hosts
- Attestation gate with auto-refresh before credential distribution
- `km push` command for credential distribution with attestation checks
- Distribution history tracking with `km history`
- Host agent for receiving credentials from DPU agent
- DPU emulator (dpuemu) for local development and testing
- Structured CLI errors with JSON output support
- Idempotent create commands (dpu add, ssh-ca create, operator invite)

### Changed
- Renamed `km distribute` to `km push` for clarity
- CLI arguments: converted required flags to positional args where intuitive
- Improved empty state messages with actionable next steps
- Added identity verification during `bluectl dpu add`
- Status column in `dpu list` now shows warning about cached values

### Security
- Private keys encrypted at rest using SECURE_INFRA_KEY
- Attestation required before credential distribution (bypass requires --force and is audited)
- All forced operations logged to audit trail

## [0.1.0] - 2025-12-15

### Added
- Initial DPU registration and management
- Tenant organization for grouping DPUs
- Basic gRPC agent for DPU communication
- SQLite storage with encryption support
- bluectl CLI for administration

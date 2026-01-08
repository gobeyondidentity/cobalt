# Changelog

All notable changes to the Secure Infrastructure project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.1] - 2026-01-08

### Added
- `make demo-*` targets for quickstart verification and regression testing

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

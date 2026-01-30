# Changelog

All notable changes to the Secure Infrastructure project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.6.11] - 2026-01-30

### Added
- **DPoP Authentication System** for client-to-server authentication (si-d2y):
  - Core library with types, errors, and key utilities (si-d2y.1.5)
  - Proof generator for client authentication (si-d2y.1.6)
  - Proof validator with security-focused validation (si-d2y.1.7)
  - JTI replay cache for proof validation (si-d2y.1.8)
  - HTTP middleware for nexus API authentication (si-d2y.1.9)
  - DB schema for DPoP key lookup (si-d2y.1.4)
  - KeyStore and DPoP Client for client integration (si-d2y.1.10)
  - Security test suite with comprehensive attack vector coverage (si-d2y.1.11)
- **Windows CI Support**: Added Windows runner for cross-platform test verification (si-l80)
- **Platform-Specific Permission Checks**: File permission validation adapted for Windows vs Unix (si-d2y.1.15)

### Changed
- **DPoP JWT Primitives**: Refactored to use go-jose library instead of manual JWT handling (si-d2y.1.12)
- **KeyStore Simplification**: Load only what we save, removing unnecessary complexity (si-d2y.1.13)
- **URL Normalization**: Consolidated into single NormalizeURI function for consistency
- **CLI DPoP Integration**: bluectl and km now use DPoP authentication when configured (si-d2y.1.10)

### Fixed
- **Windows Test Compatibility**: Multiple fixes for cross-platform test execution (si-d2y.1.15):
  - Format tests with Linux-only build tags
  - Mode().Perm() checks wrapped for Windows
  - Unix socket and credential tests guarded with build constraints
- **PKCS8 Parsing**: Now uses x509.ParsePKCS8PrivateKey for correct key deserialization
- **JTI Cache Key**: Uses actual jti claim instead of full proof for replay detection
- **IAT Validation**: Added ErrIATNonPositive for clearer zero/negative timestamp errors
- **Panic Recovery**: Stack traces now included for debugging

## [0.6.10] - 2026-01-29

### Added
- **KeyMaker Revocation**: Revoked KeyMakers can no longer push credentials or sign certificates
- **Host Posture Retrieval**: Query host security posture via aegis agent
- **Operator Suspension Enforcement**: Suspended operators blocked from authorization checks and credential push
- **E2E Test Suite** covering critical security paths:
  - Host posture collection (si-4f8.14)
  - Operator suspension enforcement (si-4f8.15)
  - CA lifecycle operations (si-4f8.10)
  - KeyMaker revocation (si-4f8.16)
  - SSH access flows (si-4f8.13)
  - Mid-push restart recovery (si-4f8.12)
  - DPU metadata preservation and re-registration (si-4f8.11)
  - Multi-tenant isolation (si-4f8.9)
  - Attestation gating (si-4f8.8)
  - Authorization enforcement (si-4f8.7)
  - Operator onboarding (si-4f8.6)
- **sshd Test Harness**: Containerized sshd for integration testing (si-4f8.17)

### Changed
- **km push**: Refactored to use nexus server API instead of direct store access (si-4f8.20)

### Fixed
- **Credential Delivery Race**: Fixed timing issue in E2E credential delivery tests
- **bluectl dpu add**: Fixed double-port bug in DPU registration
- **Operator Grant CLI**: Fixed regression in grant command (si-4f8.4)
- **Test Stability**: Fixed race conditions and bugs in operator suspension, onboarding, and CA lifecycle tests

## [0.6.9] - 2026-01-28

### Breaking Changes
- **bluectl Requires Server Mode**: Local SQLite mode removed. All commands now require `--server` flag or `BLUECTL_SERVER` environment variable pointing to a running nexus instance.

### Added
- **TCP Transport for Tmfifo**: Rewrote PTY-based transport to use TCP sockets (cleaner protocol, more reliable, better debugging)
- **Sentry `--hostname` Flag**: Overrides system hostname for test isolation
- **Sentry `--tmfifo-addr` Flag**: Explicit address configuration with auto-detect default
- **CLI Management Commands**: `operator remove` and `invite remove` for cleanup operations
- **Server Endpoints**: REST API for operator and invite management (`/api/v1/operators`, `/api/v1/invites`)
- **CLI Help Styling**: Colors and emojis in help output for improved readability
- **Aegis State Persistence**: DPU agent state now survives restarts
- **Sentry Auto-Reconnection**: Host agent automatically reconnects when aegis restarts
- **DOCA ComCh Hardware Test Harness**: Test infrastructure for real BlueField-3 hardware validation
- **Integration Test Suite**: 12+ new test scenarios covering:
  - DPU registration flows (positive and negative cases)
  - Multi-tenant enrollment isolation
  - Tenant and invite lifecycle management
  - Credential delivery end-to-end
  - Nexus restart persistence
  - Sentry restart re-enrollment
  - State sync consistency
  - Attestation rejection cases
- **Unit Test Coverage**: aegis core 43.8%, tmfifo transport 84.8%, attestation package 27.7%
- **Credential Delivery Logging**: `[CRED-DELIVERY]` markers for tracing credential flow

### Fixed
- **Sentry Reconnection Protocol**: Now tracks transport auth state correctly (prevents stale connection issues)
- **ClearActiveTransport Race**: Now requires transport parameter to prevent race conditions
- **Tenant Delete**: Checks all dependencies (operators, DPUs) before allowing deletion
- **Tenant Remove by Name**: 404 error when using name instead of ID now resolved
- **Invite Code Error Messages**: Expired and revoked states now show distinct, helpful messages
- **ForceTmfifo**: Now honors explicit `--tmfifo-addr` flag instead of always using default
- **Tmfifo Device Detection**: Correct path detection on real BlueField-3 hardware
- **Server Mode Enforcement**: `operator remove` and `invite remove` require server mode
- **Tmfifo Log Messages**: Now include address for debugging

### Changed
- **Build Scripts**: `doca-build` and `qa-remote-build` use `git pull` instead of `rsync` (simpler, more reliable)
- **Integration Tests**: Updated for server-only bluectl CLI pattern (all management via REST API)

## [0.6.8] - 2026-01-28

### Fixed
- **Credential delivery** (Critical): Sentry now correctly handles CREDENTIAL_PUSH messages via ComCh transport
- **Tenant assign**: Remote DPU lookup now works when server is configured
- **Operator invite**: Now uses remote server when configured (consistent with tenant commands)
- **Invite code caching**: New codes recognized immediately without nexus restart (SQLite WAL mode)
- **DPU state persistence**: State now persists correctly across nexus restarts
- **Cert paths**: systemd config paths now match postinstall.sh generated paths
- **Version string**: Dev builds show git-derived version instead of hardcoded 0.5.2
- **Sentry naming**: Version output now shows `sentry` instead of `host-agent`
- **Nexus naming**: All references updated from `control-plane` to `nexus`

### Changed
- **Source folder renames**: `internal/hostagent` → `internal/sentry`, `internal/agent` → `internal/aegis`
- **Release artifact naming**: Standardized to sentry, aegis, nexus

## [0.6.6] - 2026-01-23

### Added
- **DOCA ComCh CLI Flags** for hardware configuration:
  - aegis: `--doca-pci-addr`, `--doca-rep-pci-addr`, `--doca-server-name`
  - sentry: `--force-comch`, `--doca-pci-addr`, `--doca-server-name`
- **IP-over-PCIe Support**: `--allow-tmfifo-net` flag for aegis to accept connections from tmfifo_net subnet
- **Interactive Demo Script** for NVIDIA presentation with DPU-to-host credential flow

### Changed
- **Multi-arch DOCA Builds**: CGO LDFLAGS now support both arm64 (DPU) and amd64 (host) architectures

### Fixed
- **DOCA ComCh Transport**: Selector now uses real `NewDOCAComchClient()` implementation instead of stub
- **ComCh Enrollment Bridging**: `handleEnrollRequest()` now calls control plane via `RegisterViaTransport()`, enabling `km push` over ComCh
- **CLI Help Output**: nexus `--help` now outputs to stdout instead of stderr
- **Homebrew Tap Name**: Fixed tap reference from `beyondidentity/tap` to `nmelo/tap`

## [0.6.5] - 2026-01-21

### Security
- **SSH Host Key Verification** (CWE-295): Replaced `ssh.InsecureIgnoreHostKey()` with proper `knownhosts` verification in keymaker CLI. Implements TOFU (Trust On First Use) pattern with `--accept-host-key` flag for new hosts.
- **SSRF Protection** (CWE-918): Added endpoint validation for DTS and Redfish clients. Blocks requests to loopback (127.0.0.0/8), link-local (169.254.0.0/16 including AWS metadata), and private ranges (10/8, 172.16/12, 192.168/16) where appropriate.
- **Path Traversal Protection** (CWE-22): Added validation for `--ssh-key` flag to prevent reading arbitrary files. Restricts paths to `~/.ssh/`, current directory, or common SSH key filenames.
- **Test Secret Annotation**: Added `endorctl:allow` annotation for SSH public key test fixtures to suppress false positive in security scans.

### Fixed
- **version.go**: Changed version constant to variable to allow ldflags override during build

### Changed
- **License**: Changed from proprietary to Apache 2.0

## [0.6.4] - 2026-01-20

### Fixed
- **apt/yum Repository Setup**: Replaced manual `any-distro/any-version` paths with Cloudsmith setup script that auto-detects distribution (ubuntu/jammy, debian/bookworm, rhel/9, etc.)
- **Homebrew Formula Names**: Use fully-qualified names (`nmelo/tap/nexus` not `nexus`) to prevent conflict with Sonatype Nexus in homebrew-core
- **Docker Images**: Made `ghcr.io/gobeyondidentity/{nexus,sentry,aegis}` images public (no authentication required to pull)

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
  - Setup script auto-detects distro: `curl -1sLf 'https://dl.cloudsmith.io/public/beyond-identity/secure-infra/cfg/setup/bash.deb.sh' | sudo bash`

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

# Contributing to Cobalt

## Building Packages Locally

QA can build and test packages locally before release using the same build process as CI.

### Prerequisites

| Tool | Install |
|------|---------|
| goreleaser | `brew install goreleaser` or `go install github.com/goreleaser/goreleaser/v2@latest` |
| nfpm | `go install github.com/goreleaser/nfpm/v2/cmd/nfpm@latest` |
| Docker | Required for container builds |

### Standard Packages (Pure Go)

Build all standard packages on any machine:

```bash
make packages
```

Output lands in `dist/`. Includes bluectl, km, sentry, nexus for all platforms (darwin/linux, amd64/arm64) plus deb/rpm packages.

### DOCA Packages

DOCA packages require native builds on specific hardware with the DOCA SDK installed.

**aegis (BF3 only)**

SSH to the BlueField-3 DPU and build natively:

```bash
ssh ubuntu@bluefield3
cd ~/secure-infra && git pull
make package-aegis
```

Output: `aegis_<version>_arm64.deb`, `aegis-<version>-1.aarch64.rpm`

**sentry-doca (workbench only)**

Build on the workbench (x86_64 with DOCA SDK):

```bash
ssh ubuntu@workbench
cd ~/secure-infra && git pull
make package-sentry-doca
```

Output: `sentry-doca_<version>_amd64.deb`, `sentry-doca-<version>-1.x86_64.rpm`

### Container Images

Build containers locally for testing:

```bash
make docker-sentry   # Build sentry:dev (anywhere)
make docker-nexus    # Build nexus:dev (anywhere)
make docker-aegis    # Build aegis:dev (BF3 only)
```

### QA Validation Workflow

1. **Build packages**: Run `make packages` to build standard packages
2. **Install on test system**: Copy deb/rpm from `dist/` to target machine
3. **Verify installation**:
   ```bash
   sudo dpkg -i dist/sentry_*.deb
   systemctl status sentry
   journalctl -u sentry -f
   ```
4. **For DOCA packages**: Build natively on target platform, then test

### Version Override

By default, version comes from `git describe`. Override for testing:

```bash
VERSION=0.7.0-test make packages
```

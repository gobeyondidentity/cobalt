# Cobalt [![CI](https://github.com/gobeyondidentity/cobalt/actions/workflows/ci.yaml/badge.svg?branch=main)](https://github.com/gobeyondidentity/cobalt/actions/workflows/ci.yaml) [![Release](https://img.shields.io/github/v/release/gobeyondidentity/cobalt)](https://github.com/gobeyondidentity/cobalt/releases/latest) [![Go](https://img.shields.io/github/go-mod/go-version/gobeyondidentity/cobalt)](https://go.dev/) [![License](https://img.shields.io/github/license/gobeyondidentity/cobalt)](LICENSE)

<div align="center">
<br>
<img src="assets/cobalt-logo.svg?v=10" alt="Cobalt" width="200"/>
<br><br>
</div>

Cobalt is a credential lifecycle manager for GPU clusters that uses [NVIDIA BlueField DPUs](https://www.nvidia.com/en-us/networking/products/data-processing-unit/) as hardware trust anchors to automatically distribute, rotate, and revoke SSH certificates and signing keys across on-prem AI infrastructure without manual intervention.

---

* [Documentation](docs/)
* [CLI Reference](docs/reference/)
* [Tutorials](docs/guides/)
* [Changelog](CHANGELOG.md)
* [Demo](scripts/demo)

Cobalt provides several key features:

* **Zero Secret Sprawl**: Credentials are bound to specific hardware and die with the node. Reimaging a machine produces fresh credentials automatically, so there's nothing to hunt down or revoke manually.

* **No Network Configuration**: Host-to-DPU communication runs over native PCIe via DOCA ComCh. No VLANs, no firewall rules, no network plumbing between the trust anchor and the host it protects.

* **Health-Gated Distribution**: Credential operations only proceed when the target host passes posture checks (SecureBoot, disk encryption, OS version). A compromised or misconfigured node is automatically excluded.

* **Hardware Root of Trust**: Every API request is cryptographically bound to the caller's private key via DPoP (RFC 9449). Tokens can't be stolen and replayed from another machine.

* **Automation-Ready**: Structured output (`-o json`), idempotent commands, and meaningful exit codes make Cobalt a first-class citizen in CI/CD pipelines and infrastructure-as-code workflows.

* **Full Audit Trail**: Every credential push is logged with timestamp, operator identity, and target hardware. You get a complete chain of custody for compliance and incident response.

Quick Start
---

#### Emulator

The fastest way to try Cobalt. No hardware required. Follow the [Emulator Quickstart](docs/guides/quickstart-emulator.md) to walk through the full credential lifecycle in about 10 minutes.

#### Hardware

For production deployments on BlueField-3 DPUs, see the [Hardware Setup](docs/guides/setup-hardware.md) guide.

#### Demo

Run `./scripts/demo` to watch the full credential lifecycle in 2 minutes.

## Components

| Component | Description |
|-----------|-------------|
| `bluectl` | Admin CLI for DPU management, tenants, operators, and health checks |
| `km` | Operator CLI for SSH CA lifecycle and credential push |
| `nexus` | Control plane server |
| `sentry` | Host agent for credential receipt and posture reporting |
| `aegis` | DPU agent running on BlueField ARM cores |
| `dpuemu` | DPU emulator for local development |

## Documentation

| Guide | Description |
|-------|-------------|
| [Quickstart: Emulator](docs/guides/quickstart-emulator.md) | Get started without hardware |
| [Local Dev: Docker](docs/guides/local-dev-docker.md) | Run locally with Docker Compose |
| [Hardware Setup](docs/guides/setup-hardware.md) | Deploy on BlueField-3 DPU |
| [Encryption Keys](docs/reference/encryption-keys.md) | Key management internals |
| [Discovery](docs/guides/discovery.md) | Scan infrastructure for SSH keys |

## Installation

### macOS (Homebrew)

```bash
brew install nmelo/tap/bluectl nmelo/tap/km
```

### Linux

```bash
curl -1sLf 'https://raw.githubusercontent.com/gobeyondidentity/cobalt/main/scripts/install.sh' | sudo bash -s bluectl km
```

### From Source

```bash
git clone git@github.com:gobeyondidentity/cobalt.git && cd cobalt && make
```

## Contributing

See the [contributing guide](CONTRIBUTING.md) for developer documentation.

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.

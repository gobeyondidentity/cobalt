---
layout: post
title: "Project Cobalt v0.6.0: Astro"
date: 2026-01-20
author: Beyond Identity
---

Astro is our first public release. Two things blocked design partner pilots: installation friction and transport reliability. Astro fixes both.

## The Problem

Design partners told us the same thing: they couldn't evaluate software that required cloning a repo, installing Go, and running `make`. Security teams won't approve that. Competitors ship installers.

And tmfifo, the virtual serial interface we used for host-DPU communication, required manual IP configuration and had throughput limits. It worked for development but wasn't production-grade.

## What's New

### Install in One Command

```bash
# macOS
brew tap nmelo/tap && brew install bluectl km

# Debian/Ubuntu
sudo apt install bluectl km

# RHEL/Fedora
sudo yum install bluectl km
```

Binaries are available for macOS, Linux, and Windows. Container images are on ghcr.io. Docker Compose gets you a local control-plane in under a minute.

No more `go build`. No more PATH hacks. Install, configure, run.

### Native PCIe Communication

DOCA ComCh replaces tmfifo as the default transport between hosts and BlueField DPUs. The difference:

| | tmfifo | ComCh |
|---|---|---|
| Setup | Manual IP config | Zero config |
| Discovery | Manual PCI address | Automatic |
| Throughput | Limited | PCIe native |
| Resilience | Basic | Retry, backoff, circuit breaker |

ComCh uses NVIDIA's DOCA SDK to communicate directly over the PCIe fabric. No network interfaces to configure. No routing tables. The system finds BlueField devices automatically and handles connection failures gracefully.

Authentication happens on every connection using Ed25519 challenge-response. First enrollment uses trust-on-first-use (TOFU); subsequent connections verify against stored public keys.

The transport layer falls back automatically: ComCh first, then tmfifo, then network. Existing deployments keep working.

## Under the Hood

The ComCh implementation has 89.7% test coverage across 269 tests. We run hardware validation on self-hosted runners with actual BlueField-3 DPUs. The race detector caught a data race in tmfifo cleanup that only manifested under load.

Self-hosted ARM64 runners cut CI build times by 3x compared to GitHub's hosted runners. Cross-compilation for five platforms completes in under two minutes.

## Getting Started

If you have BlueField-3 DPUs:

```bash
brew install bluectl km
bluectl init
bluectl dpu add --name gpu-node-01 --address 192.168.1.100
```

If you want to try the emulator first:

```bash
brew install bluectl km
docker-compose up -d
bluectl init --emulator
```

The [quickstart guide](https://github.com/gobeyondidentity/secure-infra/blob/main/docs/guides/quickstart-emulator.md) walks through the full flow: create a tenant, register a DPU, set up operators, and push credentials to attested infrastructure.

## Known Limitations

A few things to know:

- **DOCA SDK required for ComCh**: Hosts need DOCA installed. Use `transport: tmfifo` as fallback otherwise.
- **BlueField-3 minimum**: ComCh requires BF3. BlueField-2 must use tmfifo.
- **Linux agents only**: The host-agent runs on Linux. CLI tools work everywhere.

## What's Next

v0.7.0 focuses on migration tooling. Batch rollout from SSH keys to CA certificates with rollback support. The goal: migrate a thousand-node cluster without downtime.

## Try It

Install the CLI, spin up the emulator, and run through the quickstart. If you're running BlueField infrastructure and want to talk about a pilot, reach out.

```bash
brew tap nmelo/tap && brew install bluectl km
bluectl version --check
```

We're building hardware-bound credential management for AI infrastructure. Astro is the foundation.

---

*Project Cobalt v0.6.0 "Astro" - January 2026*

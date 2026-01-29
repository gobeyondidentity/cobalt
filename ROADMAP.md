# Secure Infrastructure Roadmap

**Last Updated**: January 2026

---

## Shipped

### v0.1–v0.5
- Connect to BlueField DPUs, collect hardware health data
- Create SSH CAs, sign certificates, push to hosts
- Automatic health checks gate credential distribution to unhealthy hosts
- Discover existing SSH keys across hosts before migration

### v0.6 "Astro"
- DOCA ComCh transport (production-grade PCIe channel)
- TCP transport over tmfifo_net0 with proper disconnect detection
- Binary packaging (Homebrew, apt/yum, Docker images)
- Automated release infrastructure (GitHub Actions, self-hosted runners)
- Version check in CLI (`--check` flag)
- Server-only CLI (all commands require nexus connection)
- Operator and invite removal commands
- Aegis state persistence across restarts
- Integration test suite (enrollment, credentials, persistence)

---

## Next

### Rollout Tooling
- Batch rollout from SSH keys to CA certs with rollback
- Staged deployment with canary and percentage-based rollout
- Automated rollback on failure detection

### Credential Type Framework
- Template-based credential types with full lifecycle (create, rotate, revoke)
- CLI + config file authoring for custom types
- SSH remains built-in; mTLS client certs as first custom type

### Web Dashboard
- Next.js admin UI for tenant/DPU management

### Discovery Extensions
- MUNGE token discovery for HPC workloads
- NIXL mesh credentials for Dynamo KV cache transfers
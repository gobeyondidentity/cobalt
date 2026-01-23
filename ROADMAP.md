# Secure Infrastructure Roadmap

**Last Updated**: January 2026

---

## Shipped (v0.1–v0.6)

### v0.1–v0.5
- Connect to BlueField DPUs, collect hardware health data
- Create SSH CAs, sign certificates, push to hosts
- Automatic health checks gate credential distribution to unhealthy hosts
- Discover existing SSH keys across hosts before migration

### v0.6 "Astro"
- DOCA ComCh transport (replaces tmfifo with production-grade PCIe channel)
- Binary packaging (Homebrew, apt/yum, Docker images)
- Automated release infrastructure (GitHub Actions, self-hosted runners)
- Version check in CLI (`--check` flag)

---

## Next

| Version | Codename | Focus | Key Deliverable |
|---------|----------|-------|-----------------|
| v0.7 | Bender | Migration | Batch rollout from SSH keys to CA certs with rollback |
| v0.8 | Calculon | Credential Types | Template-based credential type framework with full lifecycle |

### v0.8 "Calculon" Direction

- Template-based credential types with full lifecycle (create, rotate, revoke)
- CLI + config file authoring for custom types
- SSH remains built-in; mTLS client certs as first custom type
- Proves extensibility pattern for future credential types

---

## Backlog

| Item | Description |
|------|-------------|
| Web Dashboard | Next.js admin UI for tenant/DPU management |
| MUNGE Token Discovery | Extend discovery to MUNGE credentials (HPC workloads) |
| Multi-Tenant Isolation | Namespace isolation for shared infrastructure |
| NIXL Mesh Credentials | Automated credentials for NIXL participation (Dynamo KV cache transfers) |

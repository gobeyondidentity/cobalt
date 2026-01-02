# Secure Infrastructure MVP - Suggestions

Improvement ideas captured during hands-on walkthrough. Will address after completing setup validation.

**Priority**: [HIGH] | [MED] | [LOW]

---

## UX / CLI

- [ ] Health endpoint at `/api/health` but docs/muscle memory expect `/health`. Consider adding root-level `/health` alias for convenience.
- [ ] `bluectl tenant` has `add`/`create` aliases but `remove` lacks a `delete` alias. Add for consistency.
- [ ] **[HIGH]** Cobra prints usage after business logic errors (e.g., "cannot remove tenant with assigned DPUs"). Set `SilenceUsage: true` on root command to suppress this for non-usage errors.
- [ ] Business logic errors should include actionable remediation commands. Example: "cannot remove tenant with 2 assigned DPUs" should suggest `bluectl tenant unassign <dpu>` or `bluectl dpu list --tenant <name>` to see what needs unassigning.
- [ ] `bluectl tenant remove` fails with cryptic "FOREIGN KEY constraint failed" when other entities reference the tenant (operators, CAs, trust relationships, distribution history). Need to check all dependencies upfront and report what's blocking deletion.
- [ ] Re-evaluate database location `~/.local/share/bluectl/dpus.db`. API server data shouldn't live in a user-specific CLI directory. Consider `/var/lib/fabric-console/` for server, keep CLI config separate.
- [ ] Add `describe` alias for `bluectl tenant show`. Also enhance `show` to include counts: DPUs, hosts, operators, CAs, trust relationships.
- [ ] Remove redundant `bluectl tenant assign-dpu`. `assign` already implies DPU in tenant context.
- [ ] Aliases (`add`/`create`, `remove`/`delete`) show as separate commands in help. Use Cobra's `Aliases` field instead so only primary command appears in help while alias still works.
- [ ] `bluectl dpu add` needs better help: clarify what "host" means (BMC IP? rshim? OOB management?), supported connection methods, examples.
- [ ] `bluectl dpu add` should warn if adding a DPU that points to the same address:port as an existing one. Currently allows duplicates silently.
- [ ] `bluectl dpu add` health check should verify identity: show the DPU's self-reported name/serial from the agent, so user can confirm they connected to the right device.
- [ ] `bluectl dpu add` should fail by default if it can't connect to the DPU agent. Add `--offline` flag to skip connectivity check and add anyway. Currently adds first then warns, which is confusing.
- [ ] **[HIGH]** `bluectl dpu add` success message should hint next step: "Next: Assign to a tenant with `bluectl tenant assign <tenant> <dpu-name>`".
- [ ] `bluectl dpu list` shows cached status, not live. Users expect current state. Either: (1) do live health check on list (may be slow for many DPUs), (2) add `--check` flag for live status, or (3) run background health checks periodically and update status. At minimum, clarify that status is from "LAST SEEN" time.
- [ ] `bluectl dpu add` should use MAC address as default name. Connect to DPU agent, query MAC, use as identifier. Allow `--name` flag to override. Simplifies: `bluectl dpu add 192.168.1.204` instead of `bluectl dpu add bf3-lab-01 192.168.1.204`.
- [ ] Add `bluectl dpu assign <dpu> --tenant <tenant>` as alias for `bluectl tenant assign`. Users think "assign DPU to tenant" not "tenant assign DPU".
- [ ] Timestamps in CLI output are hard to read (`2026-01-02T09:52:13-05:00`). Use relative times ("2m ago") for recent, human-friendly ("Jan 2, 09:52") for older. Applies to tables and show/describe output. Keep ISO format for `-o json`.
- [ ] Reorganize CLI: `health`, `flows`, `attestation` should be subcommands under `bluectl dpu` (e.g., `bluectl dpu health <name>`), not top-level commands. Reduces clutter, groups related functionality.
- [ ] Command descriptions need more context for users unfamiliar with domain terms. E.g., "corim - CoRIM validation commands" doesn't help. Better: "corim - Validate firmware integrity using reference manifests (CoRIM)". Same for attestation, flows, etc.
- [ ] `bluectl completion` should show copy-paste ready instructions for each shell. E.g., `bluectl completion zsh` should print: "# Add to ~/.zshrc:\necho 'source <(bluectl completion zsh)' >> ~/.zshrc". Like Tailscale/kubectl do.
- [ ] `bluectl operator` help should explain what an operator is: "Operators are authorized users who can distribute SSH CA credentials to DPUs. Admins invite operators, who then use the km CLI to manage credentials."
- [ ] **[HIGH]** `bluectl operator invite` has inconsistent args: email is positional, tenant is required flag. Both required = both should be positional: `bluectl operator invite <email> <tenant>`.
- [ ] `bluectl operator invite` output should include km installation instructions: where to download, or `curl -fsSL .../install-km.sh | sh`. Admin needs to tell operator how to get started.
- [ ] `km init` should have `--force` flag to re-initialize instead of telling user to manually delete config file. Also silence usage on this error (business logic, not usage error).
- [ ] **[HIGH]** `km init` success should show next steps: "Next: Run `km whoami` to verify, or `km ssh-ca create --name <name>` to create your first CA."
- [ ] "Control Plane" is internal jargon. In `km whoami` and elsewhere, use "Server" or "API" instead. Operators don't need to know architecture terms.
- [ ] **[HIGH]** Empty state hints should show complete commands. `km ssh-ca list` says "Use 'km ssh-ca create'" but that fails without `--name`. Show: "Use 'km ssh-ca create <name>'".
- [ ] **[HIGH]** `km ssh-ca create --name` should be positional: `km ssh-ca create <name>`. Required args shouldn't be flags.
- [ ] Add `describe` alias for `show` commands across all CLIs (`km ssh-ca describe`, `bluectl tenant describe`, etc.). Consistent with kubectl conventions.
- [ ] ID format (`ca_926810b3`, `op_a1236dc1`) is obtuse. Consider: hide IDs from users entirely (use names as primary identifiers), or use friendlier formats (ULIDs, shorter hashes, or human-readable slugs).
- [ ] `km whoami` authorizations show cryptic IDs (`ca_926810b3`, `35f5d16d`). Should show names: "CA: test-ca, Devices: bf-lab". IDs mean nothing to operators.
- [ ] `km whoami` shows internal IDs (KeyMaker ID, Operator ID) by default. Hide these unless `--verbose`. Default output should be: email, server, authorizations (with names, not IDs).
- [ ] `km history` output is confusing: (1) "ATTESTATION" column shows "14m", "1m", "none" - what does this mean? Should say "age" or explain in header; (2) "RESULT" values (forced, success, blocked) need legend or clearer names; (3) Add `--verbose` to show why blocked/forced. Consider renaming column to "ATTESTATION AGE" or adding footnotes.
- [ ] `bluectl operator list` lacks detail. Add columns: TENANT, ROLE, LAST ACTIVITY, or at least show count of authorizations. Current output (email, status, created) is minimal.
- [ ] `bluectl tenant list` shows empty columns (DESCRIPTION, CONTACT) as blank. Show `<empty>` or `-` placeholder instead of blank. Good that TAGS exists - expand tagging support across all entities (DPUs, operators, CAs, hosts).
- [ ] `km ssh-ca show` should explain key storage. Add field like "Private Key: Hardware-protected (TPM 2.0)" or "Private Key: Software (encrypted)". Operators need to understand where keys live and how they're protected. Builds trust in security model.
- [ ] `km` help text only mentions SSH CAs. Should describe all credential types. Add parallel commands: `km tls-ca`, `km munge`, `km api-key`, etc.
- [ ] `km` description is too vague: "credential management" doesn't explain what or why. Better: "km securely pushes SSH CAs, TLS certificates, and API keys to DPUs and hosts. Credentials are hardware-protected and require device attestation before push."
- [ ] `km init` description too vague. Better: "Set up operator identity using invite code. Generates keypair, registers with server, and saves config to ~/.km/".
- [x] ~~`km distribute` description too vague.~~ DONE: Renamed to `km push` per ADR-006. Description updated.
- [ ] `km history` description too vague. Better: "View your distribution history: what you pushed, to which devices, and whether attestation passed."
- [ ] Add `bluectl distribution history` for admin view of all distributions across all operators. `km history` is operator's personal view; admins need fleet-wide audit trail.
- [x] ~~"distribute" is unnatural jargon.~~ DONE: Renamed to `km push` per ADR-006.
- [x] ~~**[HIGH]** `km distribute ssh-ca --target` should be positional.~~ DONE: Now `km push ssh-ca <ca-name> <target>`. Already positional.
- [ ] **[HIGH]** After `km init`, operator should see what they can do: "You have access to 0 CAs and 0 devices. Ask your admin to grant access." Or `km status` showing current permissions.
- [ ] **[HIGH]** `bluectl operator grant` has too many required flags. Should be positional: `bluectl operator grant <email> <ca> <devices>`. Tenant could be inferred from operator's membership.
- [ ] **[HIGH]** `bluectl trust create` required flags should be positional: `bluectl trust create <source> <target>` instead of `--source` and `--target` flags.
- [ ] `bluectl trust create` should have `--force` flag to bypass attestation check (like `km push --force`). Currently no way to create trust without fresh attestation.
- [ ] **[HIGH]** `bluectl trust create` success should hint next steps and explain what trust enables. E.g., "Trust created. The source DPU can now SSH to the target using CA-signed certificates. Next: Run `km push ssh-ca <ca> <target>` to push credentials."
- [ ] **[HIGH]** `host-agent` required flags should be positional: `host-agent <control-plane-url> <dpu-name>` instead of `host-agent --control-plane <url> --dpu <name>`.

## Security

- [ ] **Secure by default violation**: "SECURE_INFRA_KEY not set" warning appears on many commands (`km ssh-ca`, `bluectl operator grant`, etc.) and silently falls back to plaintext keys. Should: (1) attempt secure setup first, (2) if unavailable, explicitly prompt user "Encryption key not configured. Proceed with plaintext keys? (y/N)", (3) require `--insecure` flag or explicit consent. No silent downgrades. Fix system-wide, not per-command.
- [ ] Support ACME CA for mTLS between components (CLI<->API, API<->agents). API should auto-generate internal CA by default; users can bring their own. All internal traffic should be encrypted/authenticated.
- [ ] Same for SSH CA: system should auto-generate default SSH CA for DPU access; users can bring their own. Reduces setup friction while maintaining security.

## API / Backend

- [ ] DPU agent health check fails because agent doesn't implement `grpc.health.v1.Health` service. Either add standard gRPC health service or change bluectl to use a method on `DPUAgentService` (e.g., `GetSystemInfo`).
- [ ] DPU agent should log incoming connection attempts and RPC calls. Currently silent even when health check fails - no visibility into what's happening. dpuemu logs these, but the real agent doesn't.
- [ ] API server has no request logging. All operations (tenant create, DPU register, etc.) are silent. Add structured logging for requests, operations, and errors. Consider log levels (debug/info/warn/error).
- [ ] **Architecture**: `bluectl` operates directly on local SQLite DB, not through API server. This means: no audit trail in API, can't administer remotely, DB access split between two processes. Consider making bluectl a pure API client with `--api-url` flag.
- [ ] **User Story**: As an operator, when a DPU shows "unhealthy", I want to investigate why. Need `bluectl dpu diagnose <name>` or `bluectl dpu health <name> --verbose` that shows: last error, connection attempts, latency, what health checks failed and why.
- [ ] Add `bluectl host health <name>` to check host-agent connectivity. Currently no way to verify host-agent is reachable from control plane.
- [ ] Host-agent should log incoming requests like dpuemu does. Currently silent.

## Documentation

(none yet)

## Architecture

- [ ] **Design question**: Who triggers attestation? Current: admin manually runs `bluectl attestation`. Alternative: `km push` auto-triggers attestation if stale/missing. Trade-offs: (1) manual = admin controls when devices are verified, (2) auto = smoother operator UX but may bypass admin oversight. Need architect decision.
- [ ] **Setup gap**: `km push ssh-ca` fails with "host SSH not configured" if DPU agent isn't set up for SSH. Agent needs `HOST_SSH_ADDR`, `HOST_SSH_USER`, `HOST_SSH_KEY` env vars. Need: (1) document in setup guide including SSH key setup from DPU to host, (2) clearer error message showing which env vars to set, (3) consider agent flags instead of env vars for discoverability.
- [ ] **Conceptual gap**: DPU vs Host relationship not explained. Operators think they're managing a "device" but then see "host SSH" errors. Need to explain upfront: DPU is a card inside a host server; agent runs on DPU; credentials get pushed to the host. Add architecture diagram or explanation in docs and CLI help.
- [ ] **Setup gap**: Attestation shows "unavailable" on real hardware - no TPM/attestation configured. Document how to set up attestation on BlueField (NVIDIA Attestation SDK, SPDM measurements). For testing, provide mock/dev mode.
- [ ] **Attestation UX confusion**: (1) `bluectl attestation` says "UNAVAILABLE" but "Attestation saved" - contradictory; (2) `km push` says "stale (1m ago)" for same device - status terminology inconsistent; (3) "No certificates available" doesn't say WHICH certificates (TPM? attestation?). Clarify terminology and make status consistent across commands.
- [ ] **[HIGH] Architecture rethink**: Why does DPU agent SSH into host to push credentials? Host-agent already exists but is push-only (reports posture). Better flow: extend host-agent to listen for credential push requests, install SSH CAs, configure sshd. Eliminates SSH key setup complexity, cleaner separation. DPU agent handles DPU tasks; host-agent handles host tasks.
- [ ] **Host agent enrollment**: How does host-agent get authorized to receive credentials? Need enrollment flow similar to `km init` for operators. Consider: invite code, mTLS with auto-provisioned certs, or trust-on-first-use tied to DPU attestation. Explore tmfifo as secure pipe between DPU and host for enrollment/credential push.
- [ ] **Host agent as SSH agent**: Consider making host-agent act as an SSH agent (like ssh-agent). Could manage SSH keys/certs in-memory, integrate with sshd via AuthorizedKeysCommand, avoid writing keys to disk. Cleaner security model.
- [x] ~~`km distribute` success output should show details.~~ DONE: `km push` now shows installed path and sshd reload status per ADR-006.
- [ ] Document that SSH CA trust enables machine-to-machine (M2M) communication, not just human SSH access. Workloads can authenticate to each other using CA-signed certificates. Important for HPC/AI pipelines. Surface this in CLI help and docs.
- [ ] Add `km ssh-ca test <ca-name> <host>` to verify push worked. Signs a temp cert, attempts SSH connection, reports success/failure. Hint to use this after `km push` succeeds.

## Testing

(none yet)

## Operational

- [ ] `dpuemu serve` requires `--fixture` flag with no default. Should either: (1) embed a default fixture and make flag optional, (2) generate a minimal fixture automatically, or (3) provide example fixtures in a well-known location. Current UX forces users to hunt for fixture files.
- [ ] `dpuemu` with no subcommand should show usage hints: "Quick start: dpuemu serve --fixture <path>". Current output just lists subcommands with no guidance.
- [ ] `--listen :50052` format is unintuitive. Use `--port 50052` instead, or accept both `50052` and `:50052` for the listen flag.
- [ ] `dpuemu` logs "HealthCheck called" but not the result. Should log: "HealthCheck called: status=SERVING" or similar.
- [ ] Add a Makefile or build script (`make all`, `make dpu-agent`) instead of listing individual go build commands. Simplifies onboarding and ensures ARM64 cross-compile is included.
- [ ] Create Tailscale-style install script for DPU agent (`curl -fsSL .../install.sh | sh`). Should detect arch, download binary, install to /usr/local/bin, create systemd service, and prompt for control plane URL.
- [ ] Same for host-agent: Tailscale-style install script. Detect arch, download, install, create systemd service, prompt for control plane URL and DPU name to pair with.
- [ ] Document firewall requirements for DPU agent (port 50051/tcp). Install script should check/configure ufw if present.

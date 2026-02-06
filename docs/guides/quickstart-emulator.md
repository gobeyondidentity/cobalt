# Quickstart: DPU Emulator

Run Project Cobalt locally using an emulated DPU instead of real hardware. By the end, you'll automate SSH CA distribution without manual key copying or authorized_keys management.

**What's a DPU?** A Data Processing Unit is a SmartNIC that handles credential distribution automatically. In production, it verifies host health before delivering credentials, eliminating manual rotation and key sprawl.

Good for: learning the system, CI/CD pipelines, product evaluation.

Starting over? See [Clean Slate](#appendix-a-clean-slate) to reset your environment.

## Prerequisites

Choose your installation method:

### Option A: Install via Package Manager (Recommended)

**macOS (Homebrew):**
```bash
brew tap nmelo/tap
brew install nmelo/tap/bluectl nmelo/tap/km nmelo/tap/nexus nmelo/tap/dpuemu nmelo/tap/sentry
```

**Linux (Debian/Ubuntu):**
```bash
# Set up repository and install packages
curl -1sLf 'https://raw.githubusercontent.com/gobeyondidentity/cobalt/main/scripts/install.sh' | sudo bash -s bluectl km nexus dpuemu sentry
```

Skip to [Terminal Setup](#terminal-setup) after installing.

### Option B: Build from Source

Requires Go 1.22+ and Make. See [Clone and Build](#clone-and-build).

## Terminal Setup

This guide uses three terminal windows. The server and emulator are long-running processes that need their own terminals.

| Terminal | Purpose | Runs |
|----------|---------|------|
| Terminal 1 | Server | `nexus` or `bin/server` (Step 1) |
| Terminal 2 | Emulator | `dpuemu` or `bin/dpuemu` (Step 3) |
| Terminal 3 | Commands | All other commands |

Open all three now. If you installed via package manager, skip to Step 1. If building from source, run clone/build in Terminal 3 first.

## Clone and Build

*Skip this section if you installed via package manager.*

```bash
git clone https://github.com/gobeyondidentity/cobalt.git
cd secure-infra
make
# Expected:
# Building all binaries...
#   bin/aegis
#   bin/bluectl
#   bin/km
#   bin/nexus
#   bin/sentry
#   bin/dpuemu
# Done.
```

**Note:** When building from source, use `bin/` prefix for all commands (e.g., `bin/bluectl` instead of `bluectl`).

## Step 1: Start the Server

The server (nexus) is your control plane. It tracks which DPUs exist, whether they've passed health checks, and who is authorized to push credentials to them. Without it, nothing else works.

In Terminal 1:

```bash
nexus              # if installed via package manager
# or: bin/server   # if built from source

# Expected:
# Fabric Console API v0.6.3 starting...
# HTTP server listening on :18080
```

**macOS:** You may see a syslog connection warning on startup. This is expected; macOS uses a different syslog socket path. Audit events fall back to SQLite storage and the server operates normally.

In Terminal 3, verify it's running:

```bash
curl http://localhost:18080/health
# Expected: {"status":"ok","version":"0.6.3"}
```

---

## Step 2: Create a Tenant

Tenants are organizational boundaries, like teams or environments. Every DPU and operator belongs to exactly one tenant. This keeps production separate from staging, or one team's infrastructure separate from another's.

In Terminal 3:

```bash
bluectl tenant add gpu-prod --description "GPU Production Cluster"
# or: bin/bluectl tenant add gpu-prod --description "GPU Production Cluster"

# Expected: Created tenant 'gpu-prod'.
```

---

## Step 3: Start the DPU Emulator

The emulator simulates a BlueField DPU with mock health check data. The DPU automatically verifies that hardware is healthy and running expected firmware. You'll see this in action in Step 7.

The fixture file defines the emulated DPU's identity: serial number, model, and certificate chain.

In Terminal 2:

```bash
dpuemu serve              # if installed via package manager (uses built-in fixture)
# or: bin/dpuemu serve --fixture dpuemu/fixtures/bf3-static.json   # if built from source

# Expected:
# Loading fixture...
# dpuemu gRPC server listening on :18051
# emulating: bluefield3 (serial: MT2542600N23)
# dpuemu local API listening on :9443
```

Leave this running.

---

## Step 4: Register the Emulated DPU

The server needs to know about each DPU before it can track health status or authorize credential distribution. Registration connects the running emulator to the control plane.

```bash
bluectl dpu add localhost --name bf3
# Expected:
# Checking connectivity to localhost:18051...
# Connected to DPU:
#   Hostname: bluefield3
#   Serial:   MT2542600N23
# Added DPU 'bf3' at localhost:18051.
#
# Next: Assign to a tenant with 'bluectl tenant assign <tenant> bf3'
```

The CLI verifies connectivity and retrieves DPU details from the emulator.

---

## Step 5: Assign DPU to Tenant

Link the DPU to the tenant you created in Step 2. This controls which operators can access the device.

```bash
bluectl tenant assign gpu-prod bf3
# Expected: Assigned DPU 'bf3' to tenant 'gpu-prod'
```

---

## Step 6: Create Operator Invitation

Admins manage infrastructure (DPUs, tenants, access grants). Operators push credentials (SSH CAs, certificates) to attested devices. This separation creates an audit trail.

In production, an admin and operator would be different people. Here you're playing both roles.

```bash
bluectl operator invite operator@example.com gpu-prod
# Expected:
# Invite created for operator@example.com
# Code: GPU-XXXX-XXXX
# Expires: <24 hours from now>
#
# Share this code with the operator. They will need to:
#   1. Run: km init
#   2. Enter the invite code when prompted
```

Save the invite code for the next step.

---

## Step 7: Accept Operator Invitation

```bash
km init
# Enter the invite code when prompted
# Expected:
# Generating keypair...
# Binding to server...
#
# Bound successfully.
#   Operator: operator@example.com
#   Tenant: gpu-prod (operator)
#   KeyMaker: km-<platform>-operator-<id>
#
# Next steps:
#   Run 'km whoami' to verify your identity.

km whoami
# Expected:
# Operator: operator@example.com
# Server:   http://localhost:18080
#
# Authorizations: none
```

"Authorizations: none" is expected. You'll grant access in the next step.

---

## Step 8: Create SSH CA

An SSH CA signs short-lived certificates instead of scattering static keys across servers. No more authorized_keys file management; certificates expire automatically and don't need to be revoked.

```bash
km ssh-ca create test-ca
# Expected: SSH CA 'test-ca' created.
```

---

## Step 9: Grant CA Access

Link the operator to specific CAs and devices. Without this grant, the operator can create CAs but can't push them anywhere.

```bash
bluectl operator grant operator@example.com gpu-prod test-ca bf3
# Expected:
# Authorization granted:
#   Operator: operator@example.com
#   Tenant:   gpu-prod
#   CA:       test-ca
#   Devices:  bf3
```

---

## Step 10: Submit Attestation

The DPU confirms it's running expected firmware before credentials can be distributed. The emulator provides mock health data for this step.

```bash
bluectl attestation bf3
# Expected:
# Attestation Status: ATTESTATION_STATUS_VALID
#
# Certificate Chain:
# LEVEL  SUBJECT                         ISSUER                ALGORITHM     VALID UNTIL
# L0     SERIALNUMBER=5C49421FED63EA...  SERIALNUMBER=4E66...  ECDSA-SHA384  9999-12-31T23:59:59Z
# L1     SERIALNUMBER=4E6655514E870B...  SERIALNUMBER=4B07...  ECDSA-SHA384  9999-12-31T23:59:59Z
# L2     SERIALNUMBER=4B070AC0363900...  SERIALNUMBER=7042...  ECDSA-SHA384  9999-12-31T23:59:59Z
# L3     SERIALNUMBER=7042F3D1DC1B48...  CN=NVIDIA BF3 Ide...  ECDSA-SHA384  9999-12-31T23:59:59Z
# L4     CN=NVIDIA BF3 Identity,O=NV...  CN=NVIDIA Device ...  ECDSA-SHA384  9999-12-31T23:59:59Z
# L5     CN=NVIDIA Device Identity C...  CN=NVIDIA Device ...  ECDSA-SHA384  9999-12-31T23:59:59Z
#
# Attestation saved: status=verified, last_validated=<timestamp>
```

---

## Step 11: Distribute Credentials

This is the payoff for automation. The system verifies the host is healthy before pushing credentials. If the DPU fails health checks, distribution pauses automatically until the issue is resolved.

```bash
km push ssh-ca test-ca bf3
# Expected:
# Pushing CA 'test-ca' to bf3...
#   Attestation: verified (<time> ago)
#
# CA installed at /etc/ssh/trusted-user-ca-keys.d/test-ca.pub
# sshd reloaded.
```

With the emulator, credentials are stored locally. On real hardware, they'd be pushed to the host via the DPU.

---

## Step 12: Test Host Agent (Optional)

In production, the host agent (sentry) runs on each server and receives credentials from the DPU over a secure channel (ComCh or tmfifo). It also reports the host's security posture.

With the emulator, sentry connects via HTTP instead of hardware channels.

```bash
sentry --dpu-agent http://localhost:9443 --oneshot
# or: bin/sentry --dpu-agent http://localhost:9443 --oneshot   # if built from source

# Expected:
# Sentry v0.6.3 starting...
# Initial posture collected: hash=<hash>
# No ComCh/tmfifo detected. Using network enrollment.
# DPU Agent: http://localhost:9443
# Hostname: <your-hostname>
# Paired with DPU: bluefield3
# Registered as host <host_id> via DPU Agent
# Oneshot mode: exiting after successful registration
```

---

## Step 13: Sign a User Certificate

Everything you've built leads to this: signing short-lived certificates that grant SSH access without managing authorized_keys files across your fleet.

Generate a test SSH key (or use your existing one):

```bash
ssh-keygen -t ed25519 -f /tmp/demo_key -N "" -C "demo@example.com"
# Expected:
# Generating public/private ed25519 key pair.
# Your identification has been saved in /tmp/demo_key
# Your public key has been saved in /tmp/demo_key.pub
```

Sign the public key with your CA:

```bash
km ssh-ca sign test-ca --principal ubuntu --pubkey /tmp/demo_key.pub > /tmp/demo_key-cert.pub
```

The certificate grants the `ubuntu` principal SSH access for 8 hours (default). Any server trusting this CA will accept this certificate.

Inspect what you created:

```bash
ssh-keygen -L -f /tmp/demo_key-cert.pub
# Expected:
# /tmp/demo_key-cert.pub:
#         Type: ssh-ed25519-cert-v01@openssh.com user certificate
#         Public key: ED25519-CERT SHA256:<fingerprint>
#         Signing CA: ED25519 SHA256:<ca-fingerprint> (using ssh-ed25519)
#         Key ID: "demo@example.com"
#         Serial: <serial>
#         Valid: from <start> to <end>
#         Principals:
#                 ubuntu
#         Critical Options: (none)
#         Extensions:
#                 permit-pty
```

**In production**, you'd SSH to hosts using this certificate:

```bash
ssh -i /tmp/demo_key ubuntu@<host-ip>
```

The host verifies the certificate was signed by a CA it trusts. No public key distribution, no authorized_keys management, automatic expiration.

Clean up the demo key:

```bash
rm /tmp/demo_key /tmp/demo_key.pub /tmp/demo_key-cert.pub
```

---

## What's Next?

You've automated the full credential lifecycle:

1. **Infrastructure** - Server, tenant, and DPU registration
2. **Identity** - Operator authentication and authorization grants
3. **Verification** - Automatic health checks before credential distribution
4. **Distribution** - CA pushed to the host without manual file copying
5. **Usage** - Short-lived certificates that expire automatically

The emulator demonstrates the workflow but doesn't show hardware-specific features: real attestation chains, PCIe credential delivery, or host posture from actual TPMs.

**Next steps:**

- [SSH Key Discovery](discovery.md) - Audit existing keys before migrating to certificates
- [Hardware Setup Guide](setup-hardware.md) - Deploy with real BlueField DPUs

---

## Troubleshooting

| Error | Cause | Fix |
|-------|-------|-----|
| `address already in use` | Port 18080 or 18051 busy | Kill existing process or use different port |
| `UNIQUE constraint failed` | Stale data from previous run | See [Clean Slate](#appendix-a-clean-slate) |
| `not authorized to access CA` | Grant not applied | Re-run `bluectl operator grant ...` |
| `connection refused` | Server or emulator not running | Check Terminals 1 and 2 |
| `KeyMaker already initialized` | km was previously set up | Run `rm -rf ~/.km` then retry |
| `invite code invalid or expired` | Code typo or expired (24h) | Create new invite with `bluectl operator invite` |

For encryption key issues (CI/CD, multi-machine setups), see [Encryption Key Management](../reference/encryption-keys.md).

---

## Appendix A: Clean Slate

To reset and start fresh:

1. **Stop the server and emulator** (Ctrl+C in Terminals 1 and 2)

2. **Verify they're stopped:**
```bash
ps aux | grep -E "nexus|dpuemu|bin/server" | grep -v grep
# Expected: no output
```

If processes are still running, kill them:
```bash
pkill -f "nexus" && pkill -f "dpuemu"
# or if built from source:
pkill -f "bin/server" && pkill -f "bin/dpuemu"
```

3. **Delete state files:**
```bash
rm -f ~/.local/share/nexus/nexus.db
rm -f ~/.local/share/bluectl/key
rm -rf ~/.km
```

4. **Restart server and emulator** (Steps 1 and 3)

The server caches data in memory, so you must stop it before deleting the database.

---

## Appendix B: Shell Completion

```bash
# Zsh
echo 'source <(bluectl completion zsh)' >> ~/.zshrc
echo 'source <(km completion zsh)' >> ~/.zshrc
source ~/.zshrc

# Bash
echo 'source <(bluectl completion bash)' >> ~/.bashrc
echo 'source <(km completion bash)' >> ~/.bashrc
source ~/.bashrc
```

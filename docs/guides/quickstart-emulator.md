# Quickstart: DPU Emulator

Get Secure Infrastructure running locally without hardware. DPUs (Data Processing Units) are SmartNICs that act as hardware trust anchors for your infrastructure. This guide uses an emulator so you can learn the system without physical hardware.

Use this to learn the system, run CI/CD pipelines, or evaluate the product.

Starting over? See [Clean Slate](#appendix-a-clean-slate) to reset your environment.

## Prerequisites

- Go 1.22+
- Make

## Terminal Setup

This guide uses three terminal windows. The server and emulator are long-running processes that need their own terminals.

| Terminal | Purpose | Runs |
|----------|---------|------|
| Terminal 1 | Server | `bin/server` (Step 1) |
| Terminal 2 | Emulator | `bin/dpuemu` (Step 3) |
| Terminal 3 | Commands | All other commands |

Open all three now. Run clone/build in Terminal 3, then follow along.

## Clone and Build

```bash
git clone https://github.com/gobeyondidentity/secure-infra.git
cd secure-infra
make
# Expected:
# Building all binaries...
#   bin/agent
#   bin/bluectl
#   bin/km
#   bin/server
#   bin/host-agent
#   bin/dpuemu
# Done.
```

## Step 1: Start the Server

The server is your control plane. It tracks which DPUs exist, whether they've passed attestation, and who is authorized to push credentials to them. Without it, nothing else works.

In Terminal 1:

```bash
bin/server
# Expected: Fabric Console API v0.4.1 starting...
# Expected: HTTP server listening on :18080
```

In Terminal 3, verify it's running:

```bash
curl http://localhost:18080/api/health
# Expected: {"status":"ok","version":"0.4.1"}
```

---

## Step 2: Create a Tenant

Tenants are organizational boundaries, like teams or environments. Every DPU and operator belongs to exactly one tenant. This keeps production separate from staging, or one team's infrastructure separate from another's.

In Terminal 3:

```bash
bin/bluectl tenant add gpu-prod --description "GPU Production Cluster"
# Expected: Created tenant 'gpu-prod'.
```

---

## Step 3: Start the DPU Emulator

The emulator simulates a BlueField DPU with mock attestation data. Attestation is cryptographic proof that hardware is genuine and running trusted firmware. You'll see this in action in Step 7.

The fixture file defines the emulated DPU's identity: serial number, model, and certificate chain.

In Terminal 2:

```bash
bin/dpuemu serve --port 50051 --fixture dpuemu/fixtures/bf3-static.json
# Expected:
# Loading fixture from dpuemu/fixtures/bf3-static.json
# dpuemu gRPC server listening on :50051
# emulating: bluefield3 (serial: MT2542600N23)
# dpuemu local API listening on :9443
```

Leave this running.

---

## Step 4: Register the Emulated DPU

The server needs to know about each DPU before it can track attestation status or authorize credential distribution. Registration connects the running emulator to the control plane.

```bash
bin/bluectl dpu add localhost --name bf3
# Expected:
# Checking connectivity to localhost:50051...
# Connected to DPU:
#   Hostname: bluefield3
#   Serial:   MT2542600N23
# Added DPU 'bf3' at localhost:50051.
#
# Next: Assign to a tenant with 'bluectl tenant assign <tenant> bf3'

bin/bluectl tenant assign gpu-prod bf3
# Expected: Assigned DPU 'bf3' to tenant 'gpu-prod'
```

The CLI verifies connectivity and shows DPU details. The `Next:` hint tells you what to do next.

---

## Step 5: Create an Operator

Admins manage infrastructure (DPUs, tenants, access grants). Operators push credentials (SSH CAs, certificates) to attested devices. This separation creates an audit trail: you can see who pushed what, when, and to which devices.

In production, an admin and operator would be different people. Here you're playing both roles.

### 5a: Create invitation (as admin)

```bash
bin/bluectl operator invite operator@example.com gpu-prod
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

### 5b: Accept invitation (as operator)

```bash
bin/km init
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

bin/km whoami
# Expected:
# Operator: operator@example.com
# Server:   http://localhost:18080
#
# Authorizations: none
```

"Authorizations: none" is expected. You'll grant access in the next step.

---

## Step 6: Create SSH CA and Grant Access

### 6a: Create CA (as operator)

An SSH CA signs short-lived certificates instead of scattering static keys across servers. In this system, the CA's private key lives on the DPU. It can only sign certificates when attestation passes, so a compromised host can't mint valid credentials.

```bash
bin/km ssh-ca create test-ca
# Expected: SSH CA 'test-ca' created.
```

### 6b: Grant access (as admin)

The grant links an operator to specific CAs and devices. Without it, the operator can create CAs but can't push them anywhere.

```bash
bin/bluectl operator grant operator@example.com gpu-prod test-ca bf3
# Expected:
# Authorization granted:
#   Operator: operator@example.com
#   Tenant:   gpu-prod
#   CA:       test-ca
#   Devices:  bf3
```

---

## Step 7: Submit Attestation

The DPU must prove it's running trusted firmware before receiving credentials. The emulator provides mock attestation.

```bash
bin/bluectl attestation bf3
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

## Step 8: Distribute Credentials

This is the core security moment. The system checks that attestation is valid before allowing the push. If the DPU had failed attestation, this command would be rejected.

```bash
bin/km push ssh-ca test-ca bf3
# Expected:
# Pushing CA 'test-ca' to bf3...
#   Attestation: verified (<time> ago)
#
# CA installed at /etc/ssh/trusted-user-ca-keys.d/test-ca.pub
# sshd reloaded.
```

With the emulator, credentials are stored locally. On real hardware, they'd be pushed to the host via the DPU.

---

## Step 9: Test Host Agent (Optional)

In production, the host agent runs on each server and receives credentials from the DPU over a secure channel (tmfifo). It also reports the host's security posture.

With the emulator, the host agent connects via HTTP instead of tmfifo.

```bash
bin/host-agent --dpu-agent http://localhost:9443 --oneshot
# Expected:
# Host Agent v0.4.1 starting...
# Initial posture collected: hash=<hash>
# No tmfifo detected. Using network enrollment.
# DPU Agent: http://localhost:9443
# Hostname: <your-hostname>
# Paired with DPU: bluefield3
# Registered as host <host_id> via DPU Agent
# Oneshot mode: exiting after successful registration
```

---

## What's Next?

You've completed the emulator quickstart. You learned:

- How tenants organize infrastructure
- The admin/operator separation and audit trail
- SSH CA creation and authorization grants
- Attestation as a gate for credential distribution

The emulator covers the full workflow but can't demonstrate hardware-specific features: real DICE attestation chains, tmfifo credential delivery, or host posture from actual TPMs.

When you're ready for production, see [Hardware Setup Guide](setup-hardware.md).

---

## Troubleshooting

| Error | Cause | Fix |
|-------|-------|-----|
| `address already in use` | Port 18080 or 50051 busy | Kill existing process or use different port |
| `UNIQUE constraint failed` | Stale data from previous run | See [Clean Slate](#appendix-a-clean-slate) |
| `not authorized to access CA` | Grant not applied | Re-run `bluectl operator grant ...` |
| `connection refused` | Server or emulator not running | Check Terminals 1 and 2 |
| `KeyMaker already initialized` | km was previously set up | Run `rm -rf ~/.km` then retry |
| `invite code invalid or expired` | Code typo or expired (24h) | Create new invite with `bluectl operator invite` |

For encryption key issues (CI/CD, multi-machine setups), see [Encryption Key Management](../reference/encryption-keys.md).

---

## Appendix A: Clean Slate

To reset and start fresh:

```bash
# Remove server database
rm -f ~/.local/share/bluectl/dpus.db

# Remove km configuration (if initialized)
rm -rf ~/.km
```

---

## Appendix B: Shell Completion

```bash
# Zsh
echo 'source <(bin/bluectl completion zsh)' >> ~/.zshrc
echo 'source <(bin/km completion zsh)' >> ~/.zshrc
source ~/.zshrc

# Bash
echo 'source <(bin/bluectl completion bash)' >> ~/.bashrc
echo 'source <(bin/km completion bash)' >> ~/.bashrc
source ~/.bashrc
```

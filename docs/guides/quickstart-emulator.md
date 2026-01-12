# Quickstart: DPU Emulator

Run Secure Infrastructure locally using an emulated DPU instead of real hardware. By the end, you'll register a DPU, create an operator, and push SSH CA credentials through the attestation flow.

**What's a DPU?** A Data Processing Unit is a SmartNIC that serves as a hardware trust anchor. In production, it provides cryptographic attestation that credentials only reach verified hosts.

Good for: learning the system, CI/CD pipelines, product evaluation.

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
bin/dpuemu serve --port 18051 --fixture dpuemu/fixtures/bf3-static.json
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
```

The CLI verifies connectivity and retrieves DPU details from the emulator.

---

## Step 5: Assign DPU to Tenant

Link the DPU to the tenant you created in Step 2. This controls which operators can access the device.

```bash
bin/bluectl tenant assign gpu-prod bf3
# Expected: Assigned DPU 'bf3' to tenant 'gpu-prod'
```

---

## Step 6: Create Operator Invitation

Admins manage infrastructure (DPUs, tenants, access grants). Operators push credentials (SSH CAs, certificates) to attested devices. This separation creates an audit trail.

In production, an admin and operator would be different people. Here you're playing both roles.

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

---

## Step 7: Accept Operator Invitation

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

## Step 8: Create SSH CA

An SSH CA signs short-lived certificates instead of scattering static keys across servers. The CA's private key lives on the DPU and can only sign certificates when attestation passes.

```bash
bin/km ssh-ca create test-ca
# Expected: SSH CA 'test-ca' created.
```

---

## Step 9: Grant CA Access

Link the operator to specific CAs and devices. Without this grant, the operator can create CAs but can't push them anywhere.

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

## Step 10: Submit Attestation

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

## Step 11: Distribute Credentials

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

## Step 12: Test Host Agent (Optional)

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

## Step 13: Sign a User Certificate

This is the payoff. Everything you've built leads to this: signing short-lived certificates that grant SSH access without distributing public keys.

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
bin/km ssh-ca sign test-ca --principal ubuntu --pubkey /tmp/demo_key.pub > /tmp/demo_key-cert.pub
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

You've completed the full credential lifecycle:

1. **Infrastructure** - Server, tenant, and DPU registration
2. **Identity** - Operator authentication and authorization grants
3. **Attestation** - Hardware verification before credential distribution
4. **Distribution** - CA pushed through the attested DPU to the host
5. **Usage** - Signed short-lived certificates for SSH access

The emulator demonstrates the workflow but can't show hardware-specific features: real DICE attestation chains, tmfifo credential delivery, or host posture from actual TPMs.

**Next steps:**

- [SSH Key Discovery](discovery.md) - Audit existing keys before migrating to certificates
- [Hardware Setup Guide](setup-hardware.md) - Deploy with real BlueField DPUs

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

1. **Stop the server and emulator** (Ctrl+C in Terminals 1 and 2)

2. **Verify they're stopped:**
```bash
ps aux | grep -E "bin/server|bin/dpuemu" | grep -v grep
# Expected: no output
```

If processes are still running, kill them:
```bash
pkill -f "bin/server" && pkill -f "bin/dpuemu"
```

3. **Delete state files:**
```bash
rm -f ~/.local/share/bluectl/dpus.db
rm -f ~/.local/share/bluectl/key
rm -rf ~/.km
```

4. **Restart server and emulator** (Steps 1 and 3)

The server caches data in memory, so you must stop it before deleting the database.

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

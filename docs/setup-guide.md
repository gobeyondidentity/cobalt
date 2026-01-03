# Secure Infrastructure MVP - Setup Guide

Step-by-step setup for a clean environment.

## Prerequisites

- Go 1.22+
- Make
- Access to BlueField DPU (or use emulator for testing)

## Clone the Repository

```bash
git clone https://github.com/beyondidentity/secure-infra.git
cd secure-infra/eng
```

## Build

```bash
# Build all binaries
make

# Or build individual components
make server      # API server
make bluectl     # Admin CLI
make km          # Operator CLI (keymaker)
make host-agent  # Host agent
make dpuemu      # DPU emulator

# For real DPU hardware (ARM64)
make agent       # Builds both local and ARM64 versions
```

---

## Step 1: Start the Server

First, start the server. It tracks your DPU inventory, attestation state, and authorization policies. All credential distribution flows through it.

Set the encryption key (same key must be used for all commands):

```bash
export SECURE_INFRA_KEY="your-secret-key-here"
bin/server --listen :8080
```

Verify:
```bash
curl http://localhost:8080/api/health
# Expected: {"status":"ok","version":"0.2.0"}
```

---

## Step 2: Create a Tenant

Let's create a tenant. Every DPU and operator you add will belong to this tenant.

```bash
bluectl tenant add gpu-prod --description "GPU Production Cluster"
bluectl tenant list
```

---

## Step 3: Set Up DPU Agent

Now let's get a DPU running. The agent is your trust anchor for credential distribution. It runs on isolated hardware (the BlueField), so even a compromised host can't tamper with it. For this guide, we'll use the emulator.

### Option A: Emulator (Recommended for Testing)

For initial testing, use the DPU emulator with a fixture that includes mock attestation:

```bash
bin/dpuemu serve --port 50051 --fixture dpuemu/fixtures/bf3-static.json
```

### Option B: Real BlueField Hardware

**3a: Copy agent to DPU**
```bash
scp bin/agent-arm64 ubuntu@<DPU_IP>:~/agent
```

**3b: Start the agent**
```bash
ssh ubuntu@<DPU_IP>
chmod +x ~/agent
~/agent --listen :50051
```

The agent communicates with the host agent through `/dev/tmfifo` (BlueField hardware FIFO). No SSH configuration is needed between DPU and host.

---

## Step 4: Register DPU with Server

Now tell the server about your DPU. Unregistered DPUs can't receive credentials, so this step is required before you can distribute anything.

```bash
# If using emulator (Option A):
bluectl dpu add localhost --name bf3

# If using real hardware (Option B):
bluectl dpu add <DPU_IP> --name bf3
```

Assign it to your tenant:

```bash
bluectl tenant assign gpu-prod bf3
bluectl dpu list
```

---

## Step 5: Create an Operator

So far you've been acting as an admin. Now let's create an operator who will actually push credentials.

- **Admins** manage infrastructure: tenants, DPUs, access grants
- **Operators** push credentials to devices they're authorized for

Admins can't push credentials directly. This separation gives you an audit trail showing exactly who pushed what to where.

### 5a: Create invitation (as admin)

```bash
bluectl operator invite operator@example.com gpu-prod
```

Save the invite code from the output.

### 5b: Accept invitation (as operator)

The operator uses a separate CLI (`km`, short for Keymaker) with their own identity. This keeps operator actions auditable and separate from admin actions.

```bash
km init
```

Enter the invite code when prompted. Verify:

```bash
km whoami
```

---

## Step 6: Create SSH CA and Grant Access

### 6a: Create CA (as operator)

An SSH Certificate Authority (CA) signs short-lived certificates for users instead of scattering static keys across servers. Benefits:

- **No key sprawl**: One CA key pair, not hundreds of authorized_keys entries
- **Short-lived certs**: 8-hour certificates by default; revocation becomes "wait for expiry"
- **Central audit**: All cert issuance logged in one place

```bash
km ssh-ca create test-ca
```

### 6b: Grant operator access to CA and devices (as admin)

Operators can only push credentials to devices they've been explicitly granted access to. This implements least privilege: credentials cannot reach devices without an admin explicitly authorizing that path.

The grant creates an auditable record of who can push what to where.

```bash
bluectl operator grant operator@example.com gpu-prod test-ca bf3
```

---

## Step 7: Submit Attestation

Before you can push credentials, the DPU must prove it's running trusted firmware. This blocks compromised hardware from receiving secrets.

```bash
bluectl attestation bf3
```

This queries the DPU for attestation data and records the result.

---

## Step 8: Distribute Credentials

Now push the CA to your DPU. Credentials flow from server to DPU to host, never directly from server to host. The DPU checks attestation before forwarding.

### Distribute

```bash
km push ssh-ca test-ca bf3
```

If attestation is unavailable (e.g., no TPM configured), you can force distribution:

```bash
km push ssh-ca test-ca bf3 --force
```

On success, the CA public key is installed at `/etc/ssh/trusted-user-ca-keys.d/test-ca.pub` on the host, and sshd is reloaded.

---

## Step 9: Set Up Host Agent (Real Hardware Only)

The host agent runs on your Linux servers and communicates with the DPU agent running on the BlueField. It collects security posture and receives credentials via the hardware-secured tmfifo channel.

**Note:** If you're using the emulator (Option A in Step 3), skip this step. The emulator doesn't provide the local API that the host agent needs.

### 9a: Build for Linux

```bash
# For x86_64 hosts (most servers)
GOOS=linux GOARCH=amd64 go build -o bin/host-agent-linux ./cmd/host-agent

# For ARM64 hosts
GOOS=linux GOARCH=arm64 go build -o bin/host-agent-arm64 ./cmd/host-agent
```

### 9b: Copy to host

```bash
scp bin/host-agent-linux <user>@<HOST_IP>:~/host-agent
```

### 9c: Run on host

The host agent auto-detects the BlueField's tmfifo device. If found, it uses the hardware-secured channel. Otherwise, it falls back to network communication with the DPU agent.

```bash
ssh <user>@<HOST_IP>
chmod +x ~/host-agent
~/host-agent
```

The agent will:
1. Detect tmfifo at `/dev/rshim0/console` (BlueField hardware channel)
2. Enroll with the DPU agent
3. Collect and report security posture periodically (default: every 5 minutes)
4. Listen for credential pushes via tmfifo

Options:
- `--oneshot`: Collect and report once, then exit (useful for testing)
- `--force-network`: Use network even if tmfifo is available
- `--dpu-agent http://IP:9443`: Specify DPU agent URL for network mode

---

## Step 10: Create Trust Relationships (Real Hardware Only)

Trust relationships let hosts authenticate each other for SSH or mTLS connections. Useful for distributed training or data pipelines where compute nodes need to communicate securely.

**Note:** Trust relationships are between **hosts**, not DPUs. Each host must have a running host-agent paired with a DPU. If you're using the emulator, skip this step.

### 10a: Prerequisites

You need two hosts, each with:
- A running host-agent
- A paired DPU with fresh attestation

Check your registered hosts:

```bash
bluectl host list
```

### 10b: Create trust relationship

Trust flows from source to target: the source host accepts connections from the target.

```bash
bluectl trust create compute-01 compute-02
```

Options:
- `--type ssh_host` (default): SSH host key trust
- `--type mtls`: Mutual TLS trust
- `--bidirectional`: Create trust in both directions
- `--force`: Bypass attestation checks (use with caution)

Example with bidirectional SSH trust:
```bash
bluectl trust create compute-01 compute-02 --bidirectional
```

### 10c: Verify trust relationships

```bash
bluectl trust list
```

---

## Appendix A: Shell Completion

Enable tab completion for CLI commands:

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

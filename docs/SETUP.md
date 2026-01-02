# Secure Infrastructure MVP - Setup Guide

Step-by-step setup for a clean environment.

## Prerequisites

- Go 1.21+
- Access to BlueField DPU (or use emulator for testing)

## Build

```bash
cd ~/Desktop/Projects/secure-infra/eng
mkdir -p bin
go build -o bin/api ./cmd/api
go build -o bin/bluectl ./cmd/bluectl
go build -o bin/km ./cmd/keymaker
go build -o bin/host-agent ./cmd/host-agent
go build -o bin/dpuemu ./dpuemu/cmd/dpuemu

# For real DPU hardware (ARM64)
GOOS=linux GOARCH=arm64 go build -o bin/agent-arm64 ./cmd/agent
```

---

## Step 1: Start the Control Plane

The API server is the central management component.

```bash
api serve --port 8080
```

Verify:
```bash
curl http://localhost:8080/api/health
# Expected: {"status":"ok","version":"0.1.0"}
```

---

## Step 2: Create a Tenant

All resources are scoped to a tenant (organization).

```bash
bluectl tenant add acme --description "ACME Corporation"
bluectl tenant list
```

---

## Step 3: Set Up DPU Agent

The DPU agent runs on the BlueField and needs SSH access to its host server to distribute credentials.

### Option A: Real BlueField Hardware

**3a: Copy agent to DPU**
```bash
scp bin/agent-arm64 ubuntu@<DPU_IP>:~/agent
```

**3b: Set up SSH key from DPU to host**

SSH to the DPU:
```bash
ssh ubuntu@<DPU_IP>
```

Generate SSH key:
```bash
ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519 -N ""
```

Copy key to host (use a user with sudo access):
```bash
ssh-copy-id -i ~/.ssh/id_ed25519.pub <USER>@<HOST_IP>
```

**3c: Start the agent**
```bash
chmod +x ~/agent

export HOST_SSH_ADDR="<HOST_IP>:22"
export HOST_SSH_USER="<USER>"
export HOST_SSH_KEY="/home/ubuntu/.ssh/id_ed25519"

~/agent --listen :50051
```

Note: The agent SSHs to the host to configure sshd when distributing SSH CAs.

### Option B: Emulator (Testing)

```bash
dpuemu --port 50051 --name bf3-lab-01
```

---

## Step 4: Register DPU in Control Plane

```bash
bluectl dpu add bf3-lab-01 <DPU_IP> --port 50051
bluectl tenant assign acme bf3-lab-01
bluectl dpu list
```

---

## Step 5: Set Up Shell Completion (Optional)

```bash
echo 'source <(bluectl completion zsh)' >> ~/.zshrc
echo 'source <(km completion zsh)' >> ~/.zshrc
source ~/.zshrc
```

---

## Step 6: Create an Operator

Operators are authorized users who can distribute credentials to DPUs.

### 6a: Create invitation (as admin)

```bash
bluectl operator invite <email> --tenant acme
```

Save the invite code from the output.

### 6b: Accept invitation (as operator)

```bash
km init
```

Enter the invite code when prompted. Verify:

```bash
km whoami
```

---

## Step 7: Create SSH CA and Grant Access

### 7a: Create CA (as operator)

```bash
km ssh-ca create --name acme-ca
```

### 7b: Grant operator access to CA and devices (as admin)

```bash
bluectl operator grant <email> --ca acme-ca --devices <dpu-name> --tenant acme
```

---

## Step 8: Submit Attestation

Before distributing credentials, the DPU must prove its integrity:

```bash
bluectl attestation <dpu-name>
```

This queries the DPU agent for attestation data and records it in the control plane.

---

## Step 9: Distribute Credentials

The operator pushes the SSH CA to the DPU, which then configures the host's sshd to trust it.

### Prerequisites

The DPU agent must be configured with SSH access to its host. When starting the agent (Step 3), ensure these environment variables are set:

```bash
export HOST_SSH_ADDR="<HOST_IP>:22"
export HOST_SSH_USER="<USER>"
export HOST_SSH_KEY="/home/ubuntu/.ssh/id_ed25519"
```

If you haven't set up the SSH key from DPU to host, see Step 3b.

### Distribute

```bash
km distribute ssh-ca <ca-name> <dpu-name>
```

If attestation is unavailable (e.g., no TPM configured), you can force distribution:

```bash
km distribute ssh-ca <ca-name> <dpu-name> --force
```

On success, the CA public key is installed at `/etc/ssh/trusted-user-ca-keys.d/<ca-name>.pub` on the host, and sshd is reloaded.

---

## Step 10: Set Up Host Agent

The host agent runs on Linux hosts paired with DPUs. It collects security posture and reports to the control plane.

### 10a: Build for Linux

```bash
# For x86_64 hosts (most servers)
GOOS=linux GOARCH=amd64 go build -o bin/host-agent-linux ./cmd/host-agent

# For ARM64 hosts
GOOS=linux GOARCH=arm64 go build -o bin/host-agent-arm64 ./cmd/host-agent
```

### 10b: Copy to host

```bash
scp bin/host-agent-linux <user>@<HOST_IP>:~/host-agent
```

### 10c: Get control plane IP

The host agent needs to reach the API server. Find the IP of the machine running the API:

```bash
# macOS
ipconfig getifaddr en0

# Linux
hostname -I | awk '{print $1}'
```

### 10d: Run on host

```bash
ssh <user>@<HOST_IP>
chmod +x ~/host-agent
~/host-agent --control-plane http://<CONTROL_PLANE_IP>:8080 --dpu <dpu-name>
```

The agent will:
1. Register with the control plane
2. Pair with the specified DPU
3. Collect and report security posture periodically (default: every 5 minutes)

Use `--oneshot` to collect and report once, then exit (useful for testing).

---

## Step 11: Create Trust Relationships

Trust relationships enable machine-to-machine (M2M) communication between DPUs. You need at least two DPUs to create a trust relationship.

### 11a: Check registered DPUs

```bash
bluectl dpu list
```

If you only have one DPU, you'll need a second one to create a trust relationship.

### 11b: Start a second DPU (emulator)

For testing, use the DPU emulator:

```bash
dpuemu serve --fixture dpuemu/fixtures/bf3-static.json --listen :50052
```

You should see output like:
```
Loading fixture from dpuemu/fixtures/bf3-static.json
dpuemu server listening on :50052
emulating: bluefield3 (serial: MT2542600N23)
```

### 11c: Register the second DPU

```bash
bluectl dpu add bf-emu localhost --port 50052
```

### 11d: (Optional) Verify health

```bash
bluectl health bf-emu
```

This updates the cached status. Then `bluectl dpu list` will show current state.

### 11e: Assign to tenant

Both DPUs must belong to the same tenant to create a trust relationship:

```bash
bluectl tenant assign <tenant> <dpu-name>
```

### 11f: Submit attestation for both DPUs

Trust relationships require fresh attestation:

```bash
bluectl attestation <dpu-name>
```

Note: Real hardware without TPM configured will show `status=unknown`. The emulator provides mock attestation with `status=verified`. Both DPUs must have verified attestation to create a trust relationship (no `--force` flag available yet).

### 11g: Create trust relationship

```bash
bluectl trust create --source <source-dpu> --target <target-dpu>
```

Options:
- `--type ssh_host` (default): SSH host key trust
- `--type mtls`: Mutual TLS trust
- `--bidirectional`: Create trust in both directions

Example output:
```
Trust relationship created:
  bf-emu <--> bf-emu-02 (SSH host, bidirectional)
  Status: active
```

### 11h: Verify trust relationships

```bash
bluectl trust list
```

---

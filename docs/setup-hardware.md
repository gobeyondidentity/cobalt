# Hardware Setup: BlueField DPU

Deploy Secure Infrastructure with real BlueField DPUs. This guide covers the full production path including trust relationships between hosts.

## Prerequisites

- Go 1.22+
- Make
- NVIDIA BlueField-3 DPU with network access
- SSH access to the DPU (default: `ubuntu@<DPU_IP>`)
- Linux host paired with the DPU

## Clone and Build

```bash
git clone https://github.com/nmelo/secure-infra.git
cd secure-infra
make
```

## Environment Setup

Set the encryption key before running any commands:

```bash
export SECURE_INFRA_KEY=$(openssl rand -hex 32)
```

To persist across sessions:

```bash
echo "export SECURE_INFRA_KEY=$SECURE_INFRA_KEY" >> ~/.zshrc
source ~/.zshrc
```

---

## Step 1: Start the Server

The server tracks your DPU inventory, attestation state, and authorization policies. Run this on your control plane host.

```bash
bin/server --listen :8080
```

Verify:

```bash
curl http://localhost:8080/api/health
# Expected: {"status":"ok","version":"0.3.0"}
```

---

## Step 2: Create a Tenant

Every DPU and operator belongs to a tenant.

```bash
bin/bluectl tenant add gpu-prod --description "GPU Production Cluster"
bin/bluectl tenant list
```

---

## Step 3: Deploy DPU Agent

The DPU agent runs on the BlueField and serves as the hardware trust anchor.

### 3a: Copy agent to DPU

```bash
scp bin/agent-arm64 ubuntu@<DPU_IP>:~/agent
```

### 3b: Start the agent

```bash
ssh ubuntu@<DPU_IP>
chmod +x ~/agent
~/agent --listen :50051
```

The agent communicates with the host agent through `/dev/tmfifo` (BlueField hardware FIFO). No SSH configuration is needed between DPU and host.

---

## Step 4: Register DPU with Server

```bash
bin/bluectl dpu add <DPU_IP> --name bf3-prod-01
bin/bluectl tenant assign gpu-prod bf3-prod-01
bin/bluectl dpu list
```

---

## Step 5: Create an Operator

Admins manage infrastructure. Operators push credentials. This separation creates an audit trail.

### 5a: Create invitation (as admin)

```bash
bin/bluectl operator invite operator@example.com gpu-prod
```

Save the invite code from the output.

### 5b: Accept invitation (as operator)

```bash
bin/km init
```

Enter the invite code when prompted. Verify:

```bash
bin/km whoami
```

---

## Step 6: Create SSH CA and Grant Access

### 6a: Create CA (as operator)

An SSH CA signs short-lived certificates instead of scattering static keys across servers.

```bash
bin/km ssh-ca create prod-ca
```

### 6b: Grant access (as admin)

```bash
bin/bluectl operator grant operator@example.com gpu-prod prod-ca bf3-prod-01
```

---

## Step 7: Submit Attestation

The DPU must prove it's running trusted firmware. This queries the TPM/DICE for attestation evidence.

```bash
bin/bluectl attestation bf3-prod-01
```

If attestation fails (e.g., DOCA not configured), you can check status:

```bash
bin/bluectl dpu list
```

---

## Step 8: Distribute Credentials

Push the CA to the DPU, which forwards it to the host via tmfifo:

```bash
bin/km push ssh-ca prod-ca bf3-prod-01
```

If attestation is unavailable, you can force distribution (not recommended for production):

```bash
bin/km push ssh-ca prod-ca bf3-prod-01 --force
```

On success, the CA public key is installed at `/etc/ssh/trusted-user-ca-keys.d/prod-ca.pub` on the host, and sshd is reloaded.

---

## Step 9: Deploy Host Agent

The host agent runs on Linux servers paired with DPUs. It collects security posture and receives credentials via the hardware-secured tmfifo channel.

### 9a: Build for your architecture

```bash
# For x86_64 hosts
GOOS=linux GOARCH=amd64 go build -o bin/host-agent-linux ./cmd/host-agent

# For ARM64 hosts
GOOS=linux GOARCH=arm64 go build -o bin/host-agent-arm64 ./cmd/host-agent
```

### 9b: Copy to host

```bash
scp bin/host-agent-linux <user>@<HOST_IP>:~/host-agent
```

### 9c: Run on host

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

---

## Step 10: Create Trust Relationships

Trust relationships let hosts authenticate each other for SSH or mTLS connections. Useful for distributed training or data pipelines.

### Prerequisites

You need two hosts, each with:
- A running host-agent
- A paired DPU with fresh attestation

Check your registered hosts:

```bash
bin/bluectl host list
```

### 10a: Add a second DPU and host

Repeat Steps 3-4 and 9 for the second host/DPU pair:

```bash
# Register second DPU
bin/bluectl dpu add <DPU2_IP> --name bf3-prod-02
bin/bluectl tenant assign gpu-prod bf3-prod-02
bin/bluectl attestation bf3-prod-02
```

### 10b: Create trust relationship

Trust flows from source to target: the source host accepts connections from the target.

```bash
bin/bluectl trust create compute-01 compute-02
```

Options:
- `--type ssh_host` (default): SSH host key trust
- `--type mtls`: Mutual TLS trust
- `--bidirectional`: Create trust in both directions
- `--force`: Bypass attestation checks (use with caution)

Example with bidirectional SSH trust:

```bash
bin/bluectl trust create compute-01 compute-02 --bidirectional
```

### 10c: Verify trust relationships

```bash
bin/bluectl trust list
```

---

## Appendix: Shell Completion

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

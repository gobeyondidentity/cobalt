# Hardware Setup: BlueField DPU

Deploy Project Cobalt with real BlueField DPUs. This guide covers the full production path including trust relationships between hosts.

## Prerequisites

**Hardware:**
- NVIDIA BlueField-3 DPU with network access
- SSH access to the DPU (default: `ubuntu@<DPU_IP>`)
- Linux host with the BlueField DPU installed
- DOCA SDK 2.8+ on both host and DPU (for ComCh transport)
- rshim driver on host (fallback for tmfifo transport)

**Control plane tools:** Choose one installation method:

### Option A: Install via Package Manager (Recommended)

**macOS (Homebrew):**
```bash
brew tap nmelo/tap
brew install bluectl km
```

**Linux (Debian/Ubuntu):**
```bash
# Set up repository and install packages
curl -1sLf 'https://raw.githubusercontent.com/gobeyondidentity/cobalt/main/scripts/install.sh' | sudo bash -s bluectl km
```

**Linux (RHEL/Fedora):**
```bash
# Set up repository and install packages
curl -1sLf 'https://raw.githubusercontent.com/gobeyondidentity/cobalt/main/scripts/install.sh' | sudo bash -s bluectl km
```

Skip to [Step 1: Start the Server](#step-1-start-the-server) after installing.

### Option B: Build from Source

Requires Go 1.22+ and Make. See [Clone and Build](#clone-and-build).

## Clone and Build

*Skip this section if you installed via package manager.*

```bash
git clone git@github.com:gobeyondidentity/cobalt.git
cd secure-infra
make aegis
# Expected:
# Building aegis...
#   bin/aegis
# Cross-compiling aegis for BlueField (linux/arm64)...
#   bin/aegis-arm64

make sentry
# Expected:
# Building sentry...
#   bin/sentry
# Cross-compiling sentry for Linux (amd64)...
#   bin/sentry-amd64
# Cross-compiling sentry for Linux (arm64)...
#   bin/sentry-arm64

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

This builds:
- `bin/aegis-arm64` for the BlueField DPU
- `bin/sentry-amd64` for x86_64 hosts
- Control plane tools (`bluectl`, `km`, `nexus`)

**Note:** When building from source, use `bin/` prefix for all commands (e.g., `bin/bluectl` instead of `bluectl`).

## Step 1: Start the Server

The server (nexus) tracks your DPU inventory, health state, and authorization policies. Run this on your control plane host.

```bash
nexus              # if installed via package manager
# or: bin/server   # if built from source
```

The server listens on port 18080 by default. Verify it's running:

```bash
curl http://localhost:18080/api/health
# Expected: {"status":"ok","version":"0.6.3"}
```

---

## Step 2: Create a Tenant

Tenants are organizational boundaries that group DPUs, operators, and policies. Use them to separate environments (dev/staging/prod) or teams.

```bash
bluectl tenant add gpu-prod --description "GPU Production Cluster"
# Expected: Created tenant 'gpu-prod'.

bluectl tenant list
# Expected:
# NAME      DESCRIPTION             CONTACT  DPUs  TAGS
# gpu-prod  GPU Production Cluster  -        0     -
```

---

## Step 3: Install DPU Agent (aegis)

The DPU agent (aegis) runs on the BlueField and handles automatic credential distribution. It exposes a gRPC interface for the control plane and a local HTTP API that the host agent uses to receive credentials without manual file copying.

SSH into the DPU:

```bash
ssh ubuntu@<DPU_IP>
```

### Option A: Install via apt (Recommended)

```bash
# Set up repository and install aegis (requires arm64/BlueField DPU)
curl -1sLf 'https://raw.githubusercontent.com/gobeyondidentity/cobalt/main/scripts/install.sh' | sudo bash -s aegis
```

### Option B: Manual Binary (Air-Gapped Environments)

From your build machine:
```bash
scp bin/aegis-arm64 ubuntu@<DPU_IP>:~/aegis
```

On the DPU:
```bash
chmod +x ~/aegis
sudo mv ~/aegis /usr/local/bin/aegis
```

---

## Step 4: Configure and Start DPU Agent

### Configure aegis

```bash
sudo mkdir -p /etc/secureinfra

sudo tee /etc/secureinfra/aegis.yaml << EOF
control_plane: http://<CONTROL_PLANE_IP>:18080
dpu_name: bf3-prod-01
transport: comch
local_api: true
log_level: info
EOF
```

Replace `<CONTROL_PLANE_IP>` with the IP of the machine running nexus. The `dpu_name` should match what you'll use in Step 5.

### Start the service

**If installed via apt:**
```bash
sudo systemctl enable --now aegis
sudo systemctl status aegis
```

**If installed manually:**
```bash
# Create systemd unit
sudo tee /etc/systemd/system/aegis.service << 'EOF'
[Unit]
Description=Aegis DPU Agent
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/aegis --config /etc/secureinfra/aegis.yaml
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now aegis
```

### Verify it's running

```bash
journalctl -u aegis --no-pager | tail -20
# Expected:
# Aegis v0.6.3 starting...
# gRPC server listening on :18051
# Local API listening on localhost:9443
# Control Plane: http://<CONTROL_PLANE_IP>:18080
# DPU Name: bf3-prod-01
```

Leave the service running. The agent must be active for registration and credential distribution.

---

## Step 5: Register DPU

Back on your control plane, register the DPU:

```bash
bluectl dpu add <DPU_IP> --name bf3-prod-01
# Expected:
# Checking connectivity to <DPU_IP>:18051...
# Connected to DPU:
#   Hostname: <hostname>
#   Serial:   <serial>
#   Model:    BlueField-3
# Connection verified: agent is healthy
# Added DPU 'bf3-prod-01' at <DPU_IP>:18051
#
# Next: Assign to a tenant with 'bluectl tenant assign <tenant> bf3-prod-01'
```

---

## Step 6: Assign DPU to Tenant

```bash
bluectl tenant assign gpu-prod bf3-prod-01
# Expected: Assigned DPU 'bf3-prod-01' to tenant 'gpu-prod'

bluectl dpu list
# Expected:
# NAME          HOST        PORT   STATUS*  LAST SEEN
# bf3-prod-01   <DPU_IP>    18051  healthy  <timestamp>
#
# * Status reflects last known state. Use 'bluectl dpu health <name>' for live status.
```

---

## Step 7: Create Operator Invitation

Admins manage infrastructure (bluectl). Operators push credentials (km). This separation creates an audit trail where credential distribution is always tied to an authenticated operator.

```bash
bluectl operator invite operator@example.com gpu-prod
# Expected:
# Invite created for operator@example.com
# Code: <CODE>
# Expires: <timestamp>
#
# Share this code with the operator. They will need to:
#   1. Run: km init
#   2. Enter the invite code when prompted
```

Save the invite code.

---

## Step 8: Accept Operator Invitation

```bash
km init
# Expected:
# KeyMaker v0.6.3
# Platform: <platform> (<arch>)
# Secure Element: <type>
#
# Enter invite code:
```

Enter the code when prompted:

```
# Expected after entering code:
# Generating keypair...
# Binding to server...
#
# Bound successfully.
#   Operator: operator@example.com
#   Tenant: gpu-prod (operator)
#   KeyMaker: <keymaker-id>
#
# Config saved to ~/.km/config.json
#
# Next steps:
#   Run 'km whoami' to verify your identity.
#
# You have access to 0 CA(s) and 0 device(s).
# Ask your admin to grant access: bluectl operator grant operator@example.com <tenant> <ca> <devices>
```

Verify your identity:

```bash
km whoami
# Expected:
# Operator: operator@example.com
# Server:   http://localhost:18080
#
# Authorizations: none
```

---

## Step 9: Create SSH CA

An SSH CA signs short-lived certificates instead of distributing static keys across servers. Certificates expire automatically, so revocation is rarely needed.

```bash
km ssh-ca create prod-ca
# Expected: SSH CA 'prod-ca' created.
```

---

## Step 10: Grant CA Access

Link the operator, CA, and DPU together. This authorizes the operator to push this CA to this DPU:

```bash
bluectl operator grant operator@example.com gpu-prod prod-ca bf3-prod-01
# Expected:
# Authorization granted:
#   Operator: operator@example.com
#   Tenant:   gpu-prod
#   CA:       prod-ca
#   Devices:  bf3-prod-01
```

---

## Step 11: Submit Attestation

Attestation is automatic health verification. The DPU confirms it's running expected firmware, enabling credential distribution to proceed without manual approval for each operation.

```bash
bluectl attestation bf3-prod-01
```

**If attestation succeeds** (DOCA properly configured):

```
# Expected:
# Attestation Status: ATTESTATION_STATUS_SUCCESS
#
# Certificates:
#   ...certificate chain...
#
# Attestation saved: status=success, last_validated=<timestamp>
```

**If attestation is unavailable** (common during initial setup):

```
# Expected:
# Attestation Status: ATTESTATION_STATUS_UNAVAILABLE
#
# No certificates available
#
# Attestation saved: status=unavailable, last_validated=<timestamp>
```

Attestation may be unavailable if DOCA is not configured or the BlueField firmware doesn't support DICE attestation. You can still proceed with `--force` in Step 15, but automatic health checks won't gate credential distribution.

---

## Step 12: Configure Host-DPU Transport

The host agent communicates with the DPU agent over PCIe. The transport is automatically selected based on what's available:

| Priority | Transport | Requires | Throughput |
|----------|-----------|----------|------------|
| 1 | DOCA ComCh | DOCA SDK 2.8+ | ~1 GB/s |
| 2 | tmfifo | rshim driver | ~10 MB/s |
| 3 | Network | HTTP connectivity | Varies |

**Why PCIe transports matter:** Network-based enrollment requires additional configuration. With ComCh or tmfifo, the DPU automatically identifies the physical host, simplifying setup and eliminating IP address management.

SSH to the host server (not the DPU) and verify transport availability:

### Option A: DOCA ComCh (Recommended)

ComCh provides the best performance and supports multiple concurrent connections.

#### 1. Check DOCA Installation

```bash
ssh <user>@<HOST_IP>

dpkg -l | grep doca-runtime
# Expected: ii  doca-runtime-<version>  ...
```

#### 2. Discover PCI Devices

```bash
lspci | grep -i mellanox
# Example output:
# 01:00.0 Ethernet controller: Mellanox Technologies MT43244 BlueField-3 integrated ConnectX-7 network controller
# 01:00.1 Ethernet controller: Mellanox Technologies MT43244 BlueField-3 integrated ConnectX-7 network controller
```

**Understanding the output:**

| Field | Meaning | Example |
|-------|---------|---------|
| `01:00.0` | PCI address (bus:device.function) | First port of DPU |
| `01:00.1` | Second function on same device | Second port of same DPU |
| `MT43244` | Device ID | BlueField-3 |

**Dual-port DPUs:** BlueField-3 has two ports (`.0` and `.1`). Both ports share the same `sys_image_guid` and belong to the same physical DPU. The host agent connects to port 0 by default.

#### 3. Verify ComCh Capability

```bash
# Check if device supports ComCh (client mode for host)
ls /sys/class/infiniband/
# Expected: mlx5_0  mlx5_1  (one per port)

cat /sys/class/infiniband/mlx5_0/sys_image_guid
# Expected: 0c42:a103:00a7:89f0 (unique per DPU)
```

The `sys_image_guid` uniquely identifies the DPU and is stable across reboots.

#### 4. Distinguishing DPUs from ConnectX NICs

If you have both BlueField DPUs and ConnectX NICs:

```bash
lspci | grep -i mellanox
# 01:00.0 ... MT43244 BlueField-3 ...     <- DPU (ComCh capable)
# 03:00.0 ... MT2910 ConnectX-7 ...       <- NIC (NOT ComCh capable)
```

| Device | Model Prefix | ComCh Support |
|--------|--------------|---------------|
| BlueField-3 | MT43244 | Yes |
| BlueField-2 | MT42822 | No (use tmfifo) |
| ConnectX-7 | MT2910 | No |
| ConnectX-6 | MT2892 | No |

The host agent automatically filters to ComCh-capable devices.

### Option B: tmfifo (Fallback)

If DOCA SDK is not installed or you're using BlueField-2, the system falls back to tmfifo:

```bash
# Check rshim driver is loaded
lsmod | grep rshim
# Expected: rshim  <size>  0

# Check tmfifo device exists
ls -la /dev/rshim0/
# Expected:
# crw-rw---- 1 root root ... /dev/rshim0/boot
# crw-rw---- 1 root root ... /dev/rshim0/console
# crw-rw---- 1 root root ... /dev/rshim0/misc
# crw-rw---- 1 root root ... /dev/rshim0/rshim
```

If rshim is not loaded:

```bash
sudo modprobe rshim
sudo systemctl enable rshim
sudo systemctl start rshim
```

### Troubleshooting: No Devices Found

If `lspci | grep -i mellanox` returns nothing:

1. **Check physical connection:** Ensure the DPU is properly seated in the PCIe slot
2. **Rescan PCI bus:** `echo 1 | sudo tee /sys/bus/pci/rescan`
3. **Check dmesg:** `dmesg | grep -i mlx` for driver messages
4. **Verify power:** Some DPUs require auxiliary power connectors

---

## Step 13: Pair Host with DPU

Before the host agent can enroll, the admin must authorize the host-DPU pairing. This ensures only intended hosts receive credentials automatically.

On the control plane:

```bash
bluectl host pair bf3-prod-01
# Expected:
# Host pairing enabled for DPU 'bf3-prod-01'
# The next host agent to connect via ComCh/tmfifo will be registered.
```

---

## Step 14: Install and Run Host Agent (sentry)

SSH to the host server (not the DPU):

```bash
ssh <user>@<HOST_IP>
```

### Option A: Install via apt/yum (Recommended)

**Debian/Ubuntu:**
```bash
# Set up repository and install sentry
curl -1sLf 'https://raw.githubusercontent.com/gobeyondidentity/cobalt/main/scripts/install.sh' | sudo bash -s sentry
```

**RHEL/Fedora:**
```bash
# Set up repository and install sentry
curl -1sLf 'https://raw.githubusercontent.com/gobeyondidentity/cobalt/main/scripts/install.sh' | sudo bash -s sentry
```

### Option B: Manual Binary (Air-Gapped Environments)

From your build machine:
```bash
scp bin/sentry-amd64 <user>@<HOST_IP>:~/sentry
```

On the host:
```bash
chmod +x ~/sentry
sudo mv ~/sentry /usr/local/bin/sentry
```

### Configure sentry

```bash
sudo mkdir -p /etc/secureinfra

sudo tee /etc/secureinfra/sentry.yaml << 'EOF'
# Transport is auto-detected: ComCh → tmfifo → network
log_level: info
EOF
```

### Start the service

**If installed via apt/yum:**
```bash
sudo systemctl enable --now sentry
sudo systemctl status sentry
```

**If installed manually:**
```bash
# Create systemd unit
sudo tee /etc/systemd/system/sentry.service << 'EOF'
[Unit]
Description=Sentry Host Agent
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/sentry --config /etc/secureinfra/sentry.yaml
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now sentry
```

### Verify it's running

```bash
journalctl -u sentry --no-pager | tail -20
```

The agent automatically selects the best available transport:

```
# Expected (ComCh path - preferred):
# Sentry v0.6.3 starting...
# Initial posture collected: hash=<hash>
# DOCA ComCh available: mlx5_0 at 01:00.0
# Enrolling via ComCh...
# Hostname: <hostname>
# Paired with DPU: bf3-prod-01
# Registered as host <host_id>
```

```
# Expected (tmfifo path - fallback):
# Sentry v0.6.3 starting...
# Initial posture collected: hash=<hash>
# DOCA ComCh unavailable, falling back to tmfifo
# tmfifo detected: /dev/rshim0/misc
# Enrolling via tmfifo...
# Hostname: <hostname>
# Paired with DPU: bf3-prod-01
# Registered as host <host_id>
```

Verify registration on the control plane:

```bash
bluectl host list
# Expected:
# NAME          DPU           STATUS   LAST SEEN    CHANNEL
# <hostname>    bf3-prod-01   online   <timestamp>  comch
```

The CHANNEL column shows which transport is in use: `comch`, `tmfifo`, or `network`.

### Troubleshooting sentry

**Service fails to start:**
```bash
journalctl -u sentry --no-pager | tail -50
cat /etc/secureinfra/sentry.yaml
```

**Network fallback (no PCIe transport):**
```bash
# Edit config to specify DPU agent URL
sudo tee /etc/secureinfra/sentry.yaml << 'EOF'
dpu_agent: http://localhost:9443
log_level: info
EOF
sudo systemctl restart sentry
```

---

## Step 15: Distribute Credentials

With the host agent running and registered, push the SSH CA through the DPU to the host:

```bash
km push ssh-ca prod-ca bf3-prod-01
```

**If attestation succeeded** in Step 11:

```
# Expected:
# Pushing CA 'prod-ca' to bf3-prod-01...
# CA installed.
```

**If attestation was unavailable**, force distribution (logs a warning):

```bash
km push ssh-ca prod-ca bf3-prod-01 --force
# Expected:
# Pushing CA 'prod-ca' to bf3-prod-01...
#   Attestation refresh attempted but unavailable.
# ! Attestation stale (0s ago)
# Warning: Forcing push despite attestation unavailable (logged)
#
# CA installed.
```

On success, the CA public key is installed at `/etc/ssh/trusted-user-ca-keys.d/prod-ca.pub` on the host, and sshd is automatically reloaded to trust the new CA.

---

## Step 16: Sign and Use Certificates

This is the payoff. Your host now trusts the CA. Sign a certificate and SSH in.

Sign your SSH key (or generate a new one):

```bash
km ssh-ca sign prod-ca --principal ubuntu --pubkey ~/.ssh/id_ed25519.pub > ~/.ssh/id_ed25519-cert.pub
```

The certificate is valid for 8 hours by default. Use `--validity 24h` or `--validity 7d` for longer durations.

SSH to your host using the certificate:

```bash
ssh -i ~/.ssh/id_ed25519 ubuntu@<HOST_IP>
# Expected: successful login
```

The host verifies:
1. The certificate was signed by a CA it trusts (prod-ca)
2. The certificate hasn't expired
3. The principal (ubuntu) matches an allowed user

No authorized_keys files to manage. No public key distribution across your fleet. Credentials flow automatically to verified hosts.

Inspect your certificate anytime:

```bash
ssh-keygen -L -f ~/.ssh/id_ed25519-cert.pub
```

---

## Appendix A: Trust Relationships (Optional)

Trust relationships let hosts authenticate each other for SSH or mTLS connections. This is useful for distributed training clusters or data pipelines where servers need to communicate without manual key exchange.

### Prerequisites

You need two hosts, each with:
- A running sentry (Steps 12-14)
- A paired DPU with health verification complete (Step 11)

Check your registered hosts:

```bash
bluectl host list
# Expected:
# DPU           HOSTNAME      LAST SEEN  SECURE BOOT  DISK ENC
# bf3-prod-01   compute-01    2m ago     enabled      LUKS
# bf3-prod-02   compute-02    1m ago     enabled      LUKS
```

### Add a second DPU and host

Repeat Steps 3-6 and 11-15 for the second host/DPU pair:

```bash
# Register second DPU
bluectl dpu add <DPU2_IP> --name bf3-prod-02
bluectl tenant assign gpu-prod bf3-prod-02

# Grant operator access
bluectl operator grant operator@example.com gpu-prod prod-ca bf3-prod-02

# Submit attestation
bluectl attestation bf3-prod-02
```

Deploy and run sentry on the second host (Steps 12-14).

### Create trust relationship

Trust is directional: the source host accepts connections from the target host. The target initiates connections and receives a CA-signed certificate.

```bash
bluectl trust create compute-01 compute-02
# Expected: Trust relationship created: compute-01 <- compute-02
```

For bidirectional trust (both hosts can initiate connections to each other):

```bash
bluectl trust create compute-01 compute-02 --bidirectional
# Expected:
# Trust relationship created: compute-01 <- compute-02
# Trust relationship created: compute-02 <- compute-01
```

Options:
- `--type ssh_host` (default): SSH host key trust
- `--type mtls`: Mutual TLS trust
- `--bidirectional`: Create trust in both directions
- `--force`: Bypass attestation checks (use with caution)

### Verify trust relationships

```bash
bluectl trust list
# Expected:
# SOURCE       TARGET       TYPE      CREATED
# compute-01   compute-02   ssh_host  <timestamp>
# compute-02   compute-01   ssh_host  <timestamp>
```

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

---

## Appendix C: Multi-DPU Support

Hosts with multiple BlueField DPUs require additional configuration. This appendix covers discovery, identification, and configuration for multi-DPU environments.

### Architecture: One Agent Per DPU

Each DPU runs its own agent. The host agent connects to all DPUs:

```
┌─────────────────────────────────────────────────────────────┐
│                           Host                               │
│  ┌───────────────────────────────────────────────────────┐  │
│  │                     Host Agent                         │  │
│  │  ┌─────────────┐              ┌─────────────┐         │  │
│  │  │ ComCh Conn  │              │ ComCh Conn  │         │  │
│  │  │ (DPU-A)     │              │ (DPU-B)     │         │  │
│  │  └──────┬──────┘              └──────┬──────┘         │  │
│  └─────────┼────────────────────────────┼────────────────┘  │
│            │                            │                    │
│    ┌───────┴───────┐            ┌───────┴───────┐          │
│    │  BF3 Port 0   │            │  BF3 Port 0   │          │
│    │  (01:00.0)    │            │  (02:00.0)    │          │
│    │  guid: ...7cca│            │  guid: ...8ddb│          │
└────┼───────────────┼────────────┼───────────────┼──────────┘
     │               │            │               │
┌────┴───────────────┴──┐    ┌────┴───────────────┴──┐
│  DPU-A (guid: ...7cca)│    │  DPU-B (guid: ...8ddb)│
│  ┌─────────────────┐  │    │  ┌─────────────────┐  │
│  │   DPU Agent A   │  │    │  │   DPU Agent B   │  │
│  └─────────────────┘  │    │  └─────────────────┘  │
└───────────────────────┘    └───────────────────────┘
```

**Why one agent per DPU:**

| Consideration | One per DPU | Single Multi-DPU Agent |
|---------------|-------------|------------------------|
| Isolation | Each DPU's secrets isolated | Shared process = shared risk |
| Failure domain | DPU failure affects only that agent | Single point of failure |
| Deployment | Standard systemd unit | Custom orchestration |

### Stable Identifiers

Use `sys_image_guid` to identify DPUs. Unlike PCI addresses, GUIDs are stable across reboots and slot changes:

| Identifier | Stability | Use Case |
|------------|-----------|----------|
| `sys_image_guid` | Survives reboots, PCI changes | Primary identifier |
| PCI address | May change on reboot/hotplug | Connection establishment |
| `node_guid` | Stable (per-port) | Port-specific identification |

Find the GUID:

```bash
cat /sys/class/infiniband/mlx5_0/sys_image_guid
# Output: 8c91:3a03:00f4:7cca
```

### Host Agent Configuration

#### Auto-Discovery (Default)

The host agent automatically discovers all DPUs:

```yaml
# /etc/secureinfra/sentry.yaml
transport:
  doca_comch:
    auto_discover: true    # Find all ComCh-capable devices
    connect_timeout: 5s
    reconnect_interval: 10s
```

#### Explicit DPU List

For controlled environments, specify DPUs by GUID:

```yaml
# /etc/secureinfra/sentry.yaml
transport:
  doca_comch:
    auto_discover: false
    dpus:
      - guid: "8c91:3a03:00f4:7cca"
        label: "dpu-primary"
      - guid: "8c91:3a03:00f4:8ddb"
        label: "dpu-backup"
```

**When to use explicit config:**
- Production environments with known hardware
- When auto-discovery finds unwanted devices
- For audit compliance (documented inventory)

### DPU Agent Configuration

Each DPU agent discovers only its local hardware:

```yaml
# /etc/secure-infra/dpu-agent.yaml (on each DPU)
transport:
  doca_comch:
    auto_discover: true     # Finds local device
    server_name: "secure-infra"
    max_clients: 1          # One host connection
```

### Scenarios

#### Scenario 1: Redundant DPUs

Two DPUs for high availability:

```bash
# Host discovers both
bluectl host list
# NAME        DPU           STATUS   CHANNEL
# compute-01  bf3-prod-01   online   comch
# compute-01  bf3-prod-02   online   comch

# Workloads can use either DPU for credential distribution
# If bf3-prod-01 fails, bf3-prod-02 continues serving
```

#### Scenario 2: DPU Replacement

When replacing a failed DPU:

```bash
# Old DPU (guid ...7cca) removed
# New DPU (guid ...5aab) installed

# With auto_discover: true
# Host agent detects new DPU automatically

# With explicit config
# Update config with new GUID, restart sentry
```

#### Scenario 3: Mixed BlueField + ConnectX

Host has both DPUs and regular NICs:

```bash
lspci | grep -i mellanox
# 01:00.0 ... MT43244 BlueField-3 ...   <- DPU (used)
# 02:00.0 ... MT43244 BlueField-3 ...   <- DPU (used)
# 03:00.0 ... MT2910 ConnectX-7 ...     <- NIC (ignored)
```

The host agent automatically filters to ComCh-capable devices only.

### Verification

Check discovered DPUs:

```bash
# On host
sentry --discover-only
# Output:
# Discovered 2 DPUs:
#   guid: 8c91:3a03:00f4:7cca  pci: 01:00.0  status: available
#   guid: 8c91:3a03:00f4:8ddb  pci: 02:00.0  status: available
```

Check connections:

```bash
bluectl host show compute-01
# Output:
# Host: compute-01
# DPU Connections:
#   bf3-prod-01 (8c91:3a03:00f4:7cca): connected via comch
#   bf3-prod-02 (8c91:3a03:00f4:8ddb): connected via comch
```

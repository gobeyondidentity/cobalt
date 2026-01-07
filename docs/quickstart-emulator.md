# Quickstart: DPU Emulator

Get Secure Infrastructure running locally without hardware. Use this guide to learn the system, run CI/CD pipelines, or evaluate the product.

## Prerequisites

- Go 1.22+
- Make

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

For testing only, you can use the `--insecure` flag instead, but this stores keys unencrypted.

---

## Step 1: Start the Server

The server tracks your DPU inventory, attestation state, and authorization policies.

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

## Step 3: Start the DPU Emulator

The emulator simulates a BlueField DPU with mock attestation data.

```bash
bin/dpuemu serve --port 50051 --fixture dpuemu/fixtures/bf3-static.json
```

Leave this running in a separate terminal.

---

## Step 4: Register the Emulated DPU

Tell the server about your emulated DPU:

```bash
bin/bluectl dpu add localhost --name bf3
bin/bluectl tenant assign gpu-prod bf3
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
bin/km ssh-ca create test-ca
```

### 6b: Grant access (as admin)

```bash
bin/bluectl operator grant operator@example.com gpu-prod test-ca bf3
```

---

## Step 7: Submit Attestation

The DPU must prove it's running trusted firmware before receiving credentials. The emulator provides mock attestation.

```bash
bin/bluectl attestation bf3
```

---

## Step 8: Distribute Credentials

Push the CA to the emulated DPU:

```bash
bin/km push ssh-ca test-ca bf3
```

With the emulator, credentials are stored locally. On real hardware, they'd be pushed to the host via the DPU.

---

## Step 9: Test Host Agent (Optional)

The host agent collects security posture and receives credentials. With the emulator, it connects via HTTP.

```bash
bin/host-agent --dpu-agent http://localhost:9443 --oneshot
```

---

## What's Next?

You've completed the emulator quickstart. The emulator can't simulate:

- Trust relationships between hosts (requires real host-agents paired with DPUs)
- Hardware-secured credential delivery via tmfifo
- Real attestation from TPM/DICE

When you're ready for production, see [Hardware Setup Guide](setup-hardware.md).

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

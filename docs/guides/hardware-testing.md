# Hardware Testing: DOCA ComCh Transport

Automated end-to-end testing of DOCA ComCh transport on real BlueField-3 hardware. Tests run from a workbench machine (localhost or 192.168.1.235) and SSH to the BlueField-3 DPU (192.168.1.204) to orchestrate the full enrollment and credential delivery flows.

## Test Architecture

```
Workbench (localhost)                     BlueField-3 DPU (192.168.1.204)
+----------------------------------+      +----------------------------------+
|  Test Driver (go test)           |      |                                  |
|    |                             |      |                                  |
|    +-- nexus (:18080)            | HTTP |  aegis                           |
|    |     Control plane API       |<---->|    -doca-pci-addr 03:00.0        |
|    |                             |      |    -doca-rep-pci-addr 01:00.0    |
|    +-- sentry                    | SSH  |    -local-api                    |
|    |     Host agent (ComCh)      |----->|    Manages via SSH               |
|    |                             |      |                                  |
|    +-- bluectl                   | gRPC |  gRPC (:18051)                   |
|          DPU registration        |<---->|    DPU management                |
+----------------------------------+      +----------------------------------+
              |                                        |
              +--------------- ComCh -----------------+
                          (PCIe via rshim)
```

The test driver:

1. SSHes to BF3 to start/stop aegis with DOCA ComCh flags
2. Starts nexus locally as control plane
3. Registers DPU via bluectl over gRPC
4. Runs sentry locally with `--force-comch` to test the transport
5. Verifies enrollment and credential delivery completed

## Prerequisites

### SSH Access to BlueField-3

```bash
ssh ubuntu@192.168.1.204
# Should connect without password prompt (SSH keys configured)
```

If SSH fails, configure key-based authentication:

```bash
ssh-copy-id ubuntu@192.168.1.204
```

### DOCA SDK on BlueField-3

Verify DOCA is installed:

```bash
ssh ubuntu@192.168.1.204 "ls -la /opt/mellanox/doca"
# Should list DOCA installation directory
```

### rshim Driver on Workbench

The workbench host needs rshim for ComCh communication:

```bash
lsmod | grep rshim
# Expected: rshim  <size>  0
```

If not loaded:

```bash
sudo modprobe rshim
```

### aegis Binary on BlueField-3

The ARM64 aegis binary must be deployed to the DPU:

```bash
ssh ubuntu@192.168.1.204 "ls -la ~/aegis"
# Expected: -rwxr-xr-x ... aegis
```

If missing, deploy it:

```bash
make qa-hardware-build
make qa-hardware-setup
```

### Go 1.22+

Required for running the test suite:

```bash
go version
# Expected: go version go1.22.x (or higher)
```

## PCI Address Discovery

DOCA ComCh requires PCI addresses for both the DPU device and the host-side representor.

### On BlueField-3 DPU

Find the Mellanox device:

```bash
ssh ubuntu@192.168.1.204 "lspci | grep -i mellanox"
# Example output:
# 03:00.0 Ethernet controller: Mellanox Technologies MT43244 BlueField-3 ...
# 03:00.1 Ethernet controller: Mellanox Technologies MT43244 BlueField-3 ...
```

The first address (03:00.0) is typically used for `DOCA_PCI_ADDR`.

### On Workbench Host

Find the representor device:

```bash
lspci | grep -i mellanox
# Example output:
# 01:00.0 Ethernet controller: Mellanox Technologies MT43244 BlueField-3 ...
```

Use this for `DOCA_REP_PCI_ADDR`.

### Common PCI Addresses

| Environment | DOCA_PCI_ADDR (DPU) | DOCA_REP_PCI_ADDR (Host) |
|-------------|---------------------|--------------------------|
| Lab BF3     | 03:00.0             | 01:00.0                  |
| Alternate   | 04:00.0             | 02:00.0                  |

## Running Hardware Tests

### Quick Start

Run the full test suite with default settings:

```bash
make qa-hardware-test
```

### Step-by-Step Workflow

For debugging or when setting up a new environment:

```bash
# 1. Build binaries with DOCA support
make qa-hardware-build

# 2. Deploy aegis to BF3 and verify connectivity
make qa-hardware-setup

# 3. Run the test suite
make qa-hardware-test

# 4. Clean up processes when done
make qa-hardware-cleanup
```

### Running Specific Tests

Run individual tests for targeted validation:

```bash
# Hardware detection smoke test (quick)
go test -tags=hardware -v -run TestDOCAComchHardwareDetection

# Full enrollment flow
go test -tags=hardware -v -run TestDOCAComchEnrollmentE2E

# Credential delivery flow
go test -tags=hardware -v -run TestDOCAComchCredentialDeliveryE2E
```

### Environment Variable Overrides

Override defaults for different hardware configurations:

| Variable | Default | Description |
|----------|---------|-------------|
| BF3_IP | 192.168.1.204 | BlueField-3 DPU IP address |
| BF3_USER | ubuntu | SSH user for BF3 |
| DOCA_PCI_ADDR | 03:00.0 | PCI address on DPU |
| DOCA_REP_PCI_ADDR | 01:00.0 | Representor PCI address on host |
| DOCA_SERVER_NAME | secure-infra | ComCh server name |
| NEXUS_ADDR | localhost:18080 | Nexus control plane address |
| WORKBENCH_IP | localhost | Workbench IP for local processes |

Example with overrides:

```bash
BF3_IP=192.168.1.205 DOCA_PCI_ADDR=04:00.0 make qa-hardware-test
```

Or for individual test runs:

```bash
BF3_IP=192.168.1.205 go test -tags=hardware -v -run TestDOCAComchEnrollmentE2E
```

## Test Descriptions

### TestDOCAComchHardwareDetection

Quick smoke test that verifies basic hardware accessibility without running the full enrollment flow.

**What it checks:**

1. SSH connectivity to BF3
2. DOCA SDK installation
3. InfiniBand device presence
4. PCI device availability
5. aegis binary deployment

**Use case:** Run this first when debugging connectivity issues or validating a new environment.

### TestDOCAComchEnrollmentE2E

Full enrollment flow testing the complete path from sentry to aegis via DOCA ComCh transport.

**Steps executed:**

1. Kill existing aegis on BF3
2. Start aegis with DOCA ComCh flags
3. Verify ComCh listener is active
4. Start nexus locally
5. Register DPU with nexus via bluectl
6. Assign DPU to tenant
7. Start sentry with `--force-comch`
8. Verify enrollment completed via ComCh transport
9. Verify enrollment in nexus

**Duration:** Approximately 2-3 minutes

### TestDOCAComchCredentialDeliveryE2E

Tests the credential push flow after enrollment, verifying that SSH CA credentials propagate correctly.

**Steps executed:**

1. Clean up existing processes
2. Start aegis on BF3 with DOCA ComCh
3. Start nexus locally
4. Register DPU
5. Start sentry daemon with `--force-comch`
6. Create SSH CA credential
7. Verify credential delivery logs on both sides
8. Verify credential file exists on host with correct permissions

**Duration:** Approximately 3-4 minutes

## Test Result JSON Format

Each test outputs a machine-readable JSON result for CI integration:

```json
{
  "test": "TestDOCAComchEnrollmentE2E",
  "passed": true,
  "duration_ms": 145230,
  "transport": "doca_comch",
  "bf3_ip": "192.168.1.204",
  "host_id": "hw-host-1706547890",
  "dpu_name": "hw-dpu-1706547890",
  "errors": []
}
```

**Fields:**

| Field | Type | Description |
|-------|------|-------------|
| test | string | Test function name |
| passed | boolean | Overall test result |
| duration_ms | int64 | Test duration in milliseconds |
| transport | string | Transport type used (always "doca_comch") |
| bf3_ip | string | BlueField-3 IP address |
| host_id | string | Assigned host ID (if enrollment succeeded) |
| dpu_name | string | DPU name used for test |
| errors | []string | List of error messages (empty if passed) |

## Troubleshooting

### Cannot SSH to BF3

**Symptom:** Test skips with "BlueField-3 hardware not reachable"

**Check:**

```bash
# Verify network connectivity
ping 192.168.1.204

# Test SSH directly
ssh -v ubuntu@192.168.1.204 echo "test"

# Check SSH key authentication
ssh-add -l
```

**Solutions:**

- Verify BF3 is powered on and booted
- Check network cable and switch configuration
- Configure SSH keys: `ssh-copy-id ubuntu@192.168.1.204`
- Check firewall rules on both machines

### DOCA SDK Not Installed

**Symptom:** Test skips with "DOCA SDK not installed on BF3"

**Check:**

```bash
ssh ubuntu@192.168.1.204 "dpkg -l | grep doca"
ssh ubuntu@192.168.1.204 "ls /opt/mellanox/doca"
```

**Solution:** Install DOCA SDK on the BlueField-3 following NVIDIA documentation.

### ComCh Listener Not Active

**Symptom:** Test fails with "Aegis ComCh listener not active"

**Check aegis logs:**

```bash
ssh ubuntu@192.168.1.204 "cat /tmp/aegis.log"
```

**Common causes:**

- Wrong PCI address. Verify with `lspci | grep -i mellanox` on BF3
- DOCA driver not loaded. Check `dmesg | grep doca`
- Another process using the ComCh device
- aegis crashed during startup

**Solution:**

```bash
# Kill and restart aegis manually
ssh ubuntu@192.168.1.204 "sudo pkill -9 aegis"
ssh ubuntu@192.168.1.204 "sudo ~/aegis -doca-pci-addr 03:00.0 -doca-rep-pci-addr 01:00.0 -doca-server-name secure-infra -local-api -control-plane http://localhost:18080 -dpu-name test"

# Check the output for errors
```

### Sentry Enrollment Failed

**Symptom:** Test fails with "Sentry enrollment failed"

**Check sentry and aegis logs:**

```bash
cat /tmp/sentry.log
ssh ubuntu@192.168.1.204 "cat /tmp/aegis.log"
```

**Common causes:**

- ComCh connection failed (check rshim on host)
- nexus not running or unreachable
- DPU not registered with nexus
- Network firewall blocking gRPC port (18051)

**Solutions:**

```bash
# Verify nexus is running
pgrep -x nexus || echo "nexus not running"
curl http://localhost:18080/health

# Verify DPU registration
./bin/bluectl dpu list --insecure

# Check rshim on workbench
lsmod | grep rshim
ls /dev/rshim0/
```

### Viewing Logs

**aegis (on BF3):**

```bash
ssh ubuntu@192.168.1.204 "cat /tmp/aegis.log"
ssh ubuntu@192.168.1.204 "tail -f /tmp/aegis.log"  # Live follow
```

**sentry (local):**

```bash
cat /tmp/sentry.log
tail -f /tmp/sentry.log  # Live follow
```

**nexus (local):**

```bash
cat /tmp/nexus.log
```

## CI Integration

### Running in CI Pipeline

```bash
# Set up environment
export BF3_IP=192.168.1.204
export BF3_USER=ubuntu

# Run tests with JSON output capture
go test -tags=hardware -v -timeout 10m ./... -run 'TestDOCA.*' 2>&1 | tee hardware-test.log

# Extract JSON results
grep -A20 "=== TEST RESULT ===" hardware-test.log | grep -v "===" > results.json
```

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | All tests passed |
| 1 | One or more tests failed |
| 2 | Test binary failed to build |

### Nightly Build Integration

Add to CI configuration:

```yaml
hardware-tests:
  runs-on: self-hosted  # Must have access to BF3 hardware
  timeout-minutes: 30
  steps:
    - uses: actions/checkout@v4
    - name: Build with DOCA support
      run: make qa-hardware-build
    - name: Run hardware tests
      run: make qa-hardware-test
      env:
        BF3_IP: 192.168.1.204
        BF3_USER: ubuntu
    - name: Upload test results
      uses: actions/upload-artifact@v4
      with:
        name: hardware-test-results
        path: /tmp/*.log
```

### Machine-Readable Output

For CI parsing, extract the JSON test results:

```bash
# Parse test results
go test -tags=hardware -v -run TestDOCAComchEnrollmentE2E 2>&1 | \
  sed -n '/=== TEST RESULT ===/,/===================/p' | \
  grep -v "===" | jq .
```

Example parsed output:

```json
{
  "test": "TestDOCAComchEnrollmentE2E",
  "passed": true,
  "duration_ms": 145230,
  "transport": "doca_comch",
  "bf3_ip": "192.168.1.204"
}
```

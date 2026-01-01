# DOCA Privileged Executer (DPE) Research

## What is DPE?

DPE is a daemon that allows DOCA services to access BlueField information that is otherwise inaccessible from containers due to technology limitations or permission granularity issues.

**Key insight**: BlueMan gets ALL its data from DPE via DTS. This is the foundation layer.

```
┌─────────────────────────────────────────────────┐
│               BlueMan (Web UI)                  │
└──────────────────────┬──────────────────────────┘
                       │ HTTP
┌──────────────────────▼──────────────────────────┐
│       DTS (DOCA Telemetry Service)              │
│       Aggregates + serves via API               │
└──────────────────────┬──────────────────────────┘
                       │ gRPC / IPC
┌──────────────────────▼──────────────────────────┐
│       DPE (DOCA Privileged Executer)            │
│       Runs privileged commands on host          │
└──────────────────────┬──────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────┐
│       BlueField Hardware / OS                   │
└─────────────────────────────────────────────────┘
```

## Availability

- Available since BlueField OS version 3.9.3.1
- Pre-installed on DOCA BFB bundles

## Managing DPE

```bash
# Check status
sudo systemctl status dpe

# Start/stop
sudo systemctl start dpe
sudo systemctl stop dpe

# Logs
cat /var/log/doca/telemetry/dpe.log
```

## Configuration

Config file: `/opt/mellanox/doca/services/telemetry/dpe/etc/dpe_config.ini`

Sections:
- `[server]` - General settings (socket path)
- `[commands]` - Bash commands without regex
- `[commands_regex]` - Bash commands with regex
- `[regex_macros]` - Custom regex definitions

The config file allows fine-grained control over what commands DPE can execute on behalf of other services.

## Data Providers via DPE

DTS uses DPE for "remote collection" by prefixing provider names with `grpc.`:

| Provider | Data | Notes |
|----------|------|-------|
| `hcaperf` | HCA performance counters | Network adapter stats |
| `bf_ptm` | BlueField-3 power/thermal | Disabled by default, needs DPE active |
| `bfperf` | ARM core performance | Requires `bfperf_pmc` executable |
| `sysinfo` | System information | OS, packages, firmware |

## Why This Matters for Fabric Console

**Option A: Use DTS/DPE stack (like BlueMan)**
- Leverage existing infrastructure
- Get rich telemetry data for free
- Requires DPE + DTS running on DPU
- Our agent becomes a thin client to DTS

**Option B: Direct collection (current plan)**
- Run our own commands (mlxconfig, ovs-vsctl, etc.)
- No dependency on DTS/DPE
- Less data available (no perf counters, thermal)
- Agent needs root or sudo for some commands

**Option C: Hybrid**
- Direct collection for basic info (our current plan)
- Optional DTS integration for telemetry (Phase 2)
- Works with or without DPE

## Recommendation

For Phase 1 MVP: Stick with **Option B (direct collection)**
- Simpler, no DPE dependency
- We control exactly what we collect
- Already planned in phase1-plan.md

For Phase 2: Add **Option C (hybrid)**
- If DTS is available, use it for telemetry
- Graceful fallback if DTS not running
- Add feature flag: `--enable-dts-integration`

## Action Items

1. [ ] Verify DPE is running on bluefield3: `systemctl status dpe`
2. [ ] Verify DTS is running: `systemctl status doca-telemetry`
3. [ ] Check DTS version and available providers
4. [ ] Capture DTS API response for reference
5. [ ] Add DTS integration to feature-requests.md as Phase 2 item

## References

- [DOCA Telemetry Service Guide](https://docs.nvidia.com/doca/archive/2-9-1/doca+telemetry+service+guide/index.html)
- [DOCA BlueMan Service Guide](https://docs.nvidia.com/doca/archive/2-9-0-cx8/doca+blueman+service+guide/index.html)
- [DOCA Management Service Guide](https://docs.nvidia.com/doca/sdk/doca-management-service-guide/index.html)

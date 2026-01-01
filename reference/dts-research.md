# DOCA Telemetry Service (DTS) Research

## Overview

DTS is NVIDIA's telemetry aggregation service for BlueField DPUs. It collects metrics from multiple providers and exports them via Prometheus, Fluent Bit, OpenTelemetry, or NetFlow.

**Service name**: `doca-telemetry-service`
**Config path**: `/opt/mellanox/doca/services/telemetry/config/dts_config.ini`
**Default port**: 9100

## Query Methods

### Prometheus Endpoint (Default)

```bash
# Prometheus format (for scraping)
curl http://localhost:9100/metrics

# JSON format (easier to parse)
curl http://localhost:9100/json/metrics
```

### HTTP API (High-Frequency)

```bash
# Structured API for programmatic access
curl http://localhost:9100/api/v1/metrics
```

### Example JSON Response

```json
{
  "timestamp": "2025-01-15T10:30:00Z",
  "hostname": "bluefield3",
  "metrics": {
    "sysfs": {
      "cpu_percent": 12.5,
      "memory_used_bytes": 8589934592,
      "memory_total_bytes": 34359738368
    },
    "ethtool": {
      "p0": {
        "rx_packets": 1234567890,
        "tx_packets": 987654321,
        "rx_errors": 0,
        "link_up": true,
        "speed_mbps": 200000
      }
    },
    "diagnostic_data": {
      "temperature_celsius": 52,
      "voltage_mv": 850,
      "power_watts": 75
    }
  }
}
```

## Available Providers

### System Metrics

| Provider | Counters | Source |
|----------|----------|--------|
| **sysfs** | CPU%, memory, disk I/O, network I/O | /proc, /sys |
| **ethtool** | Link state, speed, RX/TX packets, errors, drops | ethtool -S |
| **diagnostic_data** | Temperature, voltage, power consumption | mlxlink, mst |

### BlueField-Specific

| Provider | Counters | Source |
|----------|----------|--------|
| **bfperf** | ARM core cycles, cache hits/misses, branch predictions | Hardware PMU |
| **ovs** | Flow hits, misses, bytes, packets per bridge | ovs-dpctl |
| **dpdk** | RX/TX packets, drops, errors per port | DPDK PMD |
| **doca_flow** | Flow actions, offload statistics, hardware vs software | DOCA SDK |

### Acceleration Engines

| Provider | Counters | Source |
|----------|----------|--------|
| **doca_compress** | Compression throughput, ratios, queue depth | DOCA SDK |
| **doca_regex** | Pattern matches, engine utilization | DOCA SDK |
| **doca_sha** | Hash operations, throughput | DOCA SDK |
| **doca_dma** | DMA transfers, bandwidth | DOCA SDK |

### GPU Metrics (if GPU attached)

| Provider | Counters | Source |
|----------|----------|--------|
| **nvidia_smi** | GPU utilization, memory, temperature | nvidia-smi |
| **dcgm** | Detailed GPU metrics, ECC errors, NVLink | DCGM daemon |

### Custom Telemetry

| Provider | Counters | Source |
|----------|----------|--------|
| **custom** | User-defined counters | DOCA Telemetry SDK |

## Export Methods

1. **Prometheus** - Pull-based scraping from :9100/metrics
2. **Fluent Bit** - Push to Elasticsearch, Kafka, S3, Splunk
3. **OpenTelemetry** - OTLP export to any OTEL collector
4. **NetFlow/IPFIX** - Flow records for network monitoring tools
5. **File** - Local file output for debugging

## Configuration

### dts_config.ini Structure

```ini
[Service]
enable = true
port = 9100

[Providers]
sysfs = true
ethtool = true
diagnostic_data = true
bfperf = true
ovs = true
dpdk = false
doca_flow = true

[Export]
prometheus = true
fluent_bit = false
otel = false

[Prometheus]
port = 9100
path = /metrics

[Intervals]
sysfs_interval_ms = 1000
ethtool_interval_ms = 5000
diagnostic_interval_ms = 10000
```

## Fabric Console Integration

### Phase 1: No DTS Dependency

For MVP, collect data directly without requiring DTS:
- System info via shell commands (mlxconfig, mst, /proc)
- OVS data via ovs-vsctl, ovs-ofctl
- Attestation via BMC Redfish

**Rationale**: Simpler deployment, fewer dependencies, works on any DPU.

### Phase 2: Optional DTS Integration

Add DTS as optional enhancement for:
- Hardware-level metrics (temps, power, voltages)
- ARM performance counters (bfperf)
- DPDK and acceleration engine stats
- Historical data via Prometheus/Grafana

**Implementation**:
```go
type TelemetryClient interface {
    // Core methods (always available)
    GetSystemInfo() (*SystemInfo, error)
    GetOVSFlows(bridge string) ([]Flow, error)

    // DTS methods (optional, may return ErrDTSNotAvailable)
    GetHardwareMetrics() (*HardwareMetrics, error)
    GetPerformanceCounters() (*PerfCounters, error)
}
```

### Agent Flag

```bash
# Run without DTS (default)
./agent --listen=:50051

# Run with DTS integration
./agent --listen=:50051 --enable-dts --dts-endpoint=localhost:9100
```

## Verification Commands

```bash
# Check if DTS is running
systemctl status doca-telemetry-service

# View configuration
cat /opt/mellanox/doca/services/telemetry/config/dts_config.ini

# Query Prometheus metrics
curl -s localhost:9100/metrics | head -50

# Query JSON metrics
curl -s localhost:9100/json/metrics | jq

# Check enabled providers
curl -s localhost:9100/api/v1/providers
```

## References

- [DTS Documentation](https://docs.nvidia.com/doca/sdk/doca+telemetry+service/index.html)
- [DTS Configuration Guide](https://docs.nvidia.com/doca/sdk/doca+telemetry+service+configuration/index.html)
- [DOCA Telemetry SDK](https://docs.nvidia.com/doca/sdk/doca+telemetry/index.html)

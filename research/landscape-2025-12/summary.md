# BlueField DPU Management Landscape: Research Summary

**Date**: December 2025
**Sources**: Claude, Gemini, Perplexity deep research
**Verdict**: No unified multi-DPU management dashboard exists. Clear market opportunity confirmed.

---

## Consensus Findings

All three research sources independently reached the same conclusion: **the BlueField management ecosystem is fragmented across purpose-built tools with no "single pane of glass" solution**.

| Capability | Current State | Gap Severity |
|------------|---------------|--------------|
| Multi-DPU web dashboard | Does not exist | Critical |
| OVS flow visualization | CLI tools only (ovs-flowviz) | High |
| DICE/SPDM attestation UI | API-only via Redfish | High |
| Host introspection dashboard | Headless export to SIEM | Medium |
| Unified telemetry + security view | Requires manual integration | High |

---

## NVIDIA Tool Landscape

### DOCA BlueMan (Single-DPU Dashboard)
The **only native web UI** for BlueField DPUs.

**Provides**:
- System info (OS, kernel, firmware, mlxconfig parameters)
- Health monitoring (CPU, memory, disk, temperatures, services)
- Telemetry visualization via DTS integration
- Custom graph builder for performance counters

**Does NOT provide**:
- Multi-DPU aggregation (isolated to single DPU)
- OVS flow table visualization (shows counters, not rules)
- DICE/SPDM attestation status
- Host introspection from DPU perspective

**Access**: `https://<DPU_OOB_IP>` with SSH credentials
**Requires**: BlueField OS 3.9.3+, DTS running, DPE daemon active

### DOCA Platform Framework (DPF)
Kubernetes-native orchestration for DPU fleets.

**Provides**:
- CRDs for DPU lifecycle (DPUSet, DPU, DPUService, BFB)
- Automated BFB flashing and firmware updates
- Rolling updates with batch controls
- Integration with Prometheus/Grafana for telemetry

**Does NOT provide**:
- Native GUI (kubectl/API only)
- OVS flow management
- Attestation visualization
- Pre-built Grafana dashboards

**Latest**: v25.10.0 (December 2025)

### DOCA Telemetry Service (DTS)
Data collection engine for DPU metrics.

**Export options**: Prometheus, Fluent Bit, OpenTelemetry, NetFlow, gRPC
**OVS Provider**: Queries hardware eSwitch counters directly
**Key metrics**: `ovs_dp_flows_offloaded`, `ovs_flow_packets`, `ovs_flow_hits/misses`

**Gap**: No pre-built visualization. Requires custom Grafana dashboards.

### Other NVIDIA Tools

| Tool | Scope | DPU Introspection |
|------|-------|-------------------|
| Base Command Manager (BCM) | Cluster provisioning | Basic (firmware, health) |
| Unified Fabric Manager (UFM) | InfiniBand fabric | Minimal (port-level) |
| Mission Control | AI Factory operations | Limited (infrastructure view) |
| DOCA Management Service (DMS) | gNMI/OpenConfig | CLI-only, alpha |

---

## OVS Flow Visibility

### Current Options
1. **ovs-flowviz**: CLI tool generating HTML/Graphviz output; not live, not DPU-aware
2. **ovs-appctl dpctl/dump-flows type=offloaded**: Shows hardware-offloaded flows, CLI only
3. **DTS OVS Provider + Grafana**: Metrics (counters) but not flow rules/logic

### The ASAP2 Visibility Problem
BlueField uses ASAP2 (Accelerated Switching and Packet Processing) to offload OVS flows to hardware. Once offloaded:
- Packets bypass Arm CPU entirely
- Standard tools (tcpdump, eBPF) cannot see offloaded traffic
- Software flow counters show "0" while hardware processes millions of packets

**Only solution**: Query hardware eSwitch counters via DTS OVS Provider or DOCA Flow APIs.

---

## Attestation (DICE/SPDM)

### Current Capabilities
- BlueField-3 supports SPDM v1.1 attestation via Platform Security Controller
- Two attestation targets: `Bluefield_DPU_IRoT` (Arm + NIC) and `Bluefield_ERoT` (BMC)
- Certificate chains accessible via Redfish: `/redfish/v1/ComponentIntegrity/`

### Visualization Gap
**No GUI exists** for:
- DICE certificate chain hierarchy display
- Attestation signature validation
- Cross-DPU trust status monitoring
- CoRIM reference measurement comparison

All interaction requires custom scripts against Redfish API or libspdm integration.

---

## Host Introspection (DOCA Argus)

### Architecture
Argus uses DMA to read host memory without installing agents on the host OS. Detects rootkits, code injection, and unauthorized modifications.

### Design Philosophy
**Deliberately headless**: No local UI to maintain stealth and reduce attack surface.

**Output**: JSON/Syslog to external collectors
**Integration targets**: NVIDIA Morpheus, Splunk, Elasticsearch, CrowdStrike

---

## Third-Party Integrations

All third-party solutions focus on **security workload offloading**, not general DPU management.

### Cisco Secure Workload
- Deepest OVS integration (flow telemetry via ASAP2)
- Microsegmentation policy enforcement
- Uses DPU as enforcement point, not management target

### Xage Security Fabric
- Identity-based zero-trust controls
- Hardware-accelerated policy enforcement at line speed
- Security-focused; no DPU operational visibility

### Fortinet FortiGate VM
- Runs FortiGate firewall directly on BlueField-3 (FortiOS 7.6.3+)
- Managed via FortiManager, not DPU-native tooling
- Isolated firewall workload, not general management

### VMware vSphere Distributed Services Engine
- vCenter integration for DPU lifecycle
- NSX Distributed Firewall offload visibility
- BlueField-2 production, BlueField-3 in development

---

## Open Source Landscape

### Active Projects
| Project | Purpose | GUI |
|---------|---------|-----|
| NVIDIA doca-platform | DPF K8s operators | No |
| OpenShift DPU Network Operator | OVN-kube on BlueField | No |
| OPI Project | Cross-vendor API standardization | No |
| ovs-flowviz | Flow visualization | Static HTML only |

### Startups
**None identified** building unified DPU management platforms.

**Fungible** attempted this space but was acquired by Microsoft ($190M, 2023).

---

## The Composite Architecture Reality

NVIDIA's strategy is modular building blocks, not turnkey solutions:

```
┌────────────────────────────────────────────────────────────────┐
│                     "Unified Dashboard"                         │
│                   (Does NOT exist natively)                      │
├─────────────┬─────────────┬──────────────┬────────────────────┤
│   BlueMan   │   Grafana   │    SIEM      │  Custom Verifier   │
│  (per-DPU)  │  (metrics)  │  (security)  │   (attestation)    │
├─────────────┴─────────────┴──────────────┴────────────────────┤
│                    DOCA Telemetry Service                       │
├────────────────────────────────────────────────────────────────┤
│              DOCA Platform Framework (DPF)                      │
├────────────────────────────────────────────────────────────────┤
│                    BlueField DPU Fleet                          │
└────────────────────────────────────────────────────────────────┘
```

To achieve unified visibility today, organizations must:
1. Deploy DPF for orchestration
2. Configure DTS with OVS Provider on each DPU
3. Build custom Grafana dashboards for telemetry
4. Script Redfish API calls for attestation
5. Integrate Argus output with SIEM
6. Manually correlate data across tools

---

## Fabric Console Differentiation

Based on this research, Fabric Console fills confirmed gaps:

| Gap | Fabric Console Solution |
|-----|------------------------|
| Multi-DPU web dashboard | Unified Next.js interface |
| OVS flow visualization | Parse ovs-ofctl, display flow tables |
| DICE/SPDM attestation UI | Certificate chain viewer via Redfish |
| Host introspection display | Aggregate Argus data in dashboard |
| Tenant grouping | Cedar policy engine for multi-tenancy |
| Identity integration | Beyond Identity for users and DPUs |

**Positioning**:
- "BlueMan for a single DPU. Fabric Console for your fleet."
- "DPF for orchestration. Fabric Console for visualization."
- "Security vendors for enforcement. Fabric Console for operations."

---

## Source Quality Notes

| Source | Strengths | Unique Contributions |
|--------|-----------|---------------------|
| Claude | Concise gap analysis, competitive positioning | Clearest market opportunity framing |
| Gemini | Deepest technical detail, architecture diagrams | Two-node management problem explanation, DTS OVS Provider details |
| Perplexity | Most citations (73 sources), structured Q&A format | Specific API endpoints, version numbers, deployment paths |

All three sources corroborate the central finding: **no unified DPU management dashboard exists**.

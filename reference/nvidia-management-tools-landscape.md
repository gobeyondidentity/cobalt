# NVIDIA Management Tools Landscape

> **Purpose**: Clarify which NVIDIA tools manage what, specifically for BlueField DPU deployments
> **Last Updated**: 2024-12-23

## TL;DR

| Tool | Manages | OVS on BlueField? |
|------|---------|-------------------|
| **UFM** | InfiniBand fabric (switches) | No |
| **BCM** | Cluster provisioning, Slurm | No |
| **DPF** | DPU lifecycle, services | Yes (orchestration) |
| **DMS** | DPU device config | Yes (device-level) |
| **DOCA SDK** | DPU applications | Yes (programming) |

**For our identity fabric work**: Use DOCA SDK + DMS for development, DPF for production deployment.

---

## UFM (Unified Fabric Manager)

### What It Actually Is

UFM manages **InfiniBand switches and fabric topology**. It is NOT a general DPU management tool.

**Primary scope**:
- InfiniBand switch management (QM8700, QM8790, etc.)
- Fabric topology discovery
- Cable and port health monitoring
- Congestion detection
- Job scheduler integration (Slurm, LSF)

**What UFM does NOT do**:
- Manage BlueField DPU configuration
- Configure OVS policies
- Deploy applications to DPUs
- Manage Ethernet-only networks

### When UFM Is Relevant

UFM matters if your AI infrastructure uses **InfiniBand interconnects** between nodes. In that case:
- UFM monitors the InfiniBand fabric health
- BlueField DPUs connect to that fabric as endpoints
- UFM sees the DPU's InfiniBand ports but doesn't manage the DPU itself

### Editions

| Edition | Features | Deployment |
|---------|----------|------------|
| UFM Telemetry | Monitoring, metrics | Container or appliance |
| UFM Enterprise | + Provisioning, APIs | Container or appliance |
| UFM Cyber-AI | + AI anomaly detection | Appliance only (with GPU) |

### Licensing

- **Not free**. Subscription-based per managed node.
- **Not part of DOCA**. Separate product.
- 30-day eval on first startup, 60-day trial available.
- Contact NVIDIA sales for pricing (varies by node count).

### UFM Cyber-AI Deep Dive

The premium tier (Cyber-AI) adds AI-driven security and predictive capabilities:

**Prediction Dashboard features**:
- **Suspicious Behavior Detection**: AI identifies anomalous network patterns
- **Link Failure Prediction**: Predicts cable/port failures before they occur
- **Tenant Congestion Monitoring**: Per-PKey (InfiniBand partition) visibility
- **Anomaly Dashboard**: Critical alerts with recommended remediation actions

**Important distinction**: "Tenant ID" in UFM refers to InfiniBand Partition Keys (PKeys),
which is IB-level multi-tenancy. This is different from cloud tenants or OVS-based isolation.

**Complementary to Identity Fabric**:

| Layer | Tool | Security Focus |
|-------|------|----------------|
| InfiniBand fabric | UFM Cyber-AI | Switch anomalies, link health, PKey isolation |
| DPU data plane | Identity Fabric | Access control, authentication, flow policy |

For AI clusters with InfiniBand interconnects, these tools work together:
- UFM monitors fabric-level anomalies and predicts hardware failures
- Identity Fabric controls who can communicate at the DPU enforcement point

### REST API

Comprehensive REST API for automation. Docs at:
`docs.nvidia.com/networking/display/ufmenterpriserestapiv6201`

### UFM-SDN Appliance

A dedicated 1U hardware appliance running UFM software. "UFM in a box."

**Hardware specs**:
- 2x Intel Xeon E5-2620 v4, 64GB RAM, 2x 960GB SSD
- 1U rackmount (1.7"H x 17.2"W x 27.9"D), 14.1 kg
- 750W redundant PSU, max 550W draw

**Network support**:
- InfiniBand: SDR/DDR/QDR/FDR/EDR/HDR
- Ethernet: 1/10/25/40/50/100/200 Gb/s

**When to use**: Large InfiniBand deployments where you want dedicated management
hardware with HA support, rather than running UFM as a container.

**Still not for DPU management**. The "SDN" refers to software-defined networking
at the switch fabric level, not DPU/OVS level.

---

## DOCA Platform Framework (DPF)

### What It Is

DPF is the **production orchestration layer for BlueField DPUs**. This is what we should use for fleet management.

**Primary scope**:
- DPU provisioning and lifecycle management
- Service deployment to DPUs
- Kubernetes integration (DPU Operator)
- OVS and networking orchestration
- Multi-tenant DPU management

### Key Components

```
┌─────────────────────────────────────────────────────────┐
│                  DOCA Platform Framework                │
├─────────────────────────────────────────────────────────┤
│  DPU Operator          │  Kubernetes-native DPU mgmt   │
│  DPU Service Framework │  Deploy services to DPUs      │
│  Network Operator      │  OVS, OVN, SR-IOV config      │
│  DOCA Telemetry        │  Metrics and observability    │
└─────────────────────────────────────────────────────────┘
```

### Relevance to Identity Fabric

**HIGH**. DPF is how we would deploy our identity enforcement service to a fleet of BlueField DPUs in production:

1. Package our authenticator as a DPU service
2. Deploy via DPF to all DPUs in cluster
3. DPF handles lifecycle (upgrades, rollbacks)
4. Integrates with Kubernetes network policies

### Where to Learn More

- DOCA DPF Documentation: `docs.nvidia.com/doca/sdk/doca+platform+framework`
- NVIDIA Network Operator: For OVS/OVN orchestration
- DPU Operator: Kubernetes CRDs for DPU management

---

## DOCA Management Service (DMS)

### What It Is

DMS runs on each BlueField DPU and provides device-level configuration APIs.

**Capabilities**:
- Query DPU status and health
- Configure networking (OVS, representors)
- Manage services running on DPU
- REST API for remote management

### Installed on Our BF3

```bash
dpkg -l | grep doca-dms
# ii  doca-dms  3.2.1025-1  arm64  DOCA Management Service
```

### API Access

```bash
# Default port: 9339
curl -k https://localhost:9339/api/v1/system/info
```

---

## Base Command Manager (BCM)

### What It Is

BCM is **cluster provisioning and workload management**, not DPU-specific.

**Primary scope**:
- Bare-metal node provisioning (PXE boot, OS install)
- Slurm/Kubernetes cluster management
- GPU resource scheduling
- Software deployment to compute nodes

### Relationship to BlueField

BCM can provision hosts that have BlueField DPUs, but it doesn't manage the DPU directly. For DPU management, BCM relies on:
- DOCA Platform Framework for DPU orchestration
- DOCA Management Service for device config

### What We Have

Our lab has BCM 11 managing:
- bcmnode1, bcmnode2 (VMs)
- bluefield3 (registered as DPU type, but only for BMC access)
- workbench (Slurm GPU node)

BCM gives us BMC/Redfish access to the BF3 but doesn't configure OVS.

---

## Decision Matrix: Which Tool for What

| Task | Tool |
|------|------|
| **Provision bare-metal cluster** | BCM |
| **Monitor InfiniBand fabric** | UFM |
| **Deploy app to single DPU** | DOCA SDK + SSH |
| **Deploy app to DPU fleet** | DOCA Platform Framework |
| **Configure OVS on single DPU** | ovs-vsctl / DMS |
| **Orchestrate OVS across fleet** | DPF + Network Operator |
| **Collect DPU telemetry** | DOCA Telemetry Service |
| **Schedule GPU workloads** | Slurm / Kubernetes (via BCM) |

---

## Implications for Identity Fabric

### Development Phase (Now)

- Use **DOCA SDK** to build the authenticator
- Configure OVS via **CLI** (ovs-vsctl, ovs-ofctl)
- Test on single BF3 in lab

### Production Deployment (Future)

- Package as **DPU Service** for DPF
- Deploy via **DPU Operator** in Kubernetes
- Integrate with **Network Operator** for OVS policy
- Monitor via **DOCA Telemetry** to Grafana

### Partnership Implications

- UFM partnership: Only relevant if targeting InfiniBand AI clusters
- DPF partnership: Critical for production deployment story
- NVIDIA DPF team is the right contact for Zero Trust initiative

---

## References

- [UFM Product Page](https://www.nvidia.com/en-us/networking/infiniband/ufm/)
- [DOCA Platform Framework](https://docs.nvidia.com/doca/sdk/doca+platform+framework)
- [DOCA Management Service](https://docs.nvidia.com/doca/sdk/doca+management+service)
- [NVIDIA Network Operator](https://docs.nvidia.com/networking/display/colocentgray)
- [Base Command Manager](https://docs.nvidia.com/base-command-manager)
